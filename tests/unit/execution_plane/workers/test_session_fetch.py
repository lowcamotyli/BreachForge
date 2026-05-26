from __future__ import annotations

from datetime import UTC, datetime
import importlib.util
from pathlib import Path
import sys
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import httpx
import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[4]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from control_plane.auth_manager import SessionSnapshot
from storage.db.models import AttackTask, AttackTaskStatus, Endpoint, Scan, ScanStatus, Target

ATTACK_WORKER_PATH = PROJECT_ROOT / "execution_plane/workers/attack_worker.py"
ATTACK_WORKER_SPEC = importlib.util.spec_from_file_location("project_attack_worker_session_fetch", ATTACK_WORKER_PATH)
assert ATTACK_WORKER_SPEC is not None
assert ATTACK_WORKER_SPEC.loader is not None
attack_worker_module = importlib.util.module_from_spec(ATTACK_WORKER_SPEC)
ATTACK_WORKER_SPEC.loader.exec_module(attack_worker_module)
AttackWorker = attack_worker_module.AttackWorker
AuthExpiredError = attack_worker_module.AuthExpiredError
IdentityRole = attack_worker_module.IdentityRole


class _FakeRateLimiter:
    production_safe_mode = False
    allow_mutating_methods = True

    def acquire_for_worker(self, scan_id: str, domain: str, worker_id: str, method: str = "GET") -> bool:
        return True


class _FakeAsyncClient:
    def __init__(self, *, headers: dict[str, str], cookies: httpx.Cookies, follow_redirects: bool) -> None:
        self._headers = headers
        self._cookies = cookies
        assert follow_redirects is True

    async def __aenter__(self) -> _FakeAsyncClient:
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        return None

    def build_request(self, method: str, url: str, content: bytes | None) -> httpx.Request:
        return httpx.Request(method=method, url=url, headers=self._headers, cookies=self._cookies, content=content)

    async def send(self, request: httpx.Request) -> httpx.Response:
        return httpx.Response(status_code=200, headers={"Content-Type": "application/json"}, content=b"{}", request=request)


def _build_task() -> AttackTask:
    endpoint = Endpoint(
        id=uuid4(),
        asset_map_id=uuid4(),
        url_pattern="https://app.example.com/api/users/1",
        method="get",
        auth_required=True,
        parameters=[],
        observed_content_type="application/json",
        example_response_code=200,
    )
    task = AttackTask(
        id=uuid4(),
        scan_id=uuid4(),
        endpoint_id=endpoint.id,
        attack_class="bola",
        target_parameter="user_id",
        hypothesis='{"user_id": 2}',
        priority_score=1.0,
        status=AttackTaskStatus.pending,
    )
    target = Target(
        id=uuid4(),
        url="https://app.example.com",
        name="app.example.com",
        config={"allowed_domains": ["app.example.com"]},
    )
    scan = Scan(
        id=task.scan_id,
        target_id=target.id,
        status=ScanStatus.running,
        phase="attack",
    )
    scan.target = target
    task.scan = scan
    task.endpoint = endpoint
    return task


def _build_session(scan_id) -> SessionSnapshot:
    return SessionSnapshot(
        scan_id=scan_id,
        cookies=[{"name": "sessionid", "value": "cookie-secret", "domain": "app.example.com", "path": "/"}],
        auth_headers={"Authorization": "Bearer test-token"},
        csrf_tokens={"X-CSRF-Token": "csrf-token"},
        captured_at=datetime.now(UTC),
        expires_at=None,
    )


@pytest.mark.asyncio
async def test_execute_fetches_fresh_snapshot_every_task(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _to_thread_inline(func, *args, **kwargs):
        return func(*args, **kwargs)

    monkeypatch.setattr(attack_worker_module.asyncio, "to_thread", _to_thread_inline)
    monkeypatch.setattr(attack_worker_module.httpx, "AsyncClient", lambda **kwargs: _FakeAsyncClient(**kwargs))

    redis_client = MagicMock()
    redis_client.xadd.return_value = "1-0"

    task = _build_task()
    session_one = _build_session(task.scan_id)
    session_two = _build_session(task.scan_id)
    session_two.auth_headers = {"Authorization": "Bearer second-token"}

    auth_manager = MagicMock()
    auth_manager.health_check = AsyncMock(return_value=True)
    auth_manager.get_session_snapshot = AsyncMock(side_effect=[session_one, session_two])

    worker = AttackWorker(redis_client=redis_client, rate_limiter=_FakeRateLimiter(), auth_manager=auth_manager)

    await worker.execute(task)
    await worker.execute(task)

    assert auth_manager.get_session_snapshot.await_count == 2
    assert auth_manager.get_session_snapshot.await_args_list[0].args == (task.scan_id,)
    assert auth_manager.get_session_snapshot.await_args_list[1].args == (task.scan_id,)
    assert auth_manager.health_check.await_count == 2


@pytest.mark.asyncio
async def test_worker_has_no_persistent_session_cache_attrs(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _to_thread_inline(func, *args, **kwargs):
        return func(*args, **kwargs)

    monkeypatch.setattr(attack_worker_module.asyncio, "to_thread", _to_thread_inline)
    monkeypatch.setattr(attack_worker_module.httpx, "AsyncClient", lambda **kwargs: _FakeAsyncClient(**kwargs))

    redis_client = MagicMock()
    redis_client.xadd.return_value = "1-0"

    task = _build_task()
    auth_manager = MagicMock()
    auth_manager.health_check = AsyncMock(return_value=True)
    auth_manager.get_session_snapshot = AsyncMock(return_value=_build_session(task.scan_id))

    worker = AttackWorker(redis_client=redis_client, rate_limiter=_FakeRateLimiter(), auth_manager=auth_manager)

    await worker.execute(task)
    await worker.execute(task)

    assert not hasattr(worker, "_session")
    assert not hasattr(worker, "_snapshot")


@pytest.mark.asyncio
async def test_execute_raises_auth_expired_when_health_check_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _to_thread_inline(func, *args, **kwargs):
        return func(*args, **kwargs)

    monkeypatch.setattr(attack_worker_module.asyncio, "to_thread", _to_thread_inline)
    monkeypatch.setattr(attack_worker_module.httpx, "AsyncClient", lambda **kwargs: _FakeAsyncClient(**kwargs))

    redis_client = MagicMock()
    redis_client.xadd.return_value = "1-0"

    task = _build_task()
    auth_manager = MagicMock()
    auth_manager.health_check = AsyncMock(return_value=False)
    auth_manager.get_session_snapshot = AsyncMock()

    worker = AttackWorker(redis_client=redis_client, rate_limiter=_FakeRateLimiter(), auth_manager=auth_manager)

    with pytest.raises(AuthExpiredError, match="auth_expired"):
        await worker.execute(task)

    auth_manager.get_session_snapshot.assert_not_awaited()


@pytest.mark.asyncio
async def test_resolve_execution_session_uses_named_identity_context() -> None:
    task = _build_task()
    base_session = _build_session(task.scan_id)
    named_session = _build_session(task.scan_id)
    named_session.auth_headers = {"Authorization": "Bearer named-user"}

    identity_context = MagicMock()
    identity_context.to_session_snapshot.return_value = named_session

    auth_manager = MagicMock()
    auth_manager.health_check = AsyncMock(return_value=True)
    auth_manager.get_session_snapshot = AsyncMock(return_value=base_session)
    auth_manager.get_identity_context = AsyncMock(return_value=identity_context)

    worker = AttackWorker(redis_client=MagicMock(), rate_limiter=_FakeRateLimiter(), auth_manager=auth_manager)

    resolved = await worker._resolve_execution_session(
        task=task,
        provided_session=None,
        identity_role=None,
        identity_name="current_user",
    )

    assert resolved.auth_headers == {"Authorization": "Bearer named-user"}
    auth_manager.get_identity_context.assert_awaited_once_with(scan_id=task.scan_id, role="current_user")


@pytest.mark.asyncio
async def test_resolve_execution_session_keeps_identity_role_lookup() -> None:
    task = _build_task()
    base_session = _build_session(task.scan_id)
    role_session = _build_session(task.scan_id)
    role_session.auth_headers = {"Authorization": "Bearer admin-user"}

    identity_context = MagicMock()
    identity_context.to_session_snapshot.return_value = role_session

    auth_manager = MagicMock()
    auth_manager.health_check = AsyncMock(return_value=True)
    auth_manager.get_session_snapshot = AsyncMock(return_value=base_session)
    auth_manager.get_identity_context = AsyncMock(return_value=identity_context)

    worker = AttackWorker(redis_client=MagicMock(), rate_limiter=_FakeRateLimiter(), auth_manager=auth_manager)

    resolved = await worker._resolve_execution_session(
        task=task,
        provided_session=None,
        identity_role=IdentityRole.admin,
        identity_name=None,
    )

    assert resolved.auth_headers == {"Authorization": "Bearer admin-user"}
    auth_manager.get_identity_context.assert_awaited_once_with(scan_id=task.scan_id, role=IdentityRole.admin)


@pytest.mark.asyncio
async def test_resolve_execution_session_anonymous_returns_empty_session_without_auth_lookup() -> None:
    task = _build_task()
    auth_manager = MagicMock()
    auth_manager.health_check = AsyncMock(return_value=True)
    auth_manager.get_session_snapshot = AsyncMock(return_value=_build_session(task.scan_id))
    auth_manager.get_identity_context = AsyncMock()

    worker = AttackWorker(redis_client=MagicMock(), rate_limiter=_FakeRateLimiter(), auth_manager=auth_manager)

    resolved = await worker._resolve_execution_session(
        task=task,
        provided_session=None,
        identity_role=None,
        identity_name="anonymous",
    )

    assert resolved.scan_id == task.scan_id
    assert resolved.cookies == []
    assert resolved.auth_headers == {}
    assert resolved.csrf_tokens == {}
    auth_manager.health_check.assert_not_awaited()
    auth_manager.get_session_snapshot.assert_not_awaited()
    auth_manager.get_identity_context.assert_not_awaited()


@pytest.mark.asyncio
async def test_resolve_execution_session_missing_named_identity_raises_identity_not_found() -> None:
    task = _build_task()
    auth_manager = MagicMock()
    auth_manager.health_check = AsyncMock(return_value=True)
    auth_manager.get_session_snapshot = AsyncMock(return_value=_build_session(task.scan_id))
    auth_manager.get_identity_context = AsyncMock(side_effect=RuntimeError("Identity context is not initialized"))

    worker = AttackWorker(redis_client=MagicMock(), rate_limiter=_FakeRateLimiter(), auth_manager=auth_manager)

    with pytest.raises(
        AuthExpiredError,
        match=f"identity_not_found: 'missing_user' not in identity matrix for scan {task.scan_id}",
    ):
        await worker._resolve_execution_session(
            task=task,
            provided_session=None,
            identity_role=None,
            identity_name="missing_user",
        )
