from __future__ import annotations

from datetime import UTC, datetime
import importlib.util
from pathlib import Path
import sys
from unittest.mock import MagicMock
from uuid import UUID, uuid4

import httpx
import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[4]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from control_plane.auth_manager import SessionSnapshot
from storage.db.models import AttackTask, AttackTaskStatus, Endpoint, Scan, ScanStatus, Target

ATTACK_WORKER_PATH = PROJECT_ROOT / "execution_plane/workers/attack_worker.py"
ATTACK_WORKER_SPEC = importlib.util.spec_from_file_location("project_attack_worker", ATTACK_WORKER_PATH)
assert ATTACK_WORKER_SPEC is not None
assert ATTACK_WORKER_SPEC.loader is not None
attack_worker_module = importlib.util.module_from_spec(ATTACK_WORKER_SPEC)
ATTACK_WORKER_SPEC.loader.exec_module(attack_worker_module)
AttackWorker = attack_worker_module.AttackWorker
GuardrailViolation = attack_worker_module.GuardrailViolation


class _FakeRateLimiter:
    def __init__(
        self,
        *,
        allow: bool = True,
        production_safe_mode: bool = False,
        allow_mutating_methods: bool = False,
    ) -> None:
        self.allow = allow
        self.production_safe_mode = production_safe_mode
        self.allow_mutating_methods = allow_mutating_methods
        self.calls: list[dict[str, str]] = []

    def acquire_for_worker(self, scan_id: str, domain: str, worker_id: str, method: str = "GET") -> bool:
        self.calls.append(
            {
                "scan_id": scan_id,
                "domain": domain,
                "worker_id": worker_id,
                "method": method,
            }
        )
        return self.allow


class _FakeAsyncClient:
    def __init__(
        self,
        *,
        headers: dict[str, str],
        cookies: httpx.Cookies,
        follow_redirects: bool,
        call_order: list[str],
    ) -> None:
        self._headers = headers
        self._cookies = cookies
        self._call_order = call_order
        assert follow_redirects is True

    async def __aenter__(self) -> _FakeAsyncClient:
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        return None

    def build_request(self, method: str, url: str, content: bytes | None) -> httpx.Request:
        return httpx.Request(
            method=method,
            url=url,
            headers=self._headers,
            cookies=self._cookies,
            content=content,
        )

    async def send(self, request: httpx.Request) -> httpx.Response:
        self._call_order.append("http_send")
        return httpx.Response(
            status_code=201,
            headers={"Content-Type": "application/json", "Authorization": "response-secret"},
            content=b'{"ok": true}',
            request=request,
        )


def _build_task() -> AttackTask:
    endpoint = Endpoint(
        id=uuid4(),
        asset_map_id=uuid4(),
        url_pattern="https://app.example.com/api/users/1",
        method="post",
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


def _build_session(scan_id: UUID) -> SessionSnapshot:
    return SessionSnapshot(
        scan_id=scan_id,
        cookies=[{"name": "sessionid", "value": "cookie-secret", "domain": "app.example.com", "path": "/"}],
        auth_headers={"Authorization": "Bearer test-token"},
        csrf_tokens={"X-CSRF-Token": "csrf-token"},
        captured_at=datetime.now(UTC),
        expires_at=None,
    )


@pytest.mark.asyncio
async def test_execute_publishes_redis_evidence_and_returns_raw_probe(monkeypatch: pytest.MonkeyPatch) -> None:
    call_order: list[str] = []

    redis_client = MagicMock()
    redis_client.xadd.return_value = "1-0"
    rate_limiter = _FakeRateLimiter(allow=True)

    async def _to_thread_inline(func, *args, **kwargs):
        return func(*args, **kwargs)

    perf = iter((10.0, 10.123))

    def _perf_counter() -> float:
        return next(perf)

    monkeypatch.setattr(attack_worker_module.asyncio, "to_thread", _to_thread_inline)
    monkeypatch.setattr(attack_worker_module.time, "perf_counter", _perf_counter)
    monkeypatch.setattr(
        attack_worker_module.httpx,
        "AsyncClient",
        lambda **kwargs: _FakeAsyncClient(call_order=call_order, **kwargs),
    )

    db_call = MagicMock()
    s3_call = MagicMock()
    monkeypatch.setattr(attack_worker_module, "db_call", db_call, raising=False)
    monkeypatch.setattr(attack_worker_module, "s3_call", s3_call, raising=False)

    worker = AttackWorker(redis_client=redis_client, rate_limiter=rate_limiter)
    task = _build_task()
    session = _build_session(task.scan_id)

    raw_probe = await worker.execute(task, session)

    assert call_order == ["http_send"]
    redis_client.xadd.assert_called_once()
    stream_key, payload = redis_client.xadd.call_args.args
    assert stream_key == f"evidence:{task.scan_id}"
    assert payload["attack_task_id"] == str(task.id)
    assert payload["worker_id"] == raw_probe.worker_id
    assert rate_limiter.calls == [
        {
            "scan_id": str(task.scan_id),
            "domain": "app.example.com",
            "worker_id": raw_probe.worker_id,
            "method": "POST",
        }
    ]

    assert raw_probe.attack_task_id == task.id
    assert raw_probe.request["method"] == "POST"
    assert raw_probe.request["url"] == task.endpoint.url_pattern
    request_headers = {str(k).lower(): v for k, v in raw_probe.request["headers"].items()}
    response_headers = {str(k).lower(): v for k, v in raw_probe.response["headers"].items()}
    assert request_headers["authorization"] == "Bearer test-token"
    assert raw_probe.request["body"] == '{"user_id": 2}'
    assert raw_probe.response["status"] == 201
    assert response_headers["authorization"] == "response-secret"
    assert raw_probe.response["body"] == '{"ok": true}'
    assert 120 <= raw_probe.response["latency_ms"] <= 123

    db_call.assert_not_called()
    s3_call.assert_not_called()

    called_methods = [method_call[0] for method_call in redis_client.method_calls]
    assert called_methods == ["xadd"]


@pytest.mark.asyncio
async def test_execute_fails_closed_for_out_of_scope_domain(monkeypatch: pytest.MonkeyPatch) -> None:
    redis_client = MagicMock()
    rate_limiter = _FakeRateLimiter(allow=True)

    async def _to_thread_inline(func, *args, **kwargs):
        return func(*args, **kwargs)

    monkeypatch.setattr(attack_worker_module.asyncio, "to_thread", _to_thread_inline)
    worker = AttackWorker(redis_client=redis_client, rate_limiter=rate_limiter)

    task = _build_task()
    task.endpoint.url_pattern = "https://evil.example.net/api/users/1"
    session = _build_session(task.scan_id)

    with pytest.raises(GuardrailViolation, match="Out-of-scope target domain"):
        await worker.execute(task, session)

    redis_client.xadd.assert_not_called()
    assert rate_limiter.calls == []


@pytest.mark.asyncio
async def test_execute_blocks_mutating_method_in_production_safe_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    redis_client = MagicMock()
    rate_limiter = _FakeRateLimiter(allow=True, production_safe_mode=True, allow_mutating_methods=False)

    async def _to_thread_inline(func, *args, **kwargs):
        return func(*args, **kwargs)

    monkeypatch.setattr(attack_worker_module.asyncio, "to_thread", _to_thread_inline)
    worker = AttackWorker(redis_client=redis_client, rate_limiter=rate_limiter)
    task = _build_task()
    session = _build_session(task.scan_id)

    with pytest.raises(GuardrailViolation, match="blocked in production-safe mode"):
        await worker.execute(task, session)

    redis_client.xadd.assert_not_called()
    assert rate_limiter.calls == []


@pytest.mark.asyncio
async def test_execute_fails_closed_when_rate_limiter_denies(monkeypatch: pytest.MonkeyPatch) -> None:
    redis_client = MagicMock()
    rate_limiter = _FakeRateLimiter(allow=False)
    monkeypatch.setenv("RATE_LIMIT_WAIT_TIMEOUT_S", "0")

    async def _to_thread_inline(func, *args, **kwargs):
        return func(*args, **kwargs)

    monkeypatch.setattr(attack_worker_module.asyncio, "to_thread", _to_thread_inline)
    worker = AttackWorker(redis_client=redis_client, rate_limiter=rate_limiter)
    task = _build_task()
    session = _build_session(task.scan_id)

    with pytest.raises(GuardrailViolation, match="Rate-limiter denied request"):
        await worker.execute(task, session)

    redis_client.xadd.assert_not_called()
    assert len(rate_limiter.calls) == 1
