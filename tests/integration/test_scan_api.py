from __future__ import annotations

import os
from datetime import UTC, datetime
from uuid import UUID, uuid4

from fastapi.testclient import TestClient

os.environ.setdefault("DATABASE_URL", "postgresql://postgres:postgres@localhost:5432/proofscan")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/0")

from api.main import app
from api.routers import scans as scans_module
from control_plane.orchestrator import PreflightResult
from storage.db.models import AuthContext, Scan, ScanStatus, Target


class _FakeResult:
    def __init__(self, item: Scan | None) -> None:
        self._item = item

    def scalar_one_or_none(self) -> Scan | None:
        return self._item


class _FakeSession:
    def __init__(self) -> None:
        self.targets: dict[UUID, Target] = {}
        self.scans: dict[UUID, Scan] = {}
        self.auth_contexts: dict[UUID, AuthContext] = {}

    def add(self, model: object) -> None:
        if isinstance(model, Target):
            if model.id is None:
                model.id = uuid4()
            self.targets[model.id] = model
            return
        if isinstance(model, Scan):
            if model.id is None:
                model.id = uuid4()
            if model.created_at is None:
                model.created_at = datetime.now(UTC)
            if model.status is None:
                model.status = ScanStatus.created
            self.scans[model.id] = model
            return
        if isinstance(model, AuthContext):
            if model.id is None:
                model.id = uuid4()
            self.auth_contexts[model.id] = model

    async def flush(self) -> None:
        return None

    async def commit(self) -> None:
        return None

    async def refresh(self, model: object) -> None:
        return None

    async def execute(self, statement) -> _FakeResult:
        scan_id: UUID | None = None
        where_criteria = list(getattr(statement, "_where_criteria", ()))
        for criterion in where_criteria:
            right = getattr(criterion, "right", None)
            value = getattr(right, "value", None)
            if isinstance(value, UUID):
                scan_id = value
                break
        if scan_id is None:
            return _FakeResult(None)
        return _FakeResult(self.scans.get(scan_id))


class _FakeQueue:
    def __init__(self) -> None:
        self.calls: list[tuple[object, ...]] = []

    def enqueue(self, *args: object) -> None:
        self.calls.append(args)


class _FailingQueue:
    name = "recon"

    def enqueue(self, *args: object) -> None:
        del args
        raise RuntimeError("queue unavailable")


class _FakeKillRedis:
    def get(self, key: str) -> None:
        del key
        return None


def _stub_preflight(monkeypatch, result: PreflightResult | None = None) -> None:
    async def _preflight(scan_config: object) -> PreflightResult:
        del scan_config
        return result or PreflightResult(
            status="ok",
            failures=[],
            missing_roles=[],
            missing_tenants=[],
            csrf_status="ok",
        )

    monkeypatch.setattr(scans_module, "preflight_auth_check", _preflight)


def _stub_encryption(monkeypatch) -> None:
    class _FakeEncryption:
        def encrypt_credential(self, plaintext: str, scan_id: UUID):
            del plaintext, scan_id
            return type("_Blob", (), {"encrypted_data_key": "key", "ciphertext": "cipher"})()

    monkeypatch.setattr(scans_module, "EnvelopeEncryption", _FakeEncryption)


def test_post_and_get_scan_with_mock_db_and_mock_redis(monkeypatch) -> None:
    fake_db = _FakeSession()
    fake_queue = _FakeQueue()

    async def _override_get_db():
        yield fake_db

    monkeypatch.setattr(scans_module, "_get_auth_bootstrap_queue", lambda: fake_queue)
    monkeypatch.setattr(scans_module.Redis, "from_url", lambda *args, **kwargs: _FakeKillRedis())
    _stub_preflight(monkeypatch)
    _stub_encryption(monkeypatch)
    app.dependency_overrides[scans_module.get_db] = _override_get_db

    client = TestClient(app)

    create_payload = {
        "target_url": "https://app.example.com",
        "auth_context": {"type": "token", "bearer_token": "valid-token"},
    }
    create_response = client.post("/scans", json=create_payload)

    assert create_response.status_code == 201
    create_body = create_response.json()
    assert "id" in create_body
    scan_id = create_body["id"]

    get_response = client.get(f"/scans/{scan_id}")

    assert get_response.status_code == 200
    get_body = get_response.json()
    assert get_body["id"] == scan_id
    assert get_body["status"] == "running"
    assert create_body["warnings"] == []
    assert len(fake_queue.calls) == 1

    app.dependency_overrides.clear()


def test_post_unauth_scan_enqueues_recon_job(monkeypatch) -> None:
    fake_db = _FakeSession()
    fake_queue = _FakeQueue()

    async def _override_get_db():
        yield fake_db

    monkeypatch.setattr(scans_module, "_get_recon_queue", lambda: fake_queue)
    monkeypatch.setattr(scans_module.Redis, "from_url", lambda *args, **kwargs: _FakeKillRedis())
    _stub_preflight(monkeypatch)
    app.dependency_overrides[scans_module.get_db] = _override_get_db

    client = TestClient(app)

    create_response = client.post(
        "/scans",
        json={
            "target_url": "https://public.example.com",
            "unauth_mode": True,
        },
    )

    assert create_response.status_code == 201
    create_body = create_response.json()
    scan_id = create_body["id"]
    scan = fake_db.scans[UUID(scan_id)]

    assert create_body["status"] == "running"
    assert create_body["phase"] == "recon"
    assert scan.status == ScanStatus.running
    assert scan.phase == "recon"
    assert fake_db.auth_contexts == {}
    assert fake_queue.calls == [("execution_plane.crawler.engine.run_crawler", scan_id)]

    app.dependency_overrides.clear()


def test_post_unauth_scan_enqueue_failure_marks_scan_failed(monkeypatch) -> None:
    fake_db = _FakeSession()

    async def _override_get_db():
        yield fake_db

    monkeypatch.setattr(scans_module, "_get_recon_queue", lambda: _FailingQueue())
    monkeypatch.setattr(scans_module.Redis, "from_url", lambda *args, **kwargs: _FakeKillRedis())
    _stub_preflight(monkeypatch)
    app.dependency_overrides[scans_module.get_db] = _override_get_db

    client = TestClient(app)

    create_response = client.post(
        "/scans",
        json={
            "target_url": "https://public.example.com",
            "unauth_mode": True,
        },
    )

    assert create_response.status_code == 503
    assert create_response.json()["detail"] == "Failed to enqueue scan"
    [scan] = list(fake_db.scans.values())
    assert scan.status == ScanStatus.failed
    assert scan.phase == "failed:enqueue"

    app.dependency_overrides.clear()


def test_post_scan_invalid_session_preflight_returns_422(monkeypatch) -> None:
    fake_db = _FakeSession()
    fake_queue = _FakeQueue()

    async def _override_get_db():
        yield fake_db

    monkeypatch.setattr(scans_module, "_get_auth_bootstrap_queue", lambda: fake_queue)
    _stub_preflight(
        monkeypatch,
        PreflightResult(
            status="failed",
            failures=["invalid_session"],
            missing_roles=[],
            missing_tenants=[],
            csrf_status="not_checked",
        ),
    )
    app.dependency_overrides[scans_module.get_db] = _override_get_db

    client = TestClient(app)
    response = client.post(
        "/scans",
        json={
            "target_url": "https://app.example.com",
            "auth_context": {"type": "token", "bearer_token": "expired-token"},
        },
    )

    assert response.status_code == 422
    assert response.json()["detail"]["failures"] == ["invalid_session"]
    assert fake_db.scans == {}
    assert fake_queue.calls == []

    app.dependency_overrides.clear()


def test_post_scan_degraded_preflight_returns_warning_and_continues(monkeypatch) -> None:
    fake_db = _FakeSession()
    fake_queue = _FakeQueue()

    async def _override_get_db():
        yield fake_db

    monkeypatch.setattr(scans_module, "_get_auth_bootstrap_queue", lambda: fake_queue)
    monkeypatch.setattr(scans_module.Redis, "from_url", lambda *args, **kwargs: _FakeKillRedis())
    _stub_encryption(monkeypatch)
    _stub_preflight(
        monkeypatch,
        PreflightResult(
            status="degraded",
            failures=[],
            missing_roles=[],
            missing_tenants=[],
            csrf_status="deferred",
        ),
    )
    app.dependency_overrides[scans_module.get_db] = _override_get_db

    client = TestClient(app)
    response = client.post(
        "/scans",
        json={
            "target_url": "https://app.example.com",
            "auth_context": {"type": "credential", "credentials": {"username": "alice", "password": "secret"}},
        },
    )

    assert response.status_code == 201
    body = response.json()
    assert body["status"] == "running"
    assert body["warnings"][0]["code"] == "auth_preflight_degraded"
    assert body["warnings"][0]["preflight"]["status"] == "degraded"
    assert len(fake_queue.calls) == 1

    app.dependency_overrides.clear()
