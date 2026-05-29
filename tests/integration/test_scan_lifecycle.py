from __future__ import annotations

import os
from datetime import UTC, datetime
from uuid import UUID, uuid4

from fastapi.testclient import TestClient

os.environ.setdefault("DATABASE_URL", "postgresql://postgres:postgres@localhost:5432/proofscan")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/0")

from api.routers import scans as scans_module
from api.main import app
from storage.db.models import Scan, ScanStatus, Target, AuthContext
from control_plane.orchestrator import PreflightResult


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


def test_full_scan_lifecycle(monkeypatch) -> None:
    fake_session = _FakeSession()
    fake_queue = _FakeQueue()

    async def _override_get_db():
        yield fake_session

    monkeypatch.setattr(scans_module, "_get_auth_bootstrap_queue", lambda: fake_queue)
    monkeypatch.setattr(scans_module.Redis, "from_url", lambda *args, **kwargs: _FakeKillRedis())
    _stub_preflight(monkeypatch)
    _stub_encryption(monkeypatch)

    app.dependency_overrides[scans_module.get_db] = _override_get_db

    try:
        client = TestClient(app)

        create_payload = {
            "target_url": "https://app.example.com",
            "scan_type": "full",
            "policy": {
                "allowed_domains": ["app.example.com"],
                "max_requests": 500,
                "mutating_allowed": False,
                "replay_allowed": False,
                "oob_allowed": False,
            },
            "auth_context": {"type": "token", "bearer_token": "valid-token"},
        }
        create_response = client.post("/scans", json=create_payload)

        assert create_response.status_code == 201
        scan_id = create_response.json()["id"]
        assert len(fake_queue.calls) >= 1

        get_response = client.get(f"/scans/{scan_id}")

        assert get_response.status_code == 200
        assert get_response.json()["id"] == scan_id
    finally:
        app.dependency_overrides.clear()
