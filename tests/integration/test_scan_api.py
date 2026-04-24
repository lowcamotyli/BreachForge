from __future__ import annotations

import os
from datetime import UTC, datetime
from uuid import UUID, uuid4

from fastapi.testclient import TestClient

os.environ.setdefault("DATABASE_URL", "postgresql://postgres:postgres@localhost:5432/proofscan")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/0")

from api.main import app
from api.routers import scans as scans_module
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
        self.calls: list[tuple[str, str, str]] = []

    def enqueue(self, task_name: str, scan_id: str, auth_context_id: str) -> None:
        self.calls.append((task_name, scan_id, auth_context_id))


def test_post_and_get_scan_with_mock_db_and_mock_redis(monkeypatch) -> None:
    fake_db = _FakeSession()
    fake_queue = _FakeQueue()

    async def _override_get_db():
        yield fake_db

    monkeypatch.setattr(scans_module, "_get_auth_bootstrap_queue", lambda: fake_queue)
    app.dependency_overrides[scans_module.get_db] = _override_get_db

    client = TestClient(app)

    create_payload = {
        "target_url": "https://app.example.com",
        "auth_context": {"type": "none"},
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
    assert get_body["status"] == "created"
    assert len(fake_queue.calls) == 1

    app.dependency_overrides.clear()
