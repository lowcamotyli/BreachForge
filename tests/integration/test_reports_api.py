from __future__ import annotations

import os
from uuid import uuid4

from fastapi.testclient import TestClient

os.environ.setdefault("DATABASE_URL", "postgresql://postgres:postgres@localhost:5432/proofscan")

from api.main import app
from api.routers import reports as reports_module


class _FakeReportingService:
    def __init__(self, db) -> None:
        self._db = db

    async def export(self, scan_id, fmt: str) -> str:
        if fmt == "markdown":
            return "# report"
        return '{"scan_id": "%s", "findings": []}' % scan_id


def test_get_report_for_scan_id(monkeypatch) -> None:
    async def _override_get_db():
        yield object()

    monkeypatch.setattr(reports_module, "ReportingService", _FakeReportingService)
    app.dependency_overrides[reports_module.get_db] = _override_get_db

    client = TestClient(app)
    scan_id = uuid4()

    response = client.get(f"/scans/{scan_id}/report")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")
    assert response.json()["scan_id"] == str(scan_id)

    app.dependency_overrides.clear()
