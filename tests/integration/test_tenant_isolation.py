from __future__ import annotations

from fastapi.testclient import TestClient
import os
from uuid import UUID, uuid4
import pytest
from unittest.mock import AsyncMock, MagicMock

os.environ["DATABASE_URL"] = "postgresql+asyncpg://proofscan:proofscan@localhost:5432/proofscan_test"
os.environ["REDIS_URL"] = "redis://localhost:6379/15"

from api.main import app
from api.routers import orgs as orgs_module
from api.dependencies.auth import get_verified_actor, VerifiedActor
from storage.db.models import OrgRole, Organization, OrgMember


class _FakeScalarResult:
    def __init__(self, rows: list[OrgMember]) -> None:
        self._rows = rows

    def all(self) -> list[OrgMember]:
        return self._rows


class _FakeResult:
    def __init__(self, row: Organization | None = None, members: list[OrgMember] | None = None) -> None:
        self._row = row
        self._members = members or []

    def scalar_one_or_none(self) -> Organization | None:
        return self._row

    def scalars(self) -> _FakeScalarResult:
        return _FakeScalarResult(self._members)


class _FakeOrgsSession:
    def __init__(
        self,
        org_a_id: UUID,
        org_b_id: UUID,
        org_a_exists: bool = True,
        org_b_exists: bool = False,
    ) -> None:
        self.org_a_id = org_a_id
        self.org_b_id = org_b_id
        self.org_a_exists = org_a_exists
        self.org_b_exists = org_b_exists
        self.execute_mock = MagicMock()
        self.async_marker = AsyncMock(name="_FakeOrgsSession.async_marker")
        self.marker = MagicMock(name="_FakeOrgsSession")

    async def execute(self, statement):
        self.execute_mock(statement)
        org_id = self._queried_org_id(statement)
        if org_id == self.org_a_id:
            return _FakeResult(row=self._organization(self.org_a_id, "Org A") if self.org_a_exists else None)
        if org_id == self.org_b_id:
            return _FakeResult(row=self._organization(self.org_b_id, "Org B") if self.org_b_exists else None)
        return _FakeResult(members=[])

    @staticmethod
    def _queried_org_id(statement) -> UUID | None:
        for value in statement.compile().params.values():
            if isinstance(value, UUID):
                return value
        return None

    @staticmethod
    def _organization(org_id: UUID, name: str) -> Organization:
        return Organization(id=org_id, name=name, slug=name.lower().replace(" ", "-"))


def test_org_a_actor_can_access_own_org(monkeypatch: pytest.MonkeyPatch) -> None:
    org_a_id = uuid4()
    org_b_id = uuid4()
    session = _FakeOrgsSession(org_a_id=org_a_id, org_b_id=org_b_id)

    async def _fake_actor() -> VerifiedActor:
        return VerifiedActor(org_id=org_a_id, email="user@a.com", role=OrgRole.auditor)

    async def _override_get_db():
        yield session

    app.dependency_overrides[get_verified_actor] = _fake_actor
    app.dependency_overrides[orgs_module.get_db] = _override_get_db
    try:
        response = TestClient(app).get(f"/orgs/{org_a_id}/members")
        assert response.status_code == 200
    finally:
        app.dependency_overrides.clear()


def test_org_a_actor_cannot_access_nonexistent_org_b(monkeypatch: pytest.MonkeyPatch) -> None:
    org_a_id = uuid4()
    org_b_id = uuid4()
    session = _FakeOrgsSession(org_a_id=org_a_id, org_b_id=org_b_id, org_b_exists=False)

    async def _fake_actor() -> VerifiedActor:
        return VerifiedActor(org_id=org_a_id, email="user@a.com", role=OrgRole.auditor)

    async def _override_get_db():
        yield session

    app.dependency_overrides[get_verified_actor] = _fake_actor
    app.dependency_overrides[orgs_module.get_db] = _override_get_db
    try:
        response = TestClient(app).get(f"/orgs/{org_b_id}/members")
        assert response.status_code == 403
    finally:
        app.dependency_overrides.clear()
