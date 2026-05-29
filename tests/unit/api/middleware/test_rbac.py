from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession

from api.dependencies.auth import VerifiedActor, get_verified_actor
from api.middleware.rbac import OrgRole, RoleStore, require_role, role_store
from storage.db.models import OrgMember as OrgMemberRow
from storage.db.session import get_db


@pytest.mark.asyncio
async def test_has_role_returns_true_when_role_sufficient() -> None:
    db = AsyncMock(spec=AsyncSession)
    org_id = uuid4()
    email = "admin@example.com"

    with patch.object(RoleStore, "get_role", new=AsyncMock(return_value=OrgRole.appsec_admin)) as get_role:
        result = await role_store.has_role(db, org_id, email, OrgRole.developer)

    assert result is True
    get_role.assert_awaited_once_with(db, org_id, email)


@pytest.mark.asyncio
async def test_has_role_returns_false_when_no_role() -> None:
    db = AsyncMock(spec=AsyncSession)
    org_id = uuid4()
    email = "missing@example.com"

    with patch.object(RoleStore, "get_role", new=AsyncMock(return_value=None)) as get_role:
        result = await role_store.has_role(db, org_id, email, OrgRole.developer)

    assert result is False
    get_role.assert_awaited_once_with(db, org_id, email)


@pytest.mark.asyncio
async def test_list_members_returns_sorted_by_email() -> None:
    db = AsyncMock(spec=AsyncSession)
    org_id = uuid4()
    rows = [
        OrgMemberRow(user_email="b@x", role=OrgRole.developer),
        OrgMemberRow(user_email="a@x", role=OrgRole.auditor),
    ]
    result = MagicMock()
    result.scalars.return_value.all.return_value = rows
    db.execute.return_value = result

    members = await role_store.list_members(db, org_id)

    assert [member.email for member in members] == ["a@x", "b@x"]
    assert members[0].role is OrgRole.auditor


@pytest.mark.asyncio
async def test_remove_returns_true_when_deleted() -> None:
    db = AsyncMock(spec=AsyncSession)
    result = MagicMock()
    result.rowcount = 1
    db.execute.return_value = result

    removed = await role_store.remove(db, uuid4(), "test@x")

    assert removed is True
    db.commit.assert_awaited_once()


def test_require_role_endpoint_returns_403_when_no_role() -> None:
    app = FastAPI()

    @app.post("/guarded", dependencies=[require_role(OrgRole.developer)])
    async def guarded() -> dict[str, str]:
        return {"status": "ok"}

    low_actor = VerifiedActor(org_id=uuid4(), email="test@x", role=OrgRole.runner)
    app.dependency_overrides[get_verified_actor] = lambda: low_actor

    response = TestClient(app).post("/guarded")

    assert response.status_code == 403
