from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession

from api.dependencies.auth import VerifiedActor, get_verified_actor
from api.routers.orgs import router
from storage.db.models import OrgMember, OrgRole, Organization
from storage.db.session import get_db


@pytest.fixture
def mock_db() -> AsyncMock:
    return AsyncMock(spec=AsyncSession)


@pytest.fixture
def client(mock_db: AsyncMock) -> Iterator[TestClient]:
    app = FastAPI()
    app.include_router(router)
    actor = VerifiedActor(org_id=uuid4(), email="admin@example.com", role=OrgRole.owner)
    app.state.actor_org_id = actor.org_id
    app.dependency_overrides[get_db] = lambda: mock_db
    app.dependency_overrides[get_verified_actor] = lambda: actor

    with TestClient(app) as test_client:
        yield test_client

    app.dependency_overrides.clear()


def test_create_org_inserts_to_db(client: TestClient, mock_db: AsyncMock) -> None:
    org_id = uuid4()
    created_at = datetime(2026, 5, 28, 10, 0, tzinfo=UTC)

    async def refresh_row(row: Organization) -> None:
        row.id = org_id
        row.name = "Acme"
        row.slug = "acme"
        row.created_at = created_at

    mock_db.refresh.side_effect = refresh_row

    response = client.post("/orgs", json={"name": "Acme", "slug": "acme"})

    assert response.status_code == 201
    payload = response.json()
    assert payload["org_id"] == str(org_id)
    assert payload["name"] == "Acme"
    assert payload["slug"] == "acme"
    assert payload["created_at"] == created_at.isoformat().replace("+00:00", "Z")
    mock_db.add.assert_called_once()
    added_row = mock_db.add.call_args.args[0]
    assert isinstance(added_row, Organization)
    assert added_row.name == "Acme"
    assert added_row.slug == "acme"
    mock_db.commit.assert_awaited_once()
    mock_db.refresh.assert_awaited_once_with(added_row)


def test_get_org_returns_404_when_not_found(client: TestClient, mock_db: AsyncMock) -> None:
    org_id = uuid4()
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = None
    mock_db.execute.return_value = mock_result

    response = client.get(f"/orgs/{org_id}")

    assert response.status_code == 404
    assert response.json() == {"detail": "org not found"}
    mock_db.execute.assert_awaited_once()


def test_get_org_returns_org_when_found(client: TestClient, mock_db: AsyncMock) -> None:
    org_id = uuid4()
    created_at = datetime(2026, 5, 28, 10, 0, tzinfo=UTC)
    row = Organization(id=org_id, name="Acme", slug="acme", created_at=created_at)
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = row
    mock_db.execute.return_value = mock_result

    response = client.get(f"/orgs/{org_id}")

    assert response.status_code == 200
    assert response.json() == {
        "org_id": str(org_id),
        "name": "Acme",
        "slug": "acme",
        "created_at": created_at.isoformat().replace("+00:00", "Z"),
    }
    mock_db.execute.assert_awaited_once()


def test_list_members_queries_org_members(client: TestClient, mock_db: AsyncMock) -> None:
    org_id = client.app.state.actor_org_id
    rows = [
        OrgMember(org_id=org_id, user_email="admin@example.com", role=OrgRole.appsec_admin),
        OrgMember(org_id=org_id, user_email="dev@example.com", role=OrgRole.developer),
    ]
    mock_result = MagicMock()
    mock_result.scalars.return_value.all.return_value = rows
    mock_db.execute.return_value = mock_result

    response = client.get(f"/orgs/{org_id}/members")

    assert response.status_code == 200
    assert response.json() == [
        {"email": "admin@example.com", "role": "appsec_admin"},
        {"email": "dev@example.com", "role": "developer"},
    ]
    mock_db.execute.assert_awaited()


def test_add_member_inserts_org_member(client: TestClient, mock_db: AsyncMock) -> None:
    org_id = client.app.state.actor_org_id
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = Organization(id=org_id, name="Acme", slug="acme")
    mock_db.execute.return_value = mock_result

    response = client.post(
        f"/orgs/{org_id}/members",
        json={"email": "DEV@example.com", "role": "developer"},
    )

    assert response.status_code == 200
    assert response.json() == {"email": "dev@example.com", "role": "developer"}
    mock_db.add.assert_called_once()
    added_row = mock_db.add.call_args.args[0]
    assert isinstance(added_row, OrgMember)
    assert added_row.org_id == org_id
    assert added_row.user_email == "dev@example.com"
    assert added_row.role is OrgRole.developer
    mock_db.commit.assert_awaited_once()


def test_add_member_rejects_wrong_org(client: TestClient, mock_db: AsyncMock) -> None:
    other_org_id = uuid4()

    response = client.post(
        f"/orgs/{other_org_id}/members",
        json={"email": "dev@example.com", "role": "developer"},
    )

    assert response.status_code == 403
    mock_db.add.assert_not_called()
