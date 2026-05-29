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
from api.routers.api_keys import router
from storage.db.models import APIKey as APIKeyModel, OrgRole
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


def test_list_api_keys_queries_db(client: TestClient, mock_db: AsyncMock) -> None:
    org_id = client.app.state.actor_org_id
    first_id = uuid4()
    second_id = uuid4()
    created_at = datetime(2026, 5, 28, 10, 0, tzinfo=UTC)
    expires_at = datetime(2026, 6, 28, 10, 0, tzinfo=UTC)
    revoked_at = datetime(2026, 5, 29, 10, 0, tzinfo=UTC)
    rows = [
        APIKeyModel(
            id=first_id,
            org_id=org_id,
            name="CI",
            key_hash="hash-1",
            key_prefix="ci-key...",
            scopes=["scans:read"],
            created_by="owner@example.com",
            created_at=created_at,
            expires_at=expires_at,
        ),
        APIKeyModel(
            id=second_id,
            org_id=org_id,
            name="Runner",
            key_hash="hash-2",
            key_prefix="runner...",
            scopes=["scans:write"],
            created_by="owner@example.com",
            created_at=created_at,
            revoked_at=revoked_at,
        ),
    ]
    mock_result = MagicMock()
    mock_result.scalars.return_value.all.return_value = rows
    mock_db.execute.return_value = mock_result

    response = client.get(f"/orgs/{org_id}/api-keys")

    assert response.status_code == 200
    assert response.json() == [
        {
            "id": str(first_id),
            "name": "CI",
            "prefix": "ci-key...",
            "scopes": ["scans:read"],
            "created_at": created_at.isoformat().replace("+00:00", "Z"),
            "expires_at": expires_at.isoformat().replace("+00:00", "Z"),
            "revoked_at": None,
        },
        {
            "id": str(second_id),
            "name": "Runner",
            "prefix": "runner...",
            "scopes": ["scans:write"],
            "created_at": created_at.isoformat().replace("+00:00", "Z"),
            "expires_at": None,
            "revoked_at": revoked_at.isoformat().replace("+00:00", "Z"),
        },
    ]
    mock_db.execute.assert_awaited_once()


def test_create_api_key_inserts_and_returns_plaintext(client: TestClient, mock_db: AsyncMock) -> None:
    org_id = client.app.state.actor_org_id
    row_id = uuid4()
    plaintext_key = "a" * 43

    async def refresh_row(row: APIKeyModel) -> None:
        row.id = row_id
        row.key_prefix = "aaaaaaaa..."
        row.name = "CI"
        row.scopes = ["scans:read"]

    mock_db.refresh.side_effect = refresh_row

    with patch("api.routers.api_keys.secrets.token_urlsafe", return_value=plaintext_key):
        response = client.post(
            f"/orgs/{org_id}/api-keys",
            json={"name": "CI", "scopes": ["scans:read"], "created_by": "owner@example.com"},
        )

    assert response.status_code == 201
    payload = response.json()
    assert payload["id"] == str(row_id)
    assert payload["key"] == plaintext_key
    assert len(payload["key"]) == 43
    assert payload["prefix"] == "aaaaaaaa..."
    assert payload["name"] == "CI"
    assert payload["scopes"] == ["scans:read"]
    mock_db.add.assert_called_once()
    added_row = mock_db.add.call_args.args[0]
    assert isinstance(added_row, APIKeyModel)
    assert added_row.org_id == org_id
    assert added_row.name == "CI"
    assert added_row.scopes == ["scans:read"]
    assert added_row.key_hash
    assert added_row.key_hash != plaintext_key
    mock_db.commit.assert_awaited_once()
    mock_db.refresh.assert_awaited_once_with(added_row)


def test_revoke_api_key_updates_revoked_at(client: TestClient, mock_db: AsyncMock) -> None:
    org_id = client.app.state.actor_org_id
    key_id = uuid4()
    row = APIKeyModel(
        id=key_id,
        org_id=org_id,
        name="CI",
        key_hash="hash",
        key_prefix="ci-key...",
        scopes=["scans:read"],
        created_by="owner@example.com",
    )
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = row
    mock_db.execute.return_value = mock_result

    response = client.delete(f"/orgs/{org_id}/api-keys/{key_id}")

    assert response.status_code == 200
    assert response.json() == {"status": "revoked"}
    assert row.revoked_at is not None
    assert row.revoked_at.tzinfo is UTC
    mock_db.execute.assert_awaited_once()
    mock_db.commit.assert_awaited_once()


def test_revoke_api_key_404_when_not_found(client: TestClient, mock_db: AsyncMock) -> None:
    org_id = client.app.state.actor_org_id
    key_id = uuid4()
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = None
    mock_db.execute.return_value = mock_result

    response = client.delete(f"/orgs/{org_id}/api-keys/{key_id}")

    assert response.status_code == 404
    assert response.json() == {"detail": "API key not found"}
    mock_db.execute.assert_awaited_once()
    mock_db.commit.assert_not_awaited()
