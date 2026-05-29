from __future__ import annotations

import os
import hashlib
from collections.abc import Iterator
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock
from uuid import UUID, uuid4

import pytest
from cryptography.fernet import Fernet
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession

from api.dependencies.auth import VerifiedActor, get_verified_actor
from api.routers.api_keys import router as api_keys_router
from api.routers.audit import router as audit_router
from api.routers.runners import router as runners_router
from api.routers.secrets import router as secrets_router
from storage.db.models import Runner as RunnerModel
from storage.db.session import get_db


def make_actor(org_id: UUID) -> VerifiedActor:
    return VerifiedActor(org_id=org_id, email="test@test.com", role="admin")


@pytest.fixture
def mock_db() -> AsyncMock:
    return AsyncMock(spec=AsyncSession)


@pytest.fixture
def client(mock_db: AsyncMock) -> Iterator[TestClient]:
    app = FastAPI()
    app.include_router(api_keys_router)
    app.include_router(audit_router)
    app.include_router(runners_router)
    app.include_router(secrets_router)
    app.dependency_overrides[get_db] = lambda: mock_db

    with TestClient(app) as test_client:
        yield test_client

    app.dependency_overrides.clear()


@pytest.fixture(autouse=True)
def _set_vault_key() -> Iterator[None]:
    previous = os.environ.get("VAULT_ENCRYPTION_KEY")
    os.environ["VAULT_ENCRYPTION_KEY"] = Fernet.generate_key().decode()
    yield
    if previous is None:
        os.environ.pop("VAULT_ENCRYPTION_KEY", None)
    else:
        os.environ["VAULT_ENCRYPTION_KEY"] = previous


def test_api_keys_list_rejects_wrong_org(client: TestClient) -> None:
    actor_org_id = uuid4()
    other_org_id = uuid4()
    client.app.dependency_overrides[get_verified_actor] = lambda: make_actor(actor_org_id)

    response = client.get(f"/orgs/{other_org_id}/api-keys")

    assert response.status_code == 403


def test_api_keys_create_rejects_wrong_org(client: TestClient) -> None:
    actor_org_id = uuid4()
    other_org_id = uuid4()
    client.app.dependency_overrides[get_verified_actor] = lambda: make_actor(actor_org_id)

    response = client.post(
        f"/orgs/{other_org_id}/api-keys",
        json={"name": "CI", "scopes": ["scans:read"], "created_by": "owner@example.com"},
    )

    assert response.status_code == 403


def test_api_keys_revoke_rejects_wrong_org(client: TestClient) -> None:
    actor_org_id = uuid4()
    other_org_id = uuid4()
    key_id = uuid4()
    client.app.dependency_overrides[get_verified_actor] = lambda: make_actor(actor_org_id)

    response = client.delete(f"/orgs/{other_org_id}/api-keys/{key_id}")

    assert response.status_code == 403


def test_audit_list_rejects_wrong_org(client: TestClient) -> None:
    actor_org_id = uuid4()
    other_org_id = uuid4()
    client.app.dependency_overrides[get_verified_actor] = lambda: make_actor(actor_org_id)

    response = client.get(f"/orgs/{other_org_id}/audit")

    assert response.status_code == 403


def test_audit_export_rejects_wrong_org(client: TestClient) -> None:
    actor_org_id = uuid4()
    other_org_id = uuid4()
    client.app.dependency_overrides[get_verified_actor] = lambda: make_actor(actor_org_id)

    response = client.post(f"/orgs/{other_org_id}/audit/export")

    assert response.status_code == 403


def test_runners_list_rejects_wrong_org(client: TestClient) -> None:
    actor_org_id = uuid4()
    other_org_id = uuid4()
    client.app.dependency_overrides[get_verified_actor] = lambda: make_actor(actor_org_id)

    response = client.get(f"/runners?org_id={other_org_id}")

    assert response.status_code == 403


def test_runner_heartbeat_requires_runner_token(client: TestClient) -> None:
    runner_id = uuid4()

    response = client.post(f"/runners/{runner_id}/heartbeat", json={})

    assert response.status_code == 401


def test_runner_heartbeat_rejects_wrong_token(client: TestClient, mock_db: AsyncMock) -> None:
    runner_id = uuid4()
    row = RunnerModel(
        id=runner_id,
        org_id=uuid4(),
        name="runner",
        token_hash=hashlib.sha256(b"correct-token").hexdigest(),
        token_prefix="correct-...",
        capabilities={},
        registered_at=datetime(2026, 5, 29, 12, 0, tzinfo=UTC),
    )
    result = MagicMock()
    result.scalar_one_or_none.return_value = row
    mock_db.execute.return_value = result

    response = client.post(
        f"/runners/{runner_id}/heartbeat",
        headers={"Authorization": "Bearer wrong-token"},
        json={},
    )

    assert response.status_code == 401
    mock_db.commit.assert_not_awaited()


def test_runner_heartbeat_accepts_matching_token(client: TestClient, mock_db: AsyncMock) -> None:
    runner_id = uuid4()
    current_job_id = uuid4()
    row = RunnerModel(
        id=runner_id,
        org_id=uuid4(),
        name="runner",
        token_hash=hashlib.sha256(b"correct-token").hexdigest(),
        token_prefix="correct-...",
        capabilities={},
        registered_at=datetime(2026, 5, 29, 12, 0, tzinfo=UTC),
    )
    result = MagicMock()
    result.scalar_one_or_none.return_value = row
    mock_db.execute.return_value = result

    response = client.post(
        f"/runners/{runner_id}/heartbeat",
        headers={"Authorization": "Bearer correct-token"},
        json={"current_job_id": str(current_job_id)},
    )

    assert response.status_code == 200
    assert response.json()["ok"] is True
    assert row.current_job_id == current_job_id
    assert row.is_online is True
    mock_db.commit.assert_awaited_once()


def test_secrets_create_rejects_wrong_org(client: TestClient) -> None:
    actor_org_id = uuid4()
    other_org_id = uuid4()
    client.app.dependency_overrides[get_verified_actor] = lambda: make_actor(actor_org_id)

    response = client.post(
        f"/orgs/{other_org_id}/secrets",
        json={"name": "db-password", "secret_type": "api_credential", "plaintext": "super-secret"},
    )

    assert response.status_code == 403
