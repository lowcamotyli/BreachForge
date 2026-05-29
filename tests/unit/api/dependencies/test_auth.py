from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest
from fastapi import HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

import api.dependencies.auth as auth_dependency
from api.dependencies.auth import VerifiedActor, get_verified_actor
from storage.db.models import OrgRole


def _result(value: object | None) -> MagicMock:
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = value
    return mock_result


@pytest.fixture
def mock_db() -> AsyncMock:
    return AsyncMock(spec=AsyncSession)


@pytest.mark.asyncio
async def test_get_verified_actor_without_authorization_header_returns_401(mock_db: AsyncMock) -> None:
    with pytest.raises(HTTPException) as exc_info:
        await get_verified_actor(authorization=None, actor_email_header=None, org_id_header=None, db=mock_db)

    assert (exc_info.value.status_code, exc_info.value.detail) == (401, "invalid or expired API key")


@pytest.mark.asyncio
async def test_get_verified_actor_with_valid_bearer_token_resolves_actor(mock_db: AsyncMock) -> None:
    test_key = "proofscan-test-key"
    org_id = uuid4()
    api_key = SimpleNamespace(
        key_hash=hashlib.sha256(test_key.encode()).hexdigest(),
        org_id=org_id,
        created_by="test@test.com",
        revoked_at=None,
        expires_at=None,
        last_used_at=None,
    )
    mock_db.execute.side_effect = [_result(api_key), _result(OrgRole.developer)]

    actor = await get_verified_actor(
        authorization=f"Bearer {test_key}",
        actor_email_header=None,
        org_id_header=None,
        db=mock_db,
    )

    assert actor == VerifiedActor(org_id=org_id, email="test@test.com", role=OrgRole.developer)


@pytest.mark.asyncio
async def test_get_verified_actor_with_actor_email_header_without_dev_mode_returns_401(
    mock_db: AsyncMock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("PROOFSCAN_DEV_MODE", raising=False)
    monkeypatch.setattr(auth_dependency, "_DEV_MODE_ENABLED", False)

    with pytest.raises(HTTPException) as exc_info:
        await get_verified_actor(
            authorization=None,
            actor_email_header="test@test.com",
            org_id_header=str(uuid4()),
            db=mock_db,
        )

    assert (exc_info.value.status_code, exc_info.value.detail) == (401, "invalid or expired API key")


@pytest.mark.asyncio
async def test_get_verified_actor_with_revoked_api_key_returns_401(mock_db: AsyncMock) -> None:
    revoked_key = SimpleNamespace(
        key_hash=hashlib.sha256("revoked-key".encode()).hexdigest(),
        org_id=uuid4(),
        created_by="test@test.com",
        revoked_at=datetime(2026, 5, 28, tzinfo=UTC),
        expires_at=None,
    )
    mock_db.execute.return_value = _result(None)

    with pytest.raises(HTTPException) as exc_info:
        await get_verified_actor(
            authorization="Bearer revoked-key",
            actor_email_header=None,
            org_id_header=None,
            db=mock_db,
        )

    assert (revoked_key.revoked_at is not None, exc_info.value.status_code, exc_info.value.detail) == (
        True,
        401,
        "invalid or expired API key",
    )
