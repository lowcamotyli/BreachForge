from __future__ import annotations

import hashlib
import secrets
from datetime import UTC, datetime
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.dependencies.auth import VerifiedActor, get_verified_actor
from storage.db.models import APIKey as APIKeyModel
from storage.db.session import get_db

router = APIRouter(prefix="/orgs/{org_id}/api-keys")


class APIKeyCreate(BaseModel):
    name: str
    scopes: list[str] = Field(default_factory=list)
    created_by: str = "system"
    expires_at: datetime | None = None


class APIKeyListItem(BaseModel):
    id: UUID
    name: str
    prefix: str
    scopes: list[str]
    created_at: datetime
    expires_at: datetime | None
    revoked_at: datetime | None


class APIKeyCreateResponse(BaseModel):
    id: UUID
    key: str
    prefix: str
    name: str
    scopes: list[str]


def _hash_secret(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _key_prefix(value: str) -> str:
    return f"{value[:8]}..."


@router.get("", response_model=list[APIKeyListItem])
async def list_api_keys(
    org_id: UUID,
    actor: VerifiedActor = Depends(get_verified_actor),
    db: AsyncSession = Depends(get_db),
) -> list[APIKeyListItem]:
    if actor.org_id != org_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")

    try:
        result = await db.execute(select(APIKeyModel).where(APIKeyModel.org_id == org_id))
        return [
            APIKeyListItem(
                id=row.id,
                name=row.name,
                prefix=row.key_prefix,
                scopes=row.scopes,
                created_at=row.created_at,
                expires_at=row.expires_at,
                revoked_at=row.revoked_at,
            )
            for row in result.scalars().all()
        ]
    except Exception:
        await db.rollback()
        raise HTTPException(status_code=500, detail="db error")


@router.post("", response_model=APIKeyCreateResponse, status_code=status.HTTP_201_CREATED)
async def create_api_key(
    org_id: UUID,
    payload: APIKeyCreate,
    actor: VerifiedActor = Depends(get_verified_actor),
    db: AsyncSession = Depends(get_db),
) -> APIKeyCreateResponse:
    if actor.org_id != org_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")

    try:
        plaintext_key = secrets.token_urlsafe(32)
        row = APIKeyModel(
            org_id=org_id,
            name=payload.name,
            key_hash=_hash_secret(plaintext_key),
            key_prefix=_key_prefix(plaintext_key),
            scopes=payload.scopes,
            created_by=payload.created_by,
            expires_at=payload.expires_at,
        )
        db.add(row)
        await db.commit()
        await db.refresh(row)
        return APIKeyCreateResponse(
            id=row.id,
            key=plaintext_key,
            prefix=row.key_prefix,
            name=row.name,
            scopes=row.scopes,
        )
    except Exception:
        await db.rollback()
        raise HTTPException(status_code=500, detail="db error")


@router.delete("/{key_id}")
async def revoke_api_key(
    org_id: UUID,
    key_id: UUID,
    actor: VerifiedActor = Depends(get_verified_actor),
    db: AsyncSession = Depends(get_db),
) -> dict[str, str]:
    if actor.org_id != org_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")

    try:
        result = await db.execute(select(APIKeyModel).where(APIKeyModel.id == key_id, APIKeyModel.org_id == org_id))
        row = result.scalar_one_or_none()
        if row is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="API key not found")

        row.revoked_at = datetime.now(UTC)
        await db.commit()
        return {"status": "revoked"}
    except HTTPException:
        raise
    except Exception:
        await db.rollback()
        raise HTTPException(status_code=500, detail="db error")
