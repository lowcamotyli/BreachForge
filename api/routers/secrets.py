from __future__ import annotations

from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.dependencies.auth import VerifiedActor, get_verified_actor
from storage.db.models import Secret
from storage.db.session import get_db
from storage.secrets.vault import SecretEntry, SecretStatus, SecretType, SecretsVault

router = APIRouter(prefix="/orgs/{org_id}/secrets")


class SecretCreateRequest(BaseModel):
    name: str
    secret_type: SecretType
    plaintext: str
    expires_at: datetime | None = None


class SecretRotateRequest(BaseModel):
    new_plaintext: str


class SecretResponse(BaseModel):
    secret_id: UUID
    org_id: UUID
    name: str
    secret_type: SecretType
    status: SecretStatus
    version: int
    created_at: datetime
    expires_at: datetime | None
    rotated_at: datetime | None
    revoked_at: datetime | None
    deleted_at: datetime | None
    redacted_preview: str
    metadata: dict[str, object] = Field(default_factory=dict)


def _to_secret_response(entry: SecretEntry) -> SecretResponse:
    return SecretResponse(
        secret_id=entry.secret_id,
        org_id=entry.org_id,
        name=entry.name,
        secret_type=entry.secret_type,
        status=entry.status,
        version=entry.version,
        created_at=entry.created_at,
        expires_at=entry.expires_at,
        rotated_at=entry.rotated_at,
        revoked_at=entry.revoked_at,
        deleted_at=entry.deleted_at,
        redacted_preview=entry.redacted_preview,
        metadata=dict(entry.metadata),
    )


@router.post("", response_model=SecretResponse, status_code=status.HTTP_201_CREATED)
async def create_secret(
    org_id: UUID,
    payload: SecretCreateRequest,
    actor: VerifiedActor = Depends(get_verified_actor),
    db: AsyncSession = Depends(get_db),
) -> SecretResponse:
    if actor.org_id != org_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")

    vault = SecretsVault(session=db)
    entry = await vault.store(
        org_id=org_id,
        name=payload.name,
        secret_type=payload.secret_type,
        plaintext=payload.plaintext,
        expires_at=payload.expires_at,
    )
    return _to_secret_response(entry)


@router.get("", response_model=list[SecretResponse])
async def list_secrets(
    org_id: UUID,
    actor: VerifiedActor = Depends(get_verified_actor),
    db: AsyncSession = Depends(get_db),
) -> list[SecretResponse]:
    if actor.org_id != org_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")

    vault = SecretsVault(session=db)
    return [_to_secret_response(entry) for entry in await vault.list_for_org(org_id)]


@router.post("/{secret_id}/rotate", response_model=SecretResponse)
async def rotate_secret(
    org_id: UUID,
    secret_id: UUID,
    payload: SecretRotateRequest,
    actor: VerifiedActor = Depends(get_verified_actor),
    db: AsyncSession = Depends(get_db),
) -> SecretResponse:
    if actor.org_id != org_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")

    vault = SecretsVault(session=db)
    result = await db.execute(select(Secret).where(Secret.id == secret_id, Secret.org_id == org_id))
    if result.scalar_one_or_none() is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Secret not found")

    rotated = await vault.rotate(secret_id, payload.new_plaintext)
    if rotated is None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Secret cannot be rotated")
    return _to_secret_response(rotated)


@router.delete("/{secret_id}")
async def delete_secret(
    org_id: UUID,
    secret_id: UUID,
    actor: VerifiedActor = Depends(get_verified_actor),
    db: AsyncSession = Depends(get_db),
) -> dict[str, str]:
    if actor.org_id != org_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")

    vault = SecretsVault(session=db)
    result = await db.execute(select(Secret).where(Secret.id == secret_id, Secret.org_id == org_id))
    if result.scalar_one_or_none() is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Secret not found")

    await vault.delete(secret_id)
    return {"status": "deleted"}
