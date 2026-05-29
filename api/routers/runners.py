from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import UTC, datetime
from uuid import UUID

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Response, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.dependencies.auth import VerifiedActor, get_verified_actor
from storage.db.models import Runner as RunnerModel
from storage.db.session import get_db

router = APIRouter()


class RunnerCapabilitiesRequest(BaseModel):
    attack_classes: list[str] = Field(default_factory=list)
    max_concurrent_jobs: int = 1
    platform: str = "linux"
    runner_version: str = "1.0.0"
    extra: dict[str, object] = Field(default_factory=dict)


class RunnerRegistrationRequest(BaseModel):
    org_id: UUID | None = None
    name: str
    capabilities: RunnerCapabilitiesRequest


class RunnerRegistrationResponse(BaseModel):
    runner_id: UUID
    token: str
    token_prefix: str
    name: str
    registered_at: datetime


class RunnerHeartbeatRequest(BaseModel):
    current_job_id: UUID | None = None


class RunnerHeartbeatResponse(BaseModel):
    ok: bool
    timestamp: datetime


class RunnerCapabilitiesResponse(BaseModel):
    attack_classes: list[str]
    max_concurrent_jobs: int
    platform: str
    runner_version: str
    extra: dict[str, object]


class RunnerResponse(BaseModel):
    runner_id: UUID
    org_id: UUID
    name: str
    token_prefix: str
    capabilities: RunnerCapabilitiesResponse
    registered_at: datetime
    last_heartbeat_at: datetime | None
    is_online: bool
    current_job_id: UUID | None
    version: str


def _to_runner_response(row: RunnerModel) -> RunnerResponse:
    capabilities_payload = row.capabilities if isinstance(row.capabilities, dict) else {}
    return RunnerResponse(
        runner_id=row.id,
        org_id=row.org_id,
        name=row.name,
        token_prefix=row.token_prefix,
        capabilities=RunnerCapabilitiesResponse(
            attack_classes=list(capabilities_payload.get("attack_classes", [])),
            max_concurrent_jobs=int(capabilities_payload.get("max_concurrent_jobs", 1)),
            platform=str(capabilities_payload.get("platform", "linux")),
            runner_version=str(capabilities_payload.get("runner_version", row.version)),
            extra=dict(capabilities_payload.get("extra", {})),
        ),
        registered_at=row.registered_at,
        last_heartbeat_at=row.last_heartbeat_at,
        is_online=row.is_online,
        current_job_id=row.current_job_id,
        version=row.version,
    )


def _extract_bearer_token(authorization: str | None) -> str | None:
    if not authorization:
        return None
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer":
        return None
    value = token.strip()
    return value or None


def _runner_token_matches(row: RunnerModel, token: str) -> bool:
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    return hmac.compare_digest(row.token_hash, token_hash)


@router.post("/runners/register", response_model=RunnerRegistrationResponse)
async def register_runner(
    payload: RunnerRegistrationRequest,
    actor: VerifiedActor = Depends(get_verified_actor),
    db: AsyncSession = Depends(get_db),
) -> RunnerRegistrationResponse:
    try:
        token = secrets.token_urlsafe(32)
        row = RunnerModel(
            org_id=actor.org_id,
            name=payload.name,
            token_hash=hashlib.sha256(token.encode()).hexdigest(),
            token_prefix=token[:8] + "...",
            capabilities=payload.capabilities.model_dump(),
            version=payload.capabilities.runner_version,
        )
        db.add(row)
        await db.commit()
        await db.refresh(row)
        return RunnerRegistrationResponse(
            runner_id=row.id,
            token=token,
            token_prefix=row.token_prefix,
            name=row.name,
            registered_at=row.registered_at,
        )
    except Exception as exc:
        await db.rollback()
        raise HTTPException(status_code=500, detail="Failed to register runner") from exc


@router.post("/runners/{runner_id}/heartbeat", response_model=RunnerHeartbeatResponse)
async def heartbeat_runner(
    runner_id: UUID,
    payload: RunnerHeartbeatRequest,
    authorization: str | None = Header(default=None, alias="Authorization"),
    db: AsyncSession = Depends(get_db),
) -> RunnerHeartbeatResponse:
    runner_token = _extract_bearer_token(authorization)
    if runner_token is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid runner token")

    try:
        result = await db.execute(select(RunnerModel).where(RunnerModel.id == runner_id))
        row = result.scalar_one_or_none()
        if row is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="runner not found")
        if not _runner_token_matches(row, runner_token):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid runner token")

        row.last_heartbeat_at = datetime.now(UTC)
        row.current_job_id = payload.current_job_id
        row.is_online = True
        await db.commit()
        return RunnerHeartbeatResponse(ok=True, timestamp=datetime.now(UTC))
    except HTTPException:
        raise
    except Exception as exc:
        await db.rollback()
        raise HTTPException(status_code=500, detail="Failed to update runner heartbeat") from exc


@router.get("/runners", response_model=list[RunnerResponse])
async def list_runners(
    org_id: UUID = Query(...),
    actor: VerifiedActor = Depends(get_verified_actor),
    db: AsyncSession = Depends(get_db),
) -> list[RunnerResponse]:
    if actor.org_id != org_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")

    try:
        result = await db.execute(select(RunnerModel).where(RunnerModel.org_id == org_id))
        return [_to_runner_response(runner) for runner in result.scalars().all()]
    except Exception as exc:
        await db.rollback()
        raise HTTPException(status_code=500, detail="Failed to list runners") from exc


@router.delete("/runners/{runner_id}", status_code=status.HTTP_204_NO_CONTENT)
async def deregister_runner(
    runner_id: UUID,
    actor: VerifiedActor = Depends(get_verified_actor),
    db: AsyncSession = Depends(get_db),
) -> Response:
    try:
        result = await db.execute(select(RunnerModel).where(RunnerModel.id == runner_id))
        row = result.scalar_one_or_none()
        if row:
            if row.org_id != actor.org_id:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")
            await db.delete(row)
            await db.commit()
        return Response(status_code=status.HTTP_204_NO_CONTENT)
    except HTTPException:
        raise
    except Exception as exc:
        await db.rollback()
        raise HTTPException(status_code=500, detail="Failed to deregister runner") from exc
