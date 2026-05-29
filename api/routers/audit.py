from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.dependencies.auth import VerifiedActor, get_verified_actor
from storage.db.models import OrgAuditEvent
from storage.db.session import get_db

router = APIRouter()


class AuditEvent(BaseModel):
    event_id: UUID
    org_id: UUID
    actor: str
    action: str
    created_at: datetime
    metadata: dict[str, object] = Field(default_factory=dict)


class AuditExportRecord(BaseModel):
    export_id: UUID
    org_id: UUID
    status: str
    requested_at: datetime


_SENSITIVE_DETAIL_SUBSTRINGS = ("password", "token", "secret", "key")


def _sanitize_details(value: object) -> object:
    if isinstance(value, dict):
        safe: dict[str, object] = {}
        for k, v in value.items():
            if any(substr in k.lower() for substr in _SENSITIVE_DETAIL_SUBSTRINGS):
                continue
            safe[k] = _sanitize_details(v)
        return safe
    if isinstance(value, list):
        return [_sanitize_details(item) for item in value]
    return value


async def append_audit_event(
    event_type: str,
    actor_email: str,
    org_id: UUID,
    resource_type: str | None,
    resource_id: str | None,
    details: dict | None,
    db: AsyncSession,
) -> OrgAuditEvent:
    event = OrgAuditEvent(
        org_id=org_id,
        event_type=event_type,
        actor_email=actor_email,
        resource_type=resource_type,
        resource_id=resource_id,
        details=_sanitize_details(details) if details else None,  # type: ignore[arg-type]
    )
    db.add(event)
    await db.commit()
    await db.refresh(event)
    return event


@router.get("/orgs/{org_id}/audit", response_model=list[AuditEvent])
async def list_audit_events(
    org_id: UUID,
    actor: VerifiedActor = Depends(get_verified_actor),
    db: AsyncSession = Depends(get_db),
) -> list[AuditEvent]:
    if actor.org_id != org_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")

    result = await db.execute(
        select(OrgAuditEvent).where(OrgAuditEvent.org_id == org_id).order_by(OrgAuditEvent.created_at.desc())
    )
    events = list(result.scalars().all())
    return [
        AuditEvent(
            event_id=event.id,
            org_id=event.org_id,
            actor=event.actor_email or "",
            action=event.event_type,
            created_at=event.created_at,
            metadata=event.details or {},
        )
        for event in events
    ]


@router.post("/orgs/{org_id}/audit/export", response_model=AuditExportRecord, status_code=status.HTTP_202_ACCEPTED)
async def trigger_audit_export(
    org_id: UUID,
    actor: VerifiedActor = Depends(get_verified_actor),
    db: AsyncSession = Depends(get_db),
) -> AuditExportRecord:
    if actor.org_id != org_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")

    export_id = uuid4()
    event = await append_audit_event(
        event_type="export_requested",
        actor_email="system",
        org_id=org_id,
        resource_type="audit_export",
        resource_id=str(export_id),
        details={"export_id": str(export_id), "status": "queued", "requested_at": datetime.now(UTC).isoformat()},
        db=db,
    )
    return AuditExportRecord(export_id=event.id, org_id=org_id, status="queued", requested_at=event.created_at)


@router.get("/orgs/{org_id}/audit/exports/{export_id}", response_model=AuditExportRecord)
async def get_audit_export_status(
    org_id: UUID,
    export_id: UUID,
    actor: VerifiedActor = Depends(get_verified_actor),
    db: AsyncSession = Depends(get_db),
) -> AuditExportRecord:
    if actor.org_id != org_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")

    result = await db.execute(
        select(OrgAuditEvent).where(
            OrgAuditEvent.org_id == org_id,
            OrgAuditEvent.event_type == "export_requested",
            OrgAuditEvent.id == export_id,
        )
    )
    record = result.scalar_one_or_none()
    if record is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="export not found")
    return AuditExportRecord(export_id=record.id, org_id=record.org_id, status="queued", requested_at=record.created_at)


__all__ = ["router"]
