from __future__ import annotations

import os
import json
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlparse
from uuid import UUID

import structlog
from fastapi import APIRouter, Depends, HTTPException, status
from redis import Redis
from rq import Queue
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from api.models.requests import ScanCreate
from api.models.responses import ScanEventResponse, ScanResponse
from storage.db.encryption import EnvelopeEncryption
from storage.db.models import AssetMap, AttackTask, AuthContext, Endpoint, Finding, Scan, ScanStatus, Target
from storage.db.session import get_db

logger = structlog.get_logger()
router = APIRouter()


def _encrypt_snapshot_field(value: Any, scan_id: UUID) -> dict[str, str] | None:
    if value is None:
        return None
    encryption = EnvelopeEncryption()
    plaintext = value if isinstance(value, str) else json.dumps(value, separators=(",", ":"))
    blob = encryption.encrypt_credential(plaintext, scan_id)
    return {
        "_encrypted": "kms_envelope_v1",
        "encrypted_data_key": blob.encrypted_data_key,
        "ciphertext": blob.ciphertext,
    }


def _build_session_snapshot(payload: ScanCreate, scan_id: UUID) -> dict[str, Any]:
    return {
        "credentials": _encrypt_snapshot_field(payload.auth_context.credentials, scan_id),
        "cookies": _encrypt_snapshot_field(payload.auth_context.cookies, scan_id),
        "bearer_token": _encrypt_snapshot_field(payload.auth_context.bearer_token, scan_id),
        "login_recipe": payload.auth_context.login_recipe,
    }


def _to_scan_response(scan: Scan) -> ScanResponse:
    return ScanResponse(
        id=str(scan.id),
        status=scan.status.value if isinstance(scan.status, ScanStatus) else str(scan.status),
        phase=scan.phase or "",
        created_at=scan.created_at,
    )


def _status_value(value: Any) -> str:
    if hasattr(value, "value"):
        return str(value.value)
    return str(value)


def _count_result_value(result: Any) -> int:
    if hasattr(result, "scalar_one"):
        value = result.scalar_one()
    else:
        value = result.scalar_one_or_none()
    return value if isinstance(value, int) else 0


def _all_result_rows(result: Any) -> list[Any]:
    if not hasattr(result, "all"):
        return []
    return list(result.all())


def _append_scan_event(
    events: list[ScanEventResponse],
    *,
    timestamp: datetime,
    level: str,
    source: str,
    message: str,
    details: dict[str, object] | None = None,
) -> None:
    events.append(
        ScanEventResponse(
            timestamp=timestamp,
            level=level,
            source=source,
            message=message,
            details=details or {},
        )
    )


async def _build_scan_debug_details(db: AsyncSession, scan_id: UUID, scan: Scan) -> dict[str, object]:
    auth_result = await db.execute(select(AuthContext.id).where(AuthContext.scan_id == scan_id))
    auth_context_id = auth_result.scalar_one_or_none()

    endpoint_count_result = await db.execute(
        select(func.count(Endpoint.id))
        .select_from(AssetMap)
        .join(Endpoint, Endpoint.asset_map_id == AssetMap.id)
        .where(AssetMap.scan_id == scan_id)
    )
    endpoint_count = _count_result_value(endpoint_count_result)

    task_status_result = await db.execute(
        select(AttackTask.status, func.count(AttackTask.id))
        .where(AttackTask.scan_id == scan_id)
        .group_by(AttackTask.status)
    )
    task_status_counts = {_status_value(row[0]): int(row[1]) for row in _all_result_rows(task_status_result)}

    finding_count_result = await db.execute(select(func.count(Finding.id)).where(Finding.scan_id == scan_id))
    finding_count = _count_result_value(finding_count_result)

    return {
        "scan_id": str(scan.id),
        "status": _status_value(scan.status).lower(),
        "phase": scan.phase or "",
        "auth_context_ready": auth_context_id is not None,
        "endpoint_count": endpoint_count,
        "task_count": sum(task_status_counts.values()),
        "tasks_by_status": task_status_counts,
        "finding_count": finding_count,
    }


def _get_auth_bootstrap_queue() -> Queue:
    redis_url = os.getenv("REDIS_URL")
    if not redis_url:
        raise RuntimeError("REDIS_URL is not configured")
    connection = Redis.from_url(redis_url)
    queue_name = os.getenv("RQ_AUTH_QUEUE", "auth_bootstrap")
    return Queue(name=queue_name, connection=connection)


@router.post("", response_model=ScanResponse, status_code=status.HTTP_201_CREATED)
async def create_scan(payload: ScanCreate, db: AsyncSession = Depends(get_db)) -> ScanResponse:
    domains = payload.allowed_domains if payload.allowed_domains else [urlparse(payload.target_url).hostname or payload.target_url]
    target = Target(
        url=payload.target_url,
        name=payload.target_url,
        config={"allowed_domains": domains, "unauth_mode": payload.unauth_mode},
    )
    db.add(target)
    await db.flush()

    scan = Scan(target_id=target.id, status=ScanStatus.created, phase="created")
    db.add(scan)
    await db.flush()

    auth_context: AuthContext | None = None
    if payload.auth_context is not None:
        auth_context = AuthContext(
            scan_id=scan.id,
            type=payload.auth_context.type,
            session_snapshot=_build_session_snapshot(payload, scan.id),
            health={},
        )
        db.add(auth_context)
    elif not payload.unauth_mode:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="auth_context is required when unauth_mode is False",
        )

    scan.status = ScanStatus.running
    scan.phase = "auth_bootstrap"
    scan.started_at = datetime.now(UTC)
    await db.commit()
    await db.refresh(scan)

    try:
        if auth_context is not None:
            queue = _get_auth_bootstrap_queue()
            queue.enqueue("control_plane.auth_manager.bootstrap_auth_context", str(scan.id), str(auth_context.id))
            logger.info(
                "scan_auth_bootstrap_enqueued",
                scan_id=str(scan.id),
                phase=scan.phase,
                status=_status_value(scan.status),
                queue=getattr(queue, "name", "auth_bootstrap"),
            )
    except Exception as exc:
        logger.exception("auth_bootstrap_enqueue_failed", scan_id=str(scan.id), error=str(exc))

    return _to_scan_response(scan)


@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan(scan_id: UUID, db: AsyncSession = Depends(get_db)) -> ScanResponse:
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    debug_details = await _build_scan_debug_details(db=db, scan_id=scan_id, scan=scan)
    logger.info("scan_status_polled", **debug_details)
    return _to_scan_response(scan)


@router.get("/{scan_id}/events", response_model=list[ScanEventResponse])
async def get_scan_events(scan_id: UUID, db: AsyncSession = Depends(get_db)) -> list[ScanEventResponse]:
    scan_result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = scan_result.scalar_one_or_none()
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")

    debug_details = await _build_scan_debug_details(db=db, scan_id=scan_id, scan=scan)
    events: list[ScanEventResponse] = []
    _append_scan_event(
        events,
        timestamp=scan.created_at,
        level="info",
        source="api",
        message="Scan record created",
        details={"scan_id": str(scan.id), "target_id": str(scan.target_id)},
    )

    if scan.started_at is not None:
        _append_scan_event(
            events,
            timestamp=scan.started_at,
            level="info",
            source="orchestrator",
            message="Scan started",
            details={"status": _status_value(scan.status), "phase": scan.phase or ""},
        )

    auth_result = await db.execute(select(AuthContext).where(AuthContext.scan_id == scan_id))
    auth_context = auth_result.scalar_one_or_none()
    if auth_context is None:
        _append_scan_event(
            events,
            timestamp=scan.created_at,
            level="warn",
            source="auth",
            message="Waiting for auth context",
            details={},
        )
    else:
        health = auth_context.health if isinstance(auth_context.health, dict) else {}
        _append_scan_event(
            events,
            timestamp=scan.started_at or scan.created_at,
            level="info",
            source="auth",
            message="Auth context stored",
            details={"auth_type": auth_context.type, "health_keys": sorted(str(key) for key in health)},
        )

    endpoint_count_result = await db.execute(
        select(func.count(Endpoint.id))
        .select_from(AssetMap)
        .join(Endpoint, Endpoint.asset_map_id == AssetMap.id)
        .where(AssetMap.scan_id == scan_id)
    )
    endpoint_count = _count_result_value(endpoint_count_result)
    if endpoint_count > 0:
        _append_scan_event(
            events,
            timestamp=scan.started_at or scan.created_at,
            level="info",
            source="crawler",
            message="Asset map persisted",
            details={"endpoint_count": endpoint_count},
        )
    elif (scan.phase or "").lower() in {"crawl", "plan", "attack", "validate", "score", "report", "reporting", "complete"}:
        _append_scan_event(
            events,
            timestamp=scan.started_at or scan.created_at,
            level="warn",
            source="crawler",
            message="No endpoints persisted yet",
            details={},
        )

    task_status_result = await db.execute(
        select(AttackTask.status, func.count(AttackTask.id))
        .where(AttackTask.scan_id == scan_id)
        .group_by(AttackTask.status)
    )
    task_status_counts = {_status_value(row[0]): int(row[1]) for row in _all_result_rows(task_status_result)}
    if task_status_counts:
        _append_scan_event(
            events,
            timestamp=scan.started_at or scan.created_at,
            level="info",
            source="planner",
            message="Attack tasks persisted",
            details={"tasks_by_status": task_status_counts, "task_count": sum(task_status_counts.values())},
        )

    task_class_result = await db.execute(
        select(AttackTask.attack_class, func.count(AttackTask.id))
        .where(AttackTask.scan_id == scan_id)
        .group_by(AttackTask.attack_class)
        .order_by(AttackTask.attack_class)
    )
    task_class_counts = {str(row[0]): int(row[1]) for row in _all_result_rows(task_class_result)}
    if task_class_counts:
        _append_scan_event(
            events,
            timestamp=scan.started_at or scan.created_at,
            level="info",
            source="planner",
            message="Attack classes selected",
            details={"tasks_by_attack_class": task_class_counts},
        )

    finding_count_result = await db.execute(select(func.count(Finding.id)).where(Finding.scan_id == scan_id))
    finding_count = _count_result_value(finding_count_result)
    if finding_count > 0:
        _append_scan_event(
            events,
            timestamp=scan.completed_at or scan.started_at or scan.created_at,
            level="info",
            source="scorer",
            message="Findings recorded",
            details={"finding_count": finding_count},
        )

    normalized_status = _status_value(scan.status).lower()
    current_level = "error" if normalized_status == "failed" else "warn" if normalized_status == "paused" else "info"
    _append_scan_event(
        events,
        timestamp=scan.completed_at or scan.started_at or scan.created_at,
        level=current_level,
        source="scan",
        message="Current scan state",
        details={"status": normalized_status, "phase": scan.phase or ""},
    )

    sorted_events = sorted(events, key=lambda event: event.timestamp)
    logger.info("scan_events_polled", **debug_details, event_count=len(sorted_events))
    return sorted_events


@router.patch("/{scan_id}/pause", response_model=ScanResponse)
async def pause_scan(scan_id: UUID, db: AsyncSession = Depends(get_db)) -> ScanResponse:
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")

    scan.status = ScanStatus.paused
    scan.phase = "paused"
    await db.commit()
    await db.refresh(scan)

    logger.warning("scan_pause_requested_from_api", scan_id=str(scan.id), phase=scan.phase, status=_status_value(scan.status))

    return _to_scan_response(scan)
