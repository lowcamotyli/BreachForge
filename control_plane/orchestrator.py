from __future__ import annotations

import inspect
import os
from datetime import UTC, datetime
from dataclasses import dataclass
from typing import Any, Protocol
from uuid import UUID

import structlog
from redis import Redis
from rq import Queue
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from sqlalchemy.orm import selectinload

from control_plane.auth_manager import purge_scan_credentials
from storage.db.models import AssetMap, AuthContext, Endpoint, Scan, ScanStatus, Target

logger = structlog.get_logger(__name__)

REDACTED_FIELDS = {"authorization", "cookie", "password", "token"}


class ReportingService(Protocol):
    def export(self, scan_id: UUID) -> Any: ...


class ScanNotFoundError(RuntimeError):
    pass


@dataclass(slots=True)
class ScanConfig:
    unauth_mode: bool = False


class ScanOrchestrator:
    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        reporting_service: ReportingService,
    ) -> None:
        self._session_factory = session_factory
        self._reporting_service = reporting_service

        redis_url = os.getenv("REDIS_URL")
        if not redis_url:
            raise RuntimeError("REDIS_URL is not configured")

        connection = Redis.from_url(redis_url)
        self._auth_queue = Queue(name=os.getenv("RQ_AUTH_QUEUE", "auth_bootstrap"), connection=connection)
        self._attack_queue = Queue(
            name=os.getenv("RQ_ATTACK_QUEUE", "attack_planning"),
            connection=connection,
        )
        self._recon_queue = Queue(
            name=os.getenv("RQ_RECON_QUEUE", "recon"),
            connection=connection,
        )

        self._auth_bootstrap_job = os.getenv(
            "RQ_AUTH_BOOTSTRAP_JOB",
            "control_plane.auth_manager.bootstrap_auth_context",
        )
        self._recon_job = os.getenv(
            "RQ_RECON_JOB",
            "execution_plane.crawler.engine.run_crawler",
        )
        self._attack_planning_job = os.getenv(
            "RQ_ATTACK_PLANNING_JOB",
            "execution_plane.planner.planner.plan_attack",
        )

    async def on_scan_created(self, scan_id: UUID) -> None:
        await self._update_scan(scan_id, status=ScanStatus.running, phase="recon", started_at=datetime.now(UTC))
        scan_config, has_session_or_cookies, has_spec_asset_map, spec_asset_map = await self._resolve_scan_runtime(scan_id)
        if scan_config.unauth_mode:
            logger.info("unauth_mode active — skipping auth_bootstrap", scan_id=str(scan_id), phase="recon")
            if not has_session_or_cookies and has_spec_asset_map and spec_asset_map is not None:
                logger.info(
                    "unauth_mode: using spec AssetMap, skipping Playwright crawl",
                    scan_id=str(scan_id),
                    phase="recon",
                )
                await self.on_recon_complete(scan_id, spec_asset_map)
                return
            self._recon_queue.enqueue(self._recon_job, str(scan_id))
            logger.info("scan_created_enqueued_recon", scan_id=str(scan_id), phase="recon")
            return
        self._auth_queue.enqueue(self._auth_bootstrap_job, str(scan_id))
        logger.info("scan_created_enqueued_auth_bootstrap", scan_id=str(scan_id), phase="recon")

    async def on_recon_complete(self, scan_id: UUID, asset_map: dict[str, Any]) -> None:
        await self._update_scan(scan_id, status=ScanStatus.running, phase="attack")
        self._attack_queue.enqueue(self._attack_planning_job, str(scan_id), asset_map)
        logger.info("scan_recon_complete_enqueued_attack_planning", scan_id=str(scan_id), phase="attack")

    async def on_attack_complete(self, scan_id: UUID) -> None:
        await self._update_scan(scan_id, status=ScanStatus.running, phase="validate")
        logger.info("scan_attack_complete_transitioned", scan_id=str(scan_id), phase="validate")

    async def on_all_validated(self, scan_id: UUID) -> None:
        await self._update_scan(scan_id, status=ScanStatus.running, phase="reporting")
        export_result = self._reporting_service.export(scan_id)
        if inspect.isawaitable(export_result):
            await export_result

        await self._update_scan(scan_id, status=ScanStatus.complete, phase="complete", completed_at=datetime.now(UTC))
        await purge_scan_credentials(scan_id)
        logger.info("scan_reporting_complete", scan_id=str(scan_id), phase="complete")

    async def pause_scan(self, scan_id: UUID, reason: str) -> None:
        safe_reason = self._redact_sensitive_text(reason)
        await self._update_scan(scan_id, status=ScanStatus.paused, phase=f"paused:{safe_reason[:57]}")
        logger.warning("scan_paused", scan_id=str(scan_id), reason=safe_reason)

    async def on_scan_failed(self, scan_id: UUID, reason: str) -> None:
        safe_reason = self._redact_sensitive_text(reason)
        await self._update_scan(scan_id, status=ScanStatus.failed, phase=f"failed:{safe_reason[:57]}")
        logger.error("scan_failed", scan_id=str(scan_id), reason=safe_reason)

    async def _update_scan(
        self,
        scan_id: UUID,
        *,
        status: ScanStatus,
        phase: str,
        started_at: datetime | None = None,
        completed_at: datetime | None = None,
    ) -> None:
        async with self._session_factory() as session:
            result = await session.execute(select(Scan).where(Scan.id == scan_id))
            scan = result.scalar_one_or_none()
            if scan is None:
                raise ScanNotFoundError(f"Scan not found: {scan_id}")

            scan.status = status
            scan.phase = phase
            if started_at is not None:
                scan.started_at = started_at
            if completed_at is not None:
                scan.completed_at = completed_at

            await session.commit()

    def _redact_sensitive_text(self, value: str) -> str:
        lowered = value.lower()
        if any(secret in lowered for secret in REDACTED_FIELDS):
            return "[REDACTED]"
        return value

    async def _resolve_scan_runtime(self, scan_id: UUID) -> tuple[ScanConfig, bool, bool, dict[str, Any] | None]:
        async with self._session_factory() as session:
            result = await session.execute(
                select(Scan)
                .where(Scan.id == scan_id)
                .options(
                    selectinload(Scan.target),
                    selectinload(Scan.auth_context),
                    selectinload(Scan.asset_map).selectinload(AssetMap.endpoints),
                )
            )
            scan = result.scalar_one_or_none()
            if scan is None:
                raise ScanNotFoundError(f"Scan not found: {scan_id}")

            target = scan.target
            target_config = target.config if isinstance(target, Target) and isinstance(target.config, dict) else {}
            scan_config = self._parse_scan_config(target_config)
            has_session_or_cookies = self._scan_has_session_or_cookies(scan.auth_context)
            spec_asset_map = self._spec_asset_map_from_scan(scan, target_config)
            has_spec_asset_map = spec_asset_map is not None and bool(spec_asset_map.get("endpoints"))
            return scan_config, has_session_or_cookies, has_spec_asset_map, spec_asset_map

    def _parse_scan_config(self, target_config: dict[str, Any]) -> ScanConfig:
        unauth_mode = bool(target_config.get("unauth_mode", False))
        return ScanConfig(unauth_mode=unauth_mode)

    def _scan_has_session_or_cookies(self, auth_context: AuthContext | None) -> bool:
        if not isinstance(auth_context, AuthContext):
            return False
        snapshot = auth_context.session_snapshot if isinstance(auth_context.session_snapshot, dict) else {}
        for key in ("cookies", "session", "session_snapshot", "bearer_token", "token"):
            if snapshot.get(key):
                return True
        return False

    def _spec_asset_map_from_scan(self, scan: Scan, target_config: dict[str, Any]) -> dict[str, Any] | None:
        asset_map_record = scan.asset_map
        if isinstance(asset_map_record, AssetMap):
            endpoints = []
            for endpoint in asset_map_record.endpoints:
                if not isinstance(endpoint, Endpoint):
                    continue
                endpoints.append(
                    {
                        "url_pattern": endpoint.url_pattern,
                        "method": endpoint.method,
                        "auth_required": endpoint.auth_required,
                        "parameters": endpoint.parameters,
                        "observed_content_type": endpoint.observed_content_type,
                        "example_response_code": endpoint.example_response_code,
                    }
                )
            if endpoints:
                target_url = scan.target.url if isinstance(scan.target, Target) else ""
                return {"target_url": target_url, "endpoints": endpoints}

        candidate_map = target_config.get("asset_map")
        if isinstance(candidate_map, dict):
            endpoints = candidate_map.get("endpoints")
            if isinstance(endpoints, list) and endpoints:
                return candidate_map

        candidate_spec_map = target_config.get("spec_asset_map")
        if isinstance(candidate_spec_map, dict):
            endpoints = candidate_spec_map.get("endpoints")
            if isinstance(endpoints, list) and endpoints:
                return candidate_spec_map

        if any(target_config.get(key) for key in ("har", "har_data", "openapi", "openapi_spec", "swagger")):
            fallback_target_url = scan.target.url if isinstance(scan.target, Target) else ""
            return {"target_url": fallback_target_url, "endpoints": []}
        return None
