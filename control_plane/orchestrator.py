from __future__ import annotations

import inspect
import os
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Protocol
from urllib.parse import urljoin, urlparse
from uuid import UUID

import httpx
import structlog
from redis import Redis
from redis.exceptions import ConnectionError as RedisConnectionError
from redis.exceptions import TimeoutError as RedisTimeoutError
from rq import Queue
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from sqlalchemy.orm import selectinload

from api.middleware.logging import redact_for_audit
from api.routers.session import validate_session_snapshot
from control_plane.auth_manager import SessionSnapshot, _decrypt_snapshot_field, purge_scan_credentials
from storage.db.models import (
    AssetMap,
    AuditEvent,
    AuditEventType,
    AuthContext,
    Endpoint,
    Scan,
    ScanStatus,
    Target,
)

logger = structlog.get_logger(__name__)

REDACTED_FIELDS = {"authorization", "cookie", "password", "token"}
PREFLIGHT_AUTH_TIMEOUT_SECONDS = 10.0


async def log_audit_event(
    session: AsyncSession,
    scan_id: UUID,
    event_type: AuditEventType,
    actor: str = "system",
    details: dict[str, Any] | None = None,
) -> None:
    sanitized_details = redact_for_audit(details) if isinstance(details, dict) else None
    session.add(
        AuditEvent(
            scan_id=scan_id,
            event_type=event_type,
            actor=actor,
            details=sanitized_details,
        )
    )


class ReportingService(Protocol):
    def export(self, scan_id: UUID) -> Any: ...


class ScanNotFoundError(RuntimeError):
    pass


class ScanAbortReason(StrEnum):
    SESSION_INVALID = "SESSION_INVALID"


class ScanWarning(StrEnum):
    SESSION_DEGRADED = "SESSION_DEGRADED"


@dataclass(slots=True)
class ScanConfig:
    unauth_mode: bool = False
    target_url: str = ""
    auth_context: Any | None = None
    identities: list[Any] | None = None
    scan_id: UUID | None = None


@dataclass(slots=True)
class PreflightResult:
    status: str
    failures: list[str]
    missing_roles: list[str]
    missing_tenants: list[str]
    csrf_status: str


@dataclass(slots=True)
class SessionProbe:
    url: str
    method: str


@dataclass(slots=True)
class SessionValidationContext:
    auth_context: AuthContext | None
    target_url: str


def _preflight_field(model: Any, field_name: str, default: Any = None) -> Any:
    if isinstance(model, dict):
        return model.get(field_name, default)
    return getattr(model, field_name, default)


def _preflight_cookie_header(cookies: Any) -> str:
    if isinstance(cookies, dict):
        return "; ".join(
            f"{name}={value}" for name, value in cookies.items() if str(name).strip() and str(value).strip()
        )
    if not isinstance(cookies, list):
        return ""

    pairs: list[str] = []
    for cookie in cookies:
        if not isinstance(cookie, dict):
            continue
        name = cookie.get("name")
        value = cookie.get("value")
        if isinstance(name, str) and name.strip() and value is not None:
            pairs.append(f"{name}={value}")
    return "; ".join(pairs)


def _preflight_has_material(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, (list, tuple, set)):
        return any(_preflight_has_material(item) for item in value)
    if isinstance(value, dict):
        return any(_preflight_has_material(item) for item in value.values())
    return bool(value)


def _preflight_auth_headers(auth_context: Any) -> dict[str, str]:
    headers: dict[str, str] = {}

    auth_headers = _preflight_field(auth_context, "auth_headers")
    if isinstance(auth_headers, dict):
        headers.update(
            {
                str(key): str(value)
                for key, value in auth_headers.items()
                if str(key).strip() and value is not None
            }
        )

    bearer_token = _preflight_field(auth_context, "bearer_token")
    if isinstance(bearer_token, str) and bearer_token.strip() and "Authorization" not in headers:
        headers["Authorization"] = f"Bearer {bearer_token.strip()}"

    cookie_header = _preflight_cookie_header(_preflight_field(auth_context, "cookies"))
    if cookie_header:
        headers["Cookie"] = cookie_header

    csrf_tokens = _preflight_field(auth_context, "csrf_tokens")
    if isinstance(csrf_tokens, dict):
        headers.update(
            {
                str(key): str(value)
                for key, value in csrf_tokens.items()
                if str(key).strip() and value is not None
            }
        )

    return headers


def _preflight_base_url(target_url: str) -> str:
    parsed = urlparse(target_url)
    if parsed.scheme and parsed.netloc:
        return f"{parsed.scheme}://{parsed.netloc}"
    return target_url


async def preflight_auth_check(scan_config: ScanConfig) -> PreflightResult:
    failures: list[str] = []
    missing_roles: list[str] = []
    missing_tenants: list[str] = []
    csrf_status = "not_required"

    if scan_config.unauth_mode:
        return PreflightResult(
            status="ok",
            failures=[],
            missing_roles=[],
            missing_tenants=[],
            csrf_status=csrf_status,
        )

    auth_context = scan_config.auth_context
    identities = list(scan_config.identities or [])
    if auth_context is None and not identities:
        return PreflightResult(
            status="failed",
            failures=["invalid_session"],
            missing_roles=[],
            missing_tenants=[],
            csrf_status="not_checked",
        )

    for index, identity in enumerate(identities):
        identity_name = str(_preflight_field(identity, "name", f"identity_{index}"))
        if _preflight_field(identity, "auth_state", "active") != "active":
            continue
        if not _preflight_field(identity, "role_hint"):
            missing_roles.append(identity_name)
        if not _preflight_field(identity, "tenant_hint"):
            missing_tenants.append(identity_name)

    if missing_roles:
        failures.append("missing_role")
    if missing_tenants:
        failures.append("missing_tenant")

    probe_context = auth_context or _preflight_field(identities[0], "auth_context", None)
    auth_type = str(_preflight_field(probe_context, "type", "none")).lower() if probe_context is not None else "none"

    if auth_type == "none":
        failures.append("invalid_session")

    if auth_type == "session":
        cookies = _preflight_field(probe_context, "cookies")
        csrf_tokens = _preflight_field(probe_context, "csrf_tokens")
        cookie_csrf = False
        if isinstance(cookies, list):
            cookie_csrf = any(
                isinstance(cookie, dict) and "csrf" in str(cookie.get("name", "")).lower() for cookie in cookies
            )
        elif isinstance(cookies, dict):
            cookie_csrf = any("csrf" in str(name).lower() for name in cookies)

        if _preflight_has_material(csrf_tokens) or cookie_csrf:
            csrf_status = "ok"
        else:
            csrf_status = "missing"
            failures.append("csrf_failed")
    elif auth_type == "credential":
        if not (
            _preflight_has_material(_preflight_field(probe_context, "credentials"))
            or _preflight_has_material(_preflight_field(probe_context, "login_recipe"))
        ):
            failures.append("invalid_session")
        return PreflightResult(
            status="degraded" if not failures else "failed",
            failures=failures,
            missing_roles=missing_roles,
            missing_tenants=missing_tenants,
            csrf_status="deferred",
        )

    headers = _preflight_auth_headers(probe_context)
    if not headers:
        failures.append("invalid_session")
    elif scan_config.target_url.strip():
        try:
            async with httpx.AsyncClient(
                timeout=PREFLIGHT_AUTH_TIMEOUT_SECONDS,
                follow_redirects=True,
                max_redirects=5,
            ) as client:
                response = await client.head(_preflight_base_url(scan_config.target_url), headers=headers)
                if response.status_code == 405:
                    response = await client.get(_preflight_base_url(scan_config.target_url), headers=headers)
        except httpx.HTTPError:
            failures.append("invalid_session")
        else:
            if response.status_code in {401, 403}:
                failures.append("invalid_session")
    else:
        failures.append("invalid_session")

    deduped_failures = list(dict.fromkeys(failures))
    status = "failed" if deduped_failures else "ok"
    return PreflightResult(
        status=status,
        failures=deduped_failures,
        missing_roles=missing_roles,
        missing_tenants=missing_tenants,
        csrf_status=csrf_status,
    )


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
        self._redis = connection
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

    def is_transient_rq_failure(self, error: BaseException) -> bool:
        return isinstance(error, (RedisConnectionError, RedisTimeoutError))

    def handle_rq_job_failure(
        self,
        *,
        queue: Queue,
        job_callable: str,
        job_id: str,
        args: tuple[object, ...],
        error: BaseException,
    ) -> bool:
        if not self.is_transient_rq_failure(error):
            return False
        retry_key = f"retry:{job_id}"
        retry_count = int(self._redis.incr(retry_key))
        if retry_count == 1:
            self._redis.expire(retry_key, 86400)
            queue.enqueue(job_callable, *args)
            return True
        return False

    def append_finding_evidence(self, *, scan_id: UUID, finding_id: str, payload: dict[str, Any]) -> bool:
        finding_key = f"finding:{finding_id}"
        if not self._redis.setnx(finding_key, "1"):
            return False
        self._redis.expire(finding_key, 86400)
        stream_key = f"evidence:{scan_id}"
        self._redis.xadd(stream_key, payload)
        return True

    async def on_scan_created(self, scan_id: UUID) -> None:
        await self._update_scan(scan_id, status=ScanStatus.running, phase="recon", started_at=datetime.now(UTC))
        async with self._session_factory() as session:
            await log_audit_event(
                session,
                scan_id=scan_id,
                event_type=AuditEventType.SCAN_CREATED,
                actor="system",
                details={"phase": "created"},
            )
            await log_audit_event(
                session,
                scan_id=scan_id,
                event_type=AuditEventType.SCAN_STARTED,
                actor="system",
                details={"phase": "recon"},
            )
            await session.commit()
        scan_config, has_session_or_cookies, has_spec_asset_map, spec_asset_map = await self._resolve_scan_runtime(
            scan_id
        )
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
        if not await self._validate_session_before_attack(scan_id, asset_map):
            return
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

    async def _validate_session_before_attack(self, scan_id: UUID, asset_map: dict[str, Any]) -> bool:
        context = await self._load_session_validation_context(scan_id)
        auth_context = context.auth_context
        if auth_context is None or auth_context.type == "none":
            return True

        probe = self._select_session_probe(asset_map=asset_map, target_url=context.target_url)
        if probe is None:
            await self._abort_scan_for_invalid_session(
                scan_id,
                reason="no_auth_required_endpoint_for_session_validation",
            )
            return False

        try:
            snapshot = self._session_snapshot_from_auth_context(auth_context, scan_id)
            result = await validate_session_snapshot(
                snapshot,
                probe.url,
                method=probe.method,
                validate_public_url=False,
            )
        except Exception as exc:
            await self._abort_scan_for_invalid_session(
                scan_id,
                reason=f"session_validation_error:{type(exc).__name__}",
            )
            return False

        if result.valid:
            await self._record_session_validation(scan_id, valid=True, reason=result.reason)
            logger.info("session_validation_passed", scan_id=str(scan_id), phase="recon")
            return True

        await self._abort_scan_for_invalid_session(scan_id, reason=result.reason)
        return False

    async def _load_session_validation_context(self, scan_id: UUID) -> SessionValidationContext:
        async with self._session_factory() as session:
            result = await session.execute(
                select(Scan)
                .where(Scan.id == scan_id)
                .options(
                    selectinload(Scan.target),
                    selectinload(Scan.auth_context),
                )
            )
            scan = result.scalar_one_or_none()
            if scan is None:
                raise ScanNotFoundError(f"Scan not found: {scan_id}")

            target_url = scan.target.url if isinstance(scan.target, Target) else ""
            return SessionValidationContext(auth_context=scan.auth_context, target_url=target_url)

    def _select_session_probe(self, *, asset_map: dict[str, Any], target_url: str) -> SessionProbe | None:
        endpoints = asset_map.get("endpoints")
        if not isinstance(endpoints, list):
            return None

        auth_required_endpoints = [
            endpoint for endpoint in endpoints if isinstance(endpoint, dict) and endpoint.get("auth_required") is True
        ]
        if not auth_required_endpoints:
            return None

        safe_methods = {"GET", "HEAD", "OPTIONS"}
        for endpoint in auth_required_endpoints:
            method = str(endpoint.get("method") or "GET").upper()
            if method in safe_methods:
                url = self._absolute_probe_url(target_url, endpoint.get("url_pattern"))
                if url:
                    return SessionProbe(url=url, method=method)

        first_endpoint = auth_required_endpoints[0]
        url = self._absolute_probe_url(target_url, first_endpoint.get("url_pattern"))
        if not url:
            return None
        return SessionProbe(url=url, method="HEAD")

    def _absolute_probe_url(self, target_url: str, raw_url: object) -> str | None:
        if not isinstance(raw_url, str) or not raw_url.strip():
            return None
        if raw_url.startswith(("http://", "https://")):
            return raw_url
        if not target_url:
            return None
        return urljoin(target_url.rstrip("/") + "/", raw_url)

    def _session_snapshot_from_auth_context(self, auth_context: AuthContext, scan_id: UUID) -> SessionSnapshot:
        snapshot_payload = auth_context.session_snapshot if isinstance(auth_context.session_snapshot, dict) else {}
        raw_cookies = _decrypt_snapshot_field(snapshot_payload.get("cookies"), scan_id)
        raw_auth_headers = _decrypt_snapshot_field(snapshot_payload.get("auth_headers"), scan_id)
        raw_csrf_tokens = _decrypt_snapshot_field(snapshot_payload.get("csrf_tokens"), scan_id)
        raw_bearer_token = _decrypt_snapshot_field(snapshot_payload.get("bearer_token"), scan_id)

        cookies: list[dict[str, Any]] | dict[str, str]
        if isinstance(raw_cookies, list):
            cookies = [cookie for cookie in raw_cookies if isinstance(cookie, dict)]
        elif isinstance(raw_cookies, dict):
            cookies = {str(key): str(value) for key, value in raw_cookies.items()}
        else:
            cookies = []

        auth_headers = (
            {str(key): str(value) for key, value in raw_auth_headers.items()}
            if isinstance(raw_auth_headers, dict)
            else {}
        )
        if not auth_headers and isinstance(raw_bearer_token, str) and raw_bearer_token:
            auth_headers["Authorization"] = f"Bearer {raw_bearer_token}"

        csrf_tokens = (
            {str(key): str(value) for key, value in raw_csrf_tokens.items()}
            if isinstance(raw_csrf_tokens, dict)
            else {}
        )
        return SessionSnapshot(scan_id=scan_id, cookies=cookies, auth_headers=auth_headers, csrf_tokens=csrf_tokens)

    async def _record_session_validation(self, scan_id: UUID, *, valid: bool, reason: str) -> None:
        safe_reason = self._redact_sensitive_text(reason)
        async with self._session_factory() as session:
            result = await session.execute(select(AuthContext).where(AuthContext.scan_id == scan_id))
            auth_context = result.scalar_one_or_none()
            if auth_context is None:
                return

            health = auth_context.health if isinstance(auth_context.health, dict) else {}
            auth_context.health = {
                **health,
                "session_validation": {
                    "valid": valid,
                    "reason": safe_reason,
                    "updated_at": datetime.now(UTC).isoformat(),
                },
            }
            await session.commit()

    async def _abort_scan_for_invalid_session(self, scan_id: UUID, *, reason: str) -> None:
        safe_reason = self._redact_sensitive_text(reason)
        async with self._session_factory() as session:
            result = await session.execute(
                select(Scan)
                .where(Scan.id == scan_id)
                .options(selectinload(Scan.auth_context))
            )
            scan = result.scalar_one_or_none()
            if scan is None:
                raise ScanNotFoundError(f"Scan not found: {scan_id}")

            scan.status = ScanStatus.failed
            scan.phase = f"failed:{ScanAbortReason.SESSION_INVALID.value}"
            scan.completed_at = datetime.now(UTC)
            if isinstance(scan.auth_context, AuthContext):
                health = scan.auth_context.health if isinstance(scan.auth_context.health, dict) else {}
                scan.auth_context.health = {
                    **health,
                    "session_validation": {
                        "valid": False,
                        "reason": safe_reason,
                        "abort_reason": ScanAbortReason.SESSION_INVALID.value,
                        "updated_at": datetime.now(UTC).isoformat(),
                    },
                }
            await log_audit_event(
                session,
                scan_id=scan_id,
                event_type=AuditEventType.AUTH_FAILED,
                actor="system",
                details={
                    "abort_reason": ScanAbortReason.SESSION_INVALID.value,
                    "reason": safe_reason,
                },
            )
            await session.commit()

        logger.error(
            "scan_aborted_session_invalid",
            scan_id=str(scan_id),
            abort_reason=ScanAbortReason.SESSION_INVALID.value,
            reason=safe_reason,
        )

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
