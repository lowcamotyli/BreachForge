from __future__ import annotations

import os
import json
from dataclasses import asdict
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlparse
from uuid import UUID

import httpx
import structlog
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from redis import Redis
from rq import Queue
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from api.models.requests import AuthContextCreate, IdentityReference, ScanCreate, ScanPolicyV2
from api.models.responses import (
    AuthReadinessResponse,
    PolicyPreflightResponse,
    ScanEventResponse,
    ScanReadinessCheck,
    ScanReadinessResponse,
    ScanResponse,
)
from execution_plane.policy.preflight import PolicyPreflight
from execution_plane.policy.kill_switch import KillSwitch, KillSwitchLevel
from storage.db.encryption import EnvelopeEncryption
from storage.db.models import (
    AssetMap,
    AttackTask,
    AuditEvent,
    AuditEventType,
    AuthContext,
    Endpoint,
    Finding,
    Scan,
    ScanStatus,
    Target,
)
from storage.db.session import get_db
from control_plane.orchestrator import ScanConfig, preflight_auth_check

logger = structlog.get_logger()
router = APIRouter()
REDIS_URL = "REDIS_URL"
TARGET_PROBE_TIMEOUT_SECONDS = 10.0
SESSION_PROBE_TIMEOUT_SECONDS = 15.0


class PreflightRequest(BaseModel):
    policy: ScanPolicyV2
    endpoints: list[dict]


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
    auth_context = payload.auth_context
    identities_payload: list[dict[str, Any]] = []
    if getattr(payload, "identities", None):
        for identity in payload.identities:
            if isinstance(identity, IdentityReference):
                identities_payload.append(identity.model_dump(mode="json"))
    return {
        "credentials": _encrypt_snapshot_field(auth_context.credentials, scan_id) if auth_context is not None else None,
        "cookies": _encrypt_snapshot_field(auth_context.cookies, scan_id) if auth_context is not None else None,
        "bearer_token": _encrypt_snapshot_field(auth_context.bearer_token, scan_id) if auth_context is not None else None,
        "login_recipe": auth_context.login_recipe if auth_context is not None else None,
        "identities": identities_payload,
    }


def _to_scan_response(scan: Scan, warnings: list[dict[str, object]] | None = None) -> ScanResponse:
    return ScanResponse(
        id=str(scan.id),
        status=scan.status.value if isinstance(scan.status, ScanStatus) else str(scan.status),
        phase=scan.phase or "",
        created_at=scan.created_at,
        warnings=warnings or [],
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


def _target_base_url(target_url: str) -> str:
    parsed = urlparse(target_url)
    if parsed.scheme and parsed.netloc:
        return f"{parsed.scheme}://{parsed.netloc}"
    return target_url


def _coerce_seed_urls(value: Any) -> list[str]:
    if isinstance(value, str):
        stripped = value.strip()
        return [stripped] if stripped else []
    if not isinstance(value, list):
        return []
    return [item.strip() for item in value if isinstance(item, str) and item.strip()]


def _configured_seed_urls(config: dict[str, Any]) -> tuple[bool, list[str]]:
    candidate_containers: list[dict[str, Any]] = [config]
    crawler_config = config.get("crawler")
    if isinstance(crawler_config, dict):
        candidate_containers.append(crawler_config)

    for container in candidate_containers:
        for key in ("seed_urls", "seed_url", "seeds", "start_urls"):
            if key in container:
                return True, _coerce_seed_urls(container.get(key))

    return False, []


def _discovery_seed_urls(target: Target | None) -> list[str]:
    if target is None:
        return []

    config = target.config if isinstance(target.config, dict) else {}
    has_explicit_seed_config, seed_urls = _configured_seed_urls(config)
    if has_explicit_seed_config:
        return seed_urls

    target_url = target.url.strip() if isinstance(target.url, str) else ""
    return [target_url] if target_url else []


def _scan_requires_auth(target: Target | None) -> bool:
    config = target.config if target is not None and isinstance(target.config, dict) else {}
    return not bool(config.get("unauth_mode"))


def _snapshot_has_material(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, list):
        return len(value) > 0
    if isinstance(value, dict):
        if value.get("_encrypted") == "kms_envelope_v1":
            return bool(value.get("ciphertext"))
        return any(_snapshot_has_material(item) for item in value.values())
    return bool(value)


def _auth_context_has_config(auth_context: AuthContext | None) -> bool:
    if auth_context is None:
        return False

    snapshot = auth_context.session_snapshot if isinstance(auth_context.session_snapshot, dict) else {}
    raw_identities = snapshot.get("identities")
    if isinstance(raw_identities, list) and raw_identities:
        return True

    if str(auth_context.type).lower() == "none":
        return False

    return any(
        _snapshot_has_material(snapshot.get(key))
        for key in (
            "credentials",
            "cookies",
            "bearer_token",
            "login_recipe",
            "auth_headers",
            "csrf_tokens",
        )
    )


def _decrypt_readiness_snapshot_value(value: Any, scan_id: UUID, field_name: str) -> Any:
    if not (isinstance(value, dict) and value.get("_encrypted") == "kms_envelope_v1"):
        return value

    try:
        from control_plane.auth_manager import _decrypt_snapshot_field

        return _decrypt_snapshot_field(value, scan_id)
    except Exception as exc:
        raise ValueError(f"Unable to decrypt session snapshot field '{field_name}'") from exc


def _cookie_header_from_snapshot(cookies: Any) -> str:
    if isinstance(cookies, dict):
        pairs = [f"{name}={value}" for name, value in cookies.items() if str(name).strip() and str(value).strip()]
        return "; ".join(pairs)

    if isinstance(cookies, list):
        pairs = []
        for cookie in cookies:
            if not isinstance(cookie, dict):
                continue
            name = cookie.get("name")
            value = cookie.get("value")
            if isinstance(name, str) and name.strip() and value is not None:
                pairs.append(f"{name}={value}")
        return "; ".join(pairs)

    return ""


def _string_header_dict(value: Any) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}
    return {
        str(key): str(header_value)
        for key, header_value in value.items()
        if str(key).strip() and header_value is not None
    }


def _build_session_probe_headers(auth_context: AuthContext, scan_id: UUID) -> dict[str, str]:
    snapshot = auth_context.session_snapshot if isinstance(auth_context.session_snapshot, dict) else {}
    headers: dict[str, str] = {}

    auth_headers = _decrypt_readiness_snapshot_value(snapshot.get("auth_headers"), scan_id, "auth_headers")
    headers.update(_string_header_dict(auth_headers))

    bearer_token = _decrypt_readiness_snapshot_value(snapshot.get("bearer_token"), scan_id, "bearer_token")
    if isinstance(bearer_token, str) and bearer_token.strip() and "Authorization" not in headers:
        headers["Authorization"] = f"Bearer {bearer_token.strip()}"

    cookies = _decrypt_readiness_snapshot_value(snapshot.get("cookies"), scan_id, "cookies")
    cookie_header = _cookie_header_from_snapshot(cookies)
    if cookie_header:
        headers["Cookie"] = cookie_header

    csrf_tokens = _decrypt_readiness_snapshot_value(snapshot.get("csrf_tokens"), scan_id, "csrf_tokens")
    headers.update(_string_header_dict(csrf_tokens))

    return headers


def _redact_readiness_value(value: Any) -> Any:
    if value is None:
        return None
    if isinstance(value, str):
        return f"{value[:4]}***"
    if isinstance(value, dict):
        return {str(key): _redact_readiness_value(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_redact_readiness_value(item) for item in value]
    return f"{str(value)[:4]}***"


def _auth_readiness_score(preflight_status: str) -> float:
    if preflight_status == "ok":
        return 1.0
    if preflight_status == "degraded":
        return 0.5
    return 0.0


def _auth_readiness_fix(failures: list[str], preflight_status: str) -> str:
    if preflight_status == "ok":
        return "No auth preflight issues detected."
    if "invalid_session" in failures:
        return "Provide a valid bearer_token or session_cookie for the target URL, then rerun auth readiness."
    if "csrf_failed" in failures:
        return "Provide a session cookie or auth context that includes CSRF material for session-based auth."
    if "missing_role" in failures or "missing_tenant" in failures:
        return "Add role and tenant hints for every active identity before starting the scan."
    if preflight_status == "degraded":
        return "Auth can be checked during bootstrap; review the degraded probes before starting the scan."
    return "Review failing probes and update the auth configuration before starting the scan."


def _cookies_from_session_cookie(session_cookie: str) -> list[dict[str, str]]:
    cookies: list[dict[str, str]] = []
    for raw_pair in session_cookie.split(";"):
        pair = raw_pair.strip()
        if not pair or "=" not in pair:
            continue
        name, value = pair.split("=", 1)
        if name.strip() and value.strip():
            cookies.append({"name": name.strip(), "value": value.strip()})
    if cookies:
        return cookies
    return [{"name": "session", "value": session_cookie.strip()}]


async def _head_or_get(
    client: httpx.AsyncClient,
    url: str,
    *,
    headers: dict[str, str] | None = None,
) -> httpx.Response:
    head_error: httpx.HTTPError | None = None
    try:
        response = await client.head(url, headers=headers)
        if response.status_code != status.HTTP_405_METHOD_NOT_ALLOWED:
            return response
    except httpx.HTTPError as exc:
        head_error = exc

    try:
        return await client.get(url, headers=headers)
    except httpx.HTTPError as exc:
        if head_error is not None:
            raise exc from head_error
        raise


async def _probe_target_reachable(target_url: str) -> tuple[bool, str]:
    if not target_url.strip():
        return False, "Target URL is missing"

    base_url = _target_base_url(target_url)
    try:
        async with httpx.AsyncClient(
            timeout=TARGET_PROBE_TIMEOUT_SECONDS,
            follow_redirects=True,
            max_redirects=5,
        ) as client:
            response = await _head_or_get(client, base_url)
    except httpx.HTTPError as exc:
        return False, f"Target did not respond to HEAD/GET probe: {type(exc).__name__}"

    return True, f"Target base URL responded with HTTP {response.status_code}"


async def _probe_session_valid(
    *,
    scan_id: UUID,
    auth_context: AuthContext | None,
    target_url: str,
    requires_auth: bool,
) -> tuple[bool, str]:
    if not requires_auth:
        return True, "Auth is not required for this scan"

    if auth_context is None:
        return False, "Auth-required scan has no auth context"

    health = auth_context.health if isinstance(auth_context.health, dict) else {}
    if str(health.get("status", "")).lower() == "unhealthy":
        return False, "Stored auth context is marked unhealthy"

    if not target_url.strip():
        return False, "Target URL is missing; session probe cannot run"

    try:
        headers = _build_session_probe_headers(auth_context, scan_id)
    except ValueError as exc:
        return False, str(exc)

    if not headers:
        return False, "No session cookies, bearer token, or auth headers are available to probe"

    base_url = _target_base_url(target_url)
    try:
        async with httpx.AsyncClient(
            timeout=SESSION_PROBE_TIMEOUT_SECONDS,
            follow_redirects=True,
            max_redirects=5,
        ) as client:
            response = await _head_or_get(client, base_url, headers=headers)
    except httpx.HTTPError as exc:
        return False, f"Session probe did not receive a response: {type(exc).__name__}"

    if response.status_code in {status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN}:
        return False, f"Session probe returned HTTP {response.status_code}"

    return True, f"Session probe returned HTTP {response.status_code}"


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
    redis_url = os.getenv(REDIS_URL)
    if not redis_url:
        raise RuntimeError("REDIS_URL is not configured")
    connection = Redis.from_url(redis_url)
    queue_name = os.getenv("RQ_AUTH_QUEUE", "auth_bootstrap")
    return Queue(name=queue_name, connection=connection)


def _get_recon_queue() -> Queue:
    redis_url = os.getenv(REDIS_URL)
    if not redis_url:
        raise RuntimeError("REDIS_URL is not configured")
    connection = Redis.from_url(redis_url)
    queue_name = os.getenv("RQ_RECON_QUEUE", "recon")
    return Queue(name=queue_name, connection=connection)


@router.get("/auth/readiness", response_model=AuthReadinessResponse)
async def get_auth_readiness(
    target_url: str | None = Query(default=None),
    bearer_token: str | None = Query(default=None),
    session_cookie: str | None = Query(default=None),
) -> AuthReadinessResponse:
    auth_context: AuthContextCreate | None = None
    if bearer_token is not None and bearer_token.strip():
        auth_context = AuthContextCreate(type="token", bearer_token=bearer_token.strip())
    elif session_cookie is not None and session_cookie.strip():
        auth_context = AuthContextCreate(
            type="session",
            cookies=_cookies_from_session_cookie(session_cookie),
        )

    preflight_result = await preflight_auth_check(
        ScanConfig(
            target_url=(target_url or "").strip(),
            auth_context=auth_context,
        )
    )
    evidence = {
        key: value
        for key, value in {
            "target_url": target_url,
            "bearer_token": bearer_token,
            "session_cookie": session_cookie,
        }.items()
        if value is not None
    }

    return AuthReadinessResponse(
        readiness_score=_auth_readiness_score(preflight_result.status),
        status=preflight_result.status,
        failing_probes=preflight_result.failures,
        redacted_evidence=_redact_readiness_value(evidence),
        recommended_fix=_auth_readiness_fix(preflight_result.failures, preflight_result.status),
        checked_at=datetime.now(UTC),
    )


@router.post("", response_model=ScanResponse, status_code=status.HTTP_201_CREATED)
async def create_scan(payload: ScanCreate, db: AsyncSession = Depends(get_db)) -> ScanResponse:
    preflight_result = await preflight_auth_check(
        ScanConfig(
            unauth_mode=payload.unauth_mode,
            target_url=payload.target_url,
            auth_context=payload.auth_context,
            identities=payload.identities,
        )
    )
    if preflight_result.status == "failed":
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=asdict(preflight_result),
        )

    preflight_warnings: list[dict[str, object]] = []
    if preflight_result.status == "degraded":
        preflight_warnings.append(
            {
                "code": "auth_preflight_degraded",
                "preflight": asdict(preflight_result),
            }
        )

    domains = payload.allowed_domains if payload.allowed_domains else [urlparse(payload.target_url).hostname or payload.target_url]
    target = Target(
        url=payload.target_url,
        name=payload.target_url,
        config={"allowed_domains": domains, "unauth_mode": payload.unauth_mode},
    )
    db.add(target)
    await db.flush()

    scan_policy: dict[str, Any] = {"policy": payload.policy.model_dump(mode="json")}
    if payload.policy_v2 is not None:
        scan_policy["policy_v2"] = payload.policy_v2.model_dump(mode="json")
    scan = Scan(target_id=target.id, status=ScanStatus.created, phase="created", policy=scan_policy)
    db.add(scan)
    await db.flush()

    has_identities = bool(getattr(payload, "identities", None))
    auth_context: AuthContext | None = None
    if payload.auth_context is not None or has_identities:
        auth_type = payload.auth_context.type if payload.auth_context is not None else "none"
        auth_context = AuthContext(
            scan_id=scan.id,
            type=auth_type,
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
    scan.started_at = datetime.now(UTC)
    if auth_context is not None:
        scan.phase = "auth_bootstrap"
    else:
        scan.phase = "recon"
    await db.commit()
    await db.refresh(scan)

    _redis_url_env = os.getenv(REDIS_URL)
    if _redis_url_env:
        _kill_conn = Redis.from_url(_redis_url_env)
        if _kill_conn.get("kill:global"):
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="global_kill_switch_active")

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
        else:
            queue = _get_recon_queue()
            queue.enqueue("execution_plane.crawler.engine.run_crawler", str(scan.id))
            logger.info(
                "scan_recon_enqueued",
                scan_id=str(scan.id),
                phase=scan.phase,
                status=_status_value(scan.status),
                queue=getattr(queue, "name", "recon"),
            )
    except Exception as exc:
        scan.status = ScanStatus.failed
        scan.phase = "failed:enqueue"
        await db.commit()
        logger.exception("scan_enqueue_failed", scan_id=str(scan.id), error=str(exc))
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Failed to enqueue scan") from exc

    return _to_scan_response(scan, warnings=preflight_warnings)


@router.post("/preflight", response_model=PolicyPreflightResponse)
async def compute_policy_preflight(body: PreflightRequest) -> PolicyPreflightResponse:
    result = PolicyPreflight.compute(body.policy, body.endpoints)
    return PolicyPreflightResponse(
        will_test=result.will_test,
        will_skip=[asdict(item) for item in result.will_skip],
        will_block=[asdict(item) for item in result.will_block],
        total_endpoints=len(body.endpoints),
        blocked_count=len(result.will_block),
    )


@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan(scan_id: UUID, db: AsyncSession = Depends(get_db)) -> ScanResponse:
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    debug_details = await _build_scan_debug_details(db=db, scan_id=scan_id, scan=scan)
    logger.info("scan_status_polled", **debug_details)
    return _to_scan_response(scan)


@router.get("/{scan_id}/preflight", response_model=ScanReadinessResponse)
async def get_scan_preflight(scan_id: UUID, db: AsyncSession = Depends(get_db)) -> ScanReadinessResponse:
    scan_result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = scan_result.scalar_one_or_none()
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")

    target_result = await db.execute(select(Target).where(Target.id == scan.target_id))
    target = target_result.scalar_one_or_none()
    auth_result = await db.execute(select(AuthContext).where(AuthContext.scan_id == scan_id))
    auth_context = auth_result.scalar_one_or_none()

    target_url = target.url if target is not None and isinstance(target.url, str) else ""
    requires_auth = _scan_requires_auth(target)
    checks: list[ScanReadinessCheck] = []

    session_valid, session_message = await _probe_session_valid(
        scan_id=scan_id,
        auth_context=auth_context,
        target_url=target_url,
        requires_auth=requires_auth,
    )
    checks.append(
        ScanReadinessCheck(
            check_name="session_valid",
            passed=session_valid,
            blocking=requires_auth,
            message=session_message,
        )
    )

    target_reachable, target_message = await _probe_target_reachable(target_url)
    checks.append(
        ScanReadinessCheck(
            check_name="target_reachable",
            passed=target_reachable,
            blocking=True,
            message=target_message,
        )
    )

    seed_urls = _discovery_seed_urls(target)
    discovery_config_complete = bool(seed_urls)
    checks.append(
        ScanReadinessCheck(
            check_name="discovery_config_complete",
            passed=discovery_config_complete,
            blocking=True,
            message=(
                f"Crawler discovery has {len(seed_urls)} seed URL configured"
                if discovery_config_complete
                else "Crawler discovery has no seed URLs configured"
            ),
        )
    )

    auth_config_present = True if not requires_auth else _auth_context_has_config(auth_context)
    if not requires_auth:
        auth_config_message = "Auth is not required for this scan"
    elif auth_config_present:
        auth_config_message = "Auth configuration is present"
    else:
        auth_config_message = "Auth-required scan has no configured identity or session"

    checks.append(
        ScanReadinessCheck(
            check_name="auth_config_present",
            passed=auth_config_present,
            blocking=requires_auth,
            message=auth_config_message,
        )
    )

    blocking_issues = [check.message for check in checks if check.blocking and not check.passed]
    return ScanReadinessResponse(
        overall_ready=len(blocking_issues) == 0,
        checks=checks,
        blocking_issues=blocking_issues,
    )


@router.post("/{scan_id}/authorize-destructive")
async def authorize_destructive(scan_id: UUID, db: AsyncSession = Depends(get_db)) -> dict[str, str]:
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")

    stored_policy = scan.policy if isinstance(scan.policy, dict) else {}
    policy_v2_data = stored_policy.get("policy_v2")
    if not isinstance(policy_v2_data, dict):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="policy_v2 is required")

    policy_v2 = ScanPolicyV2.model_validate(policy_v2_data)
    if not policy_v2.destructive_budget.require_explicit_confirmation:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="destructive confirmation is not required for this scan",
        )

    stored_policy["destructive_authorized"] = True
    scan.policy = stored_policy
    await db.commit()
    return {"status": "destructive_authorized", "scan_id": str(scan_id)}


@router.post("/{scan_id}/kill")
async def kill_scan(scan_id: UUID, db: AsyncSession = Depends(get_db)) -> dict[str, str]:
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")

    redis_url = os.getenv(REDIS_URL)
    if not redis_url:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="REDIS_URL is not configured")
    connection = Redis.from_url(redis_url)
    KillSwitch(connection).activate(KillSwitchLevel.SCAN, str(scan_id))
    return {"status": "killed", "scan_id": str(scan_id)}


@router.get("/{scan_id}/kill-status")
async def get_scan_kill_status(scan_id: UUID) -> dict[str, object]:
    redis_url = os.getenv(REDIS_URL)
    if not redis_url:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="REDIS_URL is not configured")
    connection = Redis.from_url(redis_url)
    return {"active": KillSwitch(connection).is_active(str(scan_id)), "scan_id": str(scan_id)}


@router.put("/{scan_id}/kill")
async def enable_scan_kill_switch(scan_id: UUID, db: AsyncSession = Depends(get_db)) -> dict[str, object]:
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")

    redis_url = os.getenv(REDIS_URL)
    if not redis_url:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="REDIS_URL is not configured")
    connection = Redis.from_url(redis_url)
    connection.set(f"kill:{scan_id}", "1")

    db.add(
        AuditEvent(
            scan_id=scan_id,
            event_type=AuditEventType.SCAN_KILLED,
            actor="operator",
            details={"triggered_by": "api_kill_switch"},
        )
    )
    await db.commit()

    return {"killed": True, "scan_id": scan_id}


@router.delete("/{scan_id}/kill")
async def disable_scan_kill_switch(scan_id: UUID) -> dict[str, object]:
    redis_url = os.getenv(REDIS_URL)
    if not redis_url:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="REDIS_URL is not configured")
    connection = Redis.from_url(redis_url)
    connection.delete(f"kill:{scan_id}")
    return {"killed": False, "scan_id": scan_id}


@router.put("/kill")
async def enable_global_kill_switch() -> dict[str, bool]:
    redis_url = os.getenv(REDIS_URL)
    if not redis_url:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="REDIS_URL is not configured")
    connection = Redis.from_url(redis_url)
    connection.set("kill:global", "1")
    return {"global_kill": True}


@router.delete("/kill")
async def disable_global_kill_switch() -> dict[str, bool]:
    redis_url = os.getenv(REDIS_URL)
    if not redis_url:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="REDIS_URL is not configured")
    connection = Redis.from_url(redis_url)
    connection.delete("kill:global")
    return {"global_kill": False}


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
