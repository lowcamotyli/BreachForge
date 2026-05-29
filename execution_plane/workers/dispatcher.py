from __future__ import annotations
# dispatcher.py - RQ jobs for attack dispatch and scan finalization

AUTONOMOUS_ATTACK_ROUNDS_ENV = "AUTONOMOUS_ATTACK_ROUNDS"
LIFECYCLE_SECOND_CHECK_DELAY_ENV = "LIFECYCLE_SECOND_CHECK_DELAY_SECONDS"
LIFECYCLE_SECOND_CHECK_CAP_SECONDS = 300
DEFAULT_LIFECYCLE_SECOND_CHECK_DELAY = 0
DEFAULT_AUTONOMOUS_ATTACK_ROUNDS = 2
MAX_CONCURRENT_REPLAN_TASKS = 3


class ScanBudgetExceeded(RuntimeError):
    pass


def retry_on_redis_error(func):
    def _wrapped(*args, **kwargs):
        import time

        from redis.exceptions import ConnectionError as RedisConnectionError
        from redis.exceptions import TimeoutError as RedisTimeoutError

        delay_seconds = 0.1
        retries = 3
        last_exc: Exception | None = None
        for attempt in range(retries):
            try:
                return func(*args, **kwargs)
            except (RedisConnectionError, RedisTimeoutError) as exc:
                last_exc = exc
                if attempt == retries - 1:
                    raise
                time.sleep(delay_seconds)
                delay_seconds *= 2
        if last_exc is not None:
            raise last_exc
        return None

    return _wrapped


@retry_on_redis_error
def _redis_get(connection: object, key: str) -> object:
    return connection.get(key)


@retry_on_redis_error
def _redis_incr(connection: object, key: str) -> int:
    return int(connection.incr(key))


@retry_on_redis_error
def _redis_setnx(connection: object, key: str, value: str) -> bool:
    return bool(connection.setnx(key, value))


@retry_on_redis_error
def _redis_expire(connection: object, key: str, ttl_seconds: int) -> None:
    connection.expire(key, ttl_seconds)


def _class_in_priority(priority_classes: object, attack_class: str) -> bool:
    if not isinstance(priority_classes, list):
        return False
    return attack_class in [item for item in priority_classes if isinstance(item, str)]


def _parse_scan_budget(task: object) -> dict[str, object] | None:
    import json

    hypothesis = getattr(task, "hypothesis", None)
    if not isinstance(hypothesis, str) or not hypothesis.strip():
        return None
    try:
        payload = json.loads(hypothesis)
    except json.JSONDecodeError:
        return None
    if not isinstance(payload, dict):
        return None
    scan_budget = payload.get("scan_budget")
    return scan_budget if isinstance(scan_budget, dict) else None


def _enforce_dispatch_budget(*, connection: object, scan_id: str, attack_class: str, scan_budget: dict[str, object]) -> None:
    max_requests = scan_budget.get("max_requests")
    if not isinstance(max_requests, int) or isinstance(max_requests, bool) or max_requests <= 0:
        return

    priority_classes = scan_budget.get("priority_classes")
    if _class_in_priority(priority_classes, attack_class):
        return

    total_key = f"budget:{scan_id}:requests"
    total_dispatched = _redis_incr(connection, total_key)
    if total_dispatched == 1:
        _redis_expire(connection, total_key, 86400)
    if total_dispatched > max_requests:
        raise ScanBudgetExceeded(f"scan request budget exceeded for {scan_id}")

    class_cap = 0
    per_class_cap = scan_budget.get("per_class_cap")
    if isinstance(per_class_cap, dict):
        raw_cap = per_class_cap.get(attack_class)
        if isinstance(raw_cap, int) and not isinstance(raw_cap, bool):
            class_cap = raw_cap
    if class_cap <= 0:
        return

    class_key = f"budget:{scan_id}:class:{attack_class}"
    class_count = _redis_incr(connection, class_key)
    if class_count == 1:
        _redis_expire(connection, class_key, 86400)
    if class_count > class_cap:
        raise ScanBudgetExceeded(f"class budget exceeded for {attack_class}")


class Dispatcher:
    @staticmethod
    def dispatch_attack_tasks(scan_id: str) -> None:
        dispatch_attack_tasks(scan_id)

    @staticmethod
    def execute_attack(attack_task_id: str) -> None:
        execute_attack(attack_task_id)

    @staticmethod
    def finalize_scan(scan_id: str) -> None:
        finalize_scan(scan_id)


def create_empty_auth_context(scan_id: UUID) -> AuthContext:
    from datetime import UTC, datetime

    from storage.db.models import AuthContext

    return AuthContext(
        scan_id=scan_id,
        type="none",
        session_snapshot={
            "cookies": [],
            "auth_headers": {},
            "csrf_tokens": {},
            "captured_at": datetime.now(UTC).isoformat(),
            "expires_at": None,
        },
        health={},
    )


def _auth_type_from_context(auth_context: object) -> str:
    auth_type = getattr(auth_context, "auth_type", None)
    if isinstance(auth_type, str) and auth_type:
        return auth_type
    legacy_type = getattr(auth_context, "type", None)
    if isinstance(legacy_type, str) and legacy_type:
        return legacy_type
    return "none"


def dispatch_attack_tasks(scan_id: str) -> None:
    import asyncio

    asyncio.run(_dispatch_attack_tasks_async(scan_id))


async def _dispatch_attack_tasks_async(scan_id: str) -> None:
    import json
    import os
    from uuid import UUID, uuid4

    import structlog
    from control_plane.auth_manager import AuthManager, default_pause_scan
    from redis import Redis
    from rq import Queue
    from rq.job import Dependency
    from execution_plane.planner.planner import MAX_REPLAN_ROUNDS
    from sqlalchemy import select
    from sqlalchemy.orm import selectinload
    from storage.db.models import AttackTask, AttackTaskStatus, Scan
    from storage.db.session import AsyncSessionLocal

    logger = structlog.get_logger(__name__)
    scan_uuid = UUID(scan_id)

    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(AttackTask)
            .where(
                AttackTask.scan_id == scan_uuid,
                AttackTask.status == AttackTaskStatus.pending,
            )
            .options(
                selectinload(AttackTask.endpoint),
                selectinload(AttackTask.scan).selectinload(Scan.target),
            )
        )
        pending_tasks = list(result.scalars().all())

    if not pending_tasks:
        logger.warning("no_pending_attack_tasks", scan_id=scan_id)
        async with AsyncSessionLocal() as db:
            from control_plane.orchestrator import ScanOrchestrator
            from control_plane.reporting import ReportingService
            from storage.evidence.store import EvidenceStore

            evidence_store = EvidenceStore()
            reporting_service = ReportingService(db=db, evidence_store=evidence_store)
            orchestrator = ScanOrchestrator(AsyncSessionLocal, reporting_service)
            await orchestrator.on_attack_complete(scan_uuid)
        return

    redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    connection = Redis.from_url(redis_url)
    queue_name = os.getenv("RQ_ATTACK_QUEUE", "attack_tasks")
    queue = Queue(name=queue_name, connection=connection)

    manager = AuthManager(scan_uuid, AsyncSessionLocal, default_pause_scan)
    expired_identities = await _collect_expired_identity_names(
        db_factory=AsyncSessionLocal,
        scan_uuid=scan_uuid,
        manager=manager,
        logger=logger,
    )

    dispatch_batch_size = len(pending_tasks)
    replan_rounds_raw = _redis_get(connection, f"replan:rounds:{scan_id}")
    replan_rounds = _parse_int_or_zero(replan_rounds_raw)
    if replan_rounds > MAX_REPLAN_ROUNDS:
        dispatch_batch_size = min(dispatch_batch_size, MAX_CONCURRENT_REPLAN_TASKS)

    tasks_to_dispatch = pending_tasks[:dispatch_batch_size]
    race_group_ids_by_task: dict[UUID, str] = {}
    race_groups: dict[str, dict[str, str]] = {}
    race_tasks_by_key: dict[tuple[str, str], list[AttackTask]] = {}
    for pending_task in tasks_to_dispatch:
        if not _is_race_related_attack_class(pending_task.attack_class):
            continue
        race_key = (str(pending_task.attack_class), str(pending_task.endpoint_id))
        race_tasks_by_key.setdefault(race_key, []).append(pending_task)
    for class_tasks in race_tasks_by_key.values():
        if not class_tasks:
            continue
        race_group_id = str(uuid4())
        first_task = class_tasks[0]
        endpoint_id = str(first_task.endpoint_id)
        endpoint_url = _task_endpoint_url(first_task)
        for class_task in class_tasks:
            race_group_ids_by_task[class_task.id] = race_group_id
        race_groups[race_group_id] = {
            "endpoint_id": endpoint_id,
            "endpoint_url": endpoint_url,
            "attack_class": str(first_task.attack_class),
            "task_ids": ",".join(str(task.id) for task in class_tasks),
            "reconcile_required": "true",
        }
    jobs = []
    skipped_tasks = 0
    kill_switch_active = False
    if race_groups:
        _ks = _redis_get(connection, f"kill:{scan_id}")
        _kg = _redis_get(connection, "kill:global")
        if (isinstance(_ks, (str, bytes)) and _ks) or (isinstance(_kg, (str, bytes)) and _kg):
            logger.warning("dispatch_kill_switch_active", scan_id=scan_id)
            kill_switch_active = True
        else:
            await _prime_race_initial_state_hashes(scan_uuid=scan_uuid, race_groups=race_groups)
    async with AsyncSessionLocal() as db:
        for task in tasks_to_dispatch:
            if kill_switch_active:
                break
            _ks = _redis_get(connection, f"kill:{scan_id}")
            _kg = _redis_get(connection, "kill:global")
            if (isinstance(_ks, (str, bytes)) and _ks) or (isinstance(_kg, (str, bytes)) and _kg):
                logger.warning("dispatch_kill_switch_active", scan_id=scan_id)
                kill_switch_active = True
                break
            race_group_id = race_group_ids_by_task.get(task.id)
            if race_group_id is not None:
                task.hypothesis = _inject_race_group_id(task.hypothesis, race_group_id)
                db.add(task)
            identity_selector = _extract_identity_selector_from_hypothesis(task.hypothesis)
            if identity_selector is None or identity_selector not in expired_identities:
                try:
                    scan_budget = _parse_scan_budget(task)
                    if scan_budget is not None:
                        _enforce_dispatch_budget(
                            connection=connection,
                            scan_id=scan_id,
                            attack_class=str(task.attack_class),
                            scan_budget=scan_budget,
                        )
                    jobs.append(queue.enqueue(execute_attack, str(task.id)))
                except ScanBudgetExceeded:
                    task.status = AttackTaskStatus.failed
                    db.add(task)
                continue

            task.status = AttackTaskStatus.failed
            db.add(task)
            skipped_tasks += 1
            await _emit_identity_health_failed_event(
                redis_connection=connection,
                scan_id=scan_id,
                payload={"event": "identity_health_failed", "identity_name": identity_selector, "task_id": str(task.id)},
            )
            logger.warning(
                "task_skipped_identity_expired",
                scan_id=scan_id,
                task_id=str(task.id),
                identity_name=identity_selector,
                status="skipped:identity_expired",
            )
        await db.commit()

    await manager.close()
    if kill_switch_active:
        return

    finalize_dependencies = list(jobs)
    if race_groups:
        race_reconciliation_job = queue.enqueue(
            dispatch_race_reconciliation,
            scan_id,
            race_groups,
            depends_on=Dependency(jobs=jobs, allow_failure=True),
        )
        finalize_dependencies.append(race_reconciliation_job)
    queue.enqueue(finalize_scan, scan_id, depends_on=Dependency(jobs=finalize_dependencies, allow_failure=True))

    logger.info(
        "attack_tasks_dispatched",
        scan_id=scan_id,
        task_count=len(pending_tasks),
        dispatch_batch_size=dispatch_batch_size,
        queued_count=len(jobs),
        skipped_expired_count=skipped_tasks,
        replan_rounds=replan_rounds,
    )


def execute_attack(attack_task_id: str) -> None:
    import asyncio

    asyncio.run(_execute_attack_async(attack_task_id))


async def _execute_attack_async(attack_task_id: str, hypothesis_override: str | None = None) -> None:
    from uuid import UUID

    import structlog
    from control_plane.auth_manager import AuthManager, default_pause_scan
    from execution_plane.workers.attack_worker import AttackWorker, AuthExpiredError
    from sqlalchemy import select
    from sqlalchemy.orm import selectinload
    from storage.db.models import AttackTask, AttackTaskStatus, AuthContext, Endpoint, Scan
    from storage.db.session import AsyncSessionLocal

    logger = structlog.get_logger(__name__)
    task_uuid = UUID(attack_task_id)

    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(AttackTask)
            .where(AttackTask.id == task_uuid)
            .options(
                selectinload(AttackTask.endpoint),
                selectinload(AttackTask.scan).selectinload(Scan.target),
            )
        )
        task = result.scalar_one_or_none()
        if task is None:
            logger.error("attack_task_not_found", attack_task_id=attack_task_id)
            return

        if not isinstance(task.endpoint, Endpoint):
            logger.error("attack_task_endpoint_missing", attack_task_id=attack_task_id)
            task.status = AttackTaskStatus.failed
            await db.commit()
            return

        scan = task.scan
        if not isinstance(scan, Scan):
            logger.error("attack_task_scan_missing", attack_task_id=attack_task_id)
            task.status = AttackTaskStatus.failed
            await db.commit()
            return

        manager = AuthManager(scan.id, AsyncSessionLocal, default_pause_scan)
        try:
            auth_result = await db.execute(select(AuthContext).where(AuthContext.scan_id == scan.id))
            auth_context = auth_result.scalar_one_or_none()
            if auth_context is None:
                auth_context = create_empty_auth_context(scan.id)
            session_snapshot = _session_snapshot_from_auth_context(auth_context, scan.id)
            manager._session_snapshot = session_snapshot
            manager._auth_type = _auth_type_from_context(auth_context)
        except Exception:
            logger.exception("attack_task_session_snapshot_failed", attack_task_id=attack_task_id, scan_id=str(scan.id))
            task.status = AttackTaskStatus.failed
            await db.commit()
            await manager.close()
            return

        task.status = AttackTaskStatus.running
        await db.commit()

        worker = AttackWorker(auth_manager=manager)
        try:
            await worker.execute(task, session_snapshot, hypothesis_override=hypothesis_override)
            task.status = AttackTaskStatus.done
            await db.commit()
        except AuthExpiredError:
            logger.warning("attack_task_paused_auth_expired", attack_task_id=attack_task_id, scan_id=str(scan.id))
            task.status = AttackTaskStatus.pending
            await db.commit()
        except Exception:
            logger.exception("attack_task_execution_failed", attack_task_id=attack_task_id, scan_id=str(scan.id))
            task.status = AttackTaskStatus.failed
            await db.commit()
        finally:
            await manager.close()


def _session_snapshot_from_auth_context(auth_context: object, scan_id: object) -> object:
    from datetime import UTC, datetime
    from uuid import UUID

    from control_plane.auth_manager import SessionSnapshot, _decrypt_snapshot_field

    scan_uuid = scan_id if isinstance(scan_id, UUID) else UUID(str(scan_id))
    if _auth_type_from_context(auth_context) == "none":
        return SessionSnapshot(
            scan_id=scan_uuid,
            cookies=[],
            auth_headers={},
            csrf_tokens={},
            captured_at=datetime.now(UTC),
            expires_at=None,
        )

    snapshot = getattr(auth_context, "session_snapshot", {})
    if not isinstance(snapshot, dict):
        snapshot = {}

    cookies = _decrypt_snapshot_field(snapshot.get("cookies"), scan_uuid)
    auth_headers = _decrypt_snapshot_field(snapshot.get("auth_headers"), scan_uuid)
    csrf_tokens = _decrypt_snapshot_field(snapshot.get("csrf_tokens"), scan_uuid)
    bearer_token = _decrypt_snapshot_field(snapshot.get("bearer_token"), scan_uuid)

    if not isinstance(cookies, list):
        cookies = []
    if not isinstance(auth_headers, dict):
        auth_headers = {}
    if isinstance(bearer_token, str) and bearer_token and "Authorization" not in auth_headers:
        auth_headers["Authorization"] = f"Bearer {bearer_token}"
    if not isinstance(csrf_tokens, dict):
        csrf_tokens = {}

    captured_at = _parse_datetime(snapshot.get("captured_at")) or datetime.now(UTC)
    expires_at = _parse_datetime(snapshot.get("expires_at"))

    return SessionSnapshot(
        scan_id=scan_uuid,
        cookies=cookies,
        auth_headers={str(key): str(value) for key, value in auth_headers.items()},
        csrf_tokens={str(key): str(value) for key, value in csrf_tokens.items()},
        captured_at=captured_at,
        expires_at=expires_at,
    )


def _parse_datetime(value: object) -> object:
    from datetime import datetime

    if isinstance(value, datetime):
        return value
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def _parse_int_or_zero(value: object) -> int:
    if value is None:
        return 0
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="ignore")
    try:
        return int(str(value))
    except ValueError:
        return 0


def _task_endpoint_url(task: object) -> str:
    from urllib.parse import urljoin, urlparse

    endpoint = getattr(task, "endpoint", None)
    raw_url = getattr(endpoint, "url_pattern", None)
    if not isinstance(raw_url, str) or not raw_url.strip():
        return ""

    parsed = urlparse(raw_url)
    if parsed.scheme and parsed.netloc:
        return raw_url

    scan = getattr(task, "scan", None)
    target = getattr(scan, "target", None)
    base_url = getattr(target, "url", None)
    if not isinstance(base_url, str) or not base_url.strip():
        return raw_url
    return urljoin(base_url.rstrip("/") + "/", raw_url.lstrip("/"))


async def _prime_race_initial_state_hashes(scan_uuid: object, race_groups: dict[str, dict[str, str]]) -> None:
    session = await _load_session_snapshot_for_scan(scan_uuid)
    for payload in race_groups.values():
        endpoint_url = payload.get("endpoint_url")
        if not isinstance(endpoint_url, str) or not endpoint_url:
            continue
        initial_hash = await _fetch_state_hash(endpoint_url, session)
        if initial_hash is not None:
            payload["initial_state_hash"] = initial_hash


async def _load_session_snapshot_for_scan(scan_uuid: object) -> object:
    from sqlalchemy import select
    from storage.db.models import AuthContext
    from storage.db.session import AsyncSessionLocal

    async with AsyncSessionLocal() as db:
        result = await db.execute(select(AuthContext).where(AuthContext.scan_id == scan_uuid))
        auth_context = result.scalar_one_or_none()
    if auth_context is None:
        auth_context = create_empty_auth_context(scan_uuid)
    return _session_snapshot_from_auth_context(auth_context, scan_uuid)


async def _fetch_state_hash(endpoint_url: str, session: object) -> str | None:
    from urllib.parse import urlparse

    import httpx

    parsed = urlparse(endpoint_url)
    if not parsed.scheme or not parsed.netloc:
        return None

    headers = _session_headers(session)
    cookies = _session_cookies(session)
    try:
        async with httpx.AsyncClient(follow_redirects=True) as client:
            response = await client.get(endpoint_url, headers=headers, cookies=cookies)
    except Exception:
        return None
    return _hash_state_payload({"status": response.status_code, "body": response.text})


def _session_headers(session: object) -> dict[str, str]:
    headers: dict[str, str] = {}
    auth_headers = getattr(session, "auth_headers", {})
    if isinstance(auth_headers, dict):
        headers.update({str(key): str(value) for key, value in auth_headers.items()})
    csrf_tokens = getattr(session, "csrf_tokens", {})
    if isinstance(csrf_tokens, dict):
        headers.update({str(key): str(value) for key, value in csrf_tokens.items()})
    return headers


def _session_cookies(session: object) -> dict[str, str]:
    cookies_raw = getattr(session, "cookies", [])
    if not isinstance(cookies_raw, list):
        return {}
    cookies: dict[str, str] = {}
    for cookie in cookies_raw:
        if not isinstance(cookie, dict):
            continue
        name = cookie.get("name")
        value = cookie.get("value")
        if isinstance(name, str) and isinstance(value, str):
            cookies[name] = value
    return cookies


def _hash_state_payload(payload: object) -> str:
    import hashlib
    import json

    try:
        material = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    except (TypeError, ValueError):
        material = str(payload)
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


async def _collect_expired_identity_names(
    db_factory: object,
    scan_uuid: object,
    manager: object,
    logger: object,
) -> set[str]:
    from uuid import UUID

    from sqlalchemy import select
    from storage.db.models import AuthContext

    expired: set[str] = set()
    if not hasattr(manager, "per_identity_health_check"):
        return expired

    scan_id = scan_uuid if isinstance(scan_uuid, UUID) else UUID(str(scan_uuid))
    try:
        async with db_factory() as db:
            auth_result = await db.execute(select(AuthContext).where(AuthContext.scan_id == scan_id))
            auth_context = auth_result.scalar_one_or_none()
        if auth_context is None:
            return expired

        session_snapshot = _session_snapshot_from_auth_context(auth_context, scan_id)
        setattr(manager, "_session_snapshot", session_snapshot)
        setattr(manager, "_auth_type", _auth_type_from_context(auth_context))
        await manager.per_identity_health_check()
        named_identities = getattr(manager, "_named_identities", {})
        if isinstance(named_identities, dict):
            for identity_name, identity in named_identities.items():
                if not isinstance(identity_name, str):
                    continue
                if getattr(identity, "auth_state", None) == "expired":
                    expired.add(identity_name)
    except Exception:
        logger.exception("identity_health_check_pre_dispatch_failed", scan_id=str(scan_id))
    return expired


def _extract_identity_selector_from_hypothesis(hypothesis: object) -> str | None:
    import json

    if not isinstance(hypothesis, str) or not hypothesis.strip():
        return None
    try:
        payload = json.loads(hypothesis)
    except json.JSONDecodeError:
        return None
    if not isinstance(payload, dict):
        return None
    selector = payload.get("identity_selector")
    if not isinstance(selector, str):
        return None
    clean_selector = selector.strip()
    return clean_selector if clean_selector else None


async def _emit_identity_health_failed_event(redis_connection: object, scan_id: str, payload: dict[str, str]) -> None:
    import asyncio

    stream_key = f"scan_events:{scan_id}"
    sanitized_payload = {
        "event": payload.get("event", ""),
        "identity_name": payload.get("identity_name", ""),
        "task_id": payload.get("task_id", ""),
    }
    await asyncio.to_thread(redis_connection.xadd, stream_key, sanitized_payload)


async def _emit_race_reconciliation_event(
    redis_connection: object,
    scan_id: str,
    race_group_id: str,
    status: str,
    task_id: str,
    metadata: dict[str, str] | None = None,
) -> None:
    import asyncio

    stream_key = f"race_reconciliation:{scan_id}"
    payload = {
        "event": "race_reconciliation_completed",
        "race_group_id": race_group_id,
        "status": status,
        "task_id": task_id,
    }
    if metadata:
        payload.update(metadata)
    await asyncio.to_thread(redis_connection.xadd, stream_key, payload)


async def _record_race_reconciliation_result(
    redis_connection: object,
    scan_id: str,
    race_group_id: str,
    payload: dict[str, str],
) -> None:
    import asyncio

    key = f"race_reconcile:{scan_id}:{race_group_id}"
    try:
        await asyncio.to_thread(redis_connection.hset, key, mapping=payload)
        await asyncio.to_thread(redis_connection.expire, key, 60 * 60 * 24)
    except Exception:
        return


async def _reconcile_race_final_state(
    endpoint_url: str,
    session: object,
    initial_state_hash: str | None,
    final_state_hash: str | None,
) -> bool:
    if not isinstance(initial_state_hash, str) or not initial_state_hash:
        return False
    resolved_final_hash = final_state_hash
    if not isinstance(resolved_final_hash, str) or not resolved_final_hash:
        resolved_final_hash = await _fetch_state_hash(endpoint_url, session)
    if not isinstance(resolved_final_hash, str) or not resolved_final_hash:
        return False
    return resolved_final_hash != initial_state_hash


def _is_race_related_attack_class(attack_class: object) -> bool:
    if not isinstance(attack_class, str):
        return False
    value = attack_class.strip().lower()
    race_classes = {
        "double_spend",
        "limit_override",
        "limit_override_race",
        "inventory_reservation",
        "inventory_reservation_abuse",
        "idempotency_bypass",
        "race_condition",
    }
    return value in race_classes or "race" in value


def _inject_race_group_id(hypothesis: object, race_group_id: str) -> str:
    import json

    payload: dict[str, object] = {}
    if isinstance(hypothesis, str) and hypothesis.strip():
        try:
            parsed = json.loads(hypothesis)
            if isinstance(parsed, dict):
                payload = parsed
        except json.JSONDecodeError:
            payload = {"hypothesis_raw": hypothesis}
    payload["_race_group_id"] = race_group_id
    return json.dumps(payload, sort_keys=True)


def finalize_scan(scan_id: str) -> None:
    import asyncio

    asyncio.run(_finalize_scan_async(scan_id))


def dispatch_race_reconciliation(scan_id: str, race_groups: dict[str, dict[str, str]]) -> None:
    import asyncio

    asyncio.run(_dispatch_race_reconciliation_async(scan_id, race_groups))


async def _dispatch_race_reconciliation_async(scan_id: str, race_groups: dict[str, dict[str, str]]) -> None:
    import json
    import os
    from uuid import UUID

    import structlog
    from redis import Redis
    from sqlalchemy import select
    from storage.db.models import AttackTask, AttackTaskStatus, Endpoint
    from storage.db.session import AsyncSessionLocal

    logger = structlog.get_logger(__name__)
    if not isinstance(race_groups, dict) or not race_groups:
        return

    scan_uuid = UUID(scan_id)
    redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    connection = Redis.from_url(redis_url)

    for race_group_id, payload in race_groups.items():
        if not isinstance(payload, dict):
            continue
        endpoint_id_raw = payload.get("endpoint_id")
        if not isinstance(endpoint_id_raw, str) or not endpoint_id_raw:
            continue
        reconciliation_task_id: str | None = None
        reconciliation_status = "failed"
        reconciliation_metadata: dict[str, str] = {
            "reconcile_required": "true",
            "reconcile_passed": "false",
        }
        try:
            endpoint_uuid = UUID(endpoint_id_raw)
            endpoint_url = payload.get("endpoint_url")
            if not isinstance(endpoint_url, str) or not endpoint_url.strip():
                async with AsyncSessionLocal() as db:
                    endpoint_result = await db.execute(select(Endpoint).where(Endpoint.id == endpoint_uuid))
                    endpoint = endpoint_result.scalar_one_or_none()
                    endpoint_url = str(endpoint.url_pattern) if endpoint is not None else ""
            session = await _load_session_snapshot_for_scan(scan_uuid)
            initial_state_hash = payload.get("initial_state_hash")
            final_state_hash = await _fetch_state_hash(endpoint_url, session) if endpoint_url else None
            final_ok = await _reconcile_race_final_state(
                endpoint_url,
                session,
                initial_state_hash,
                final_state_hash,
            )
            reconciliation_metadata.update(
                {
                    "reconcile_passed": "true" if final_ok else "false",
                    "initial_state_hash": initial_state_hash or "",
                    "final_state_hash": final_state_hash or "",
                    "endpoint_url": endpoint_url or "",
                }
            )
            await _record_race_reconciliation_result(
                redis_connection=connection,
                scan_id=scan_id,
                race_group_id=race_group_id,
                payload=reconciliation_metadata,
            )
            if not final_ok:
                reconciliation_status = "no_signal"
                continue

            async with AsyncSessionLocal() as db:
                hypothesis_payload = {
                    "probe_type": "race_reconciliation_read",
                    "attack_class": "reconciliation_read",
                    "method": "GET",
                    "_race_group_id": race_group_id,
                    "reconcile_passed": True,
                    "initial_state_hash": initial_state_hash,
                    "final_state_hash": final_state_hash,
                }
                reconciliation_task = AttackTask(
                    scan_id=scan_uuid,
                    endpoint_id=endpoint_uuid,
                    attack_class="reconciliation_read",
                    target_parameter="race_reconciliation",
                    hypothesis=json.dumps(hypothesis_payload, sort_keys=True),
                    status=AttackTaskStatus.pending,
                )
                db.add(reconciliation_task)
                await db.commit()
                reconciliation_task_id = str(reconciliation_task.id)

            if reconciliation_task_id is None:
                continue
            await _execute_attack_async(reconciliation_task_id)
            reconciliation_status = "done"
        except Exception:
            logger.exception(
                "race_reconciliation_dispatch_failed",
                scan_id=scan_id,
                race_group_id=race_group_id,
            )
        finally:
            await _emit_race_reconciliation_event(
                redis_connection=connection,
                scan_id=scan_id,
                race_group_id=race_group_id,
                status=reconciliation_status,
                task_id=reconciliation_task_id or "",
                metadata=reconciliation_metadata,
            )


async def _finalize_scan_async(scan_id: str) -> None:
    import os
    from uuid import UUID

    import structlog
    from redis import Redis
    from storage.db.session import AsyncSessionLocal

    logger = structlog.get_logger(__name__)
    scan_uuid = UUID(scan_id)

    redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    connection = Redis.from_url(redis_url, decode_responses=True)
    finalize_key = f"finalized:{scan_id}"
    if not _redis_setnx(connection, finalize_key, "1"):
        logger.info("scan_finalize_already_done", scan_id=scan_id)
        return
    _redis_expire(connection, finalize_key, 86400)
    max_rounds = _autonomous_attack_rounds(os.getenv(AUTONOMOUS_ATTACK_ROUNDS_ENV))
    delay_seconds = _lifecycle_second_check_delay(os.getenv(LIFECYCLE_SECOND_CHECK_DELAY_ENV))
    for round_index in range(max_rounds + 1):
        await _validate_and_score_evidence(scan_uuid=scan_uuid, redis_connection=connection, logger=logger)
        if round_index >= max_rounds:
            break

        follow_ups = await _create_autonomous_follow_up_tasks(scan_uuid=scan_uuid, logger=logger)
        if not follow_ups:
            break

        logger.info(
            "autonomous_attack_followups_executing",
            scan_id=str(scan_uuid),
            round=round_index + 1,
            task_count=len(follow_ups),
        )
        for follow_up in follow_ups:
            await _execute_attack_async(
                str(follow_up["task_id"]),
                hypothesis_override=follow_up.get("hypothesis_override"),
            )

    async with AsyncSessionLocal() as db:
        from control_plane.orchestrator import ScanOrchestrator
        from control_plane.reporting import ReportingService
        from storage.evidence.store import EvidenceStore

        evidence_store = EvidenceStore()
        reporting_service = ReportingService(db=db, evidence_store=evidence_store)
        orchestrator = ScanOrchestrator(AsyncSessionLocal, reporting_service)
        await orchestrator.on_all_validated(scan_uuid)

    logger.info("scan_finalized", scan_id=scan_id)
    logger.debug("lifecycle_second_check_configured", scan_id=scan_id, delay_seconds=delay_seconds)


def _autonomous_attack_rounds(raw_value: object) -> int:
    if raw_value is None:
        return DEFAULT_AUTONOMOUS_ATTACK_ROUNDS
    try:
        parsed = int(str(raw_value))
    except ValueError:
        return DEFAULT_AUTONOMOUS_ATTACK_ROUNDS
    return min(max(parsed, 0), 5)


def _lifecycle_second_check_delay(raw: str | None) -> int:
    if raw is None or not raw.strip():
        return DEFAULT_LIFECYCLE_SECOND_CHECK_DELAY
    try:
        parsed_value = int(raw)
    except ValueError:
        return 0
    if parsed_value <= 0:
        return 0
    return min(parsed_value, LIFECYCLE_SECOND_CHECK_CAP_SECONDS)


async def _create_autonomous_follow_up_tasks(*, scan_uuid: object, logger: object) -> list[dict[str, str | None]]:
    import json

    from sqlalchemy import select
    from sqlalchemy.orm import selectinload
    from storage.db.models import AssetMap, AttackTask, AttackTaskStatus, Finding, ProofArtifact, Scan
    from storage.db.session import AsyncSessionLocal
    from storage.evidence.store import EvidenceStore

    evidence_store = EvidenceStore()
    async with AsyncSessionLocal() as db:
        scan_result = await db.execute(
            select(Scan)
            .where(Scan.id == scan_uuid)
            .options(selectinload(Scan.asset_map).selectinload(AssetMap.endpoints))
        )
        scan_record = scan_result.scalar_one_or_none()
        scan_asset_map = getattr(scan_record, "asset_map", None)

        result = await db.execute(
            select(Finding)
            .where(Finding.scan_id == scan_uuid)
            .options(
                selectinload(Finding.affected_endpoint),
                selectinload(Finding.proof_artifacts).selectinload(ProofArtifact.attack_task),
            )
        )
        findings = result.scalars().all()

        created_follow_ups: list[dict[str, str | None]] = []
        for finding in findings:
            if finding.attack_class != "sensitive_exposure":
                continue
            _annotate_replay_artifacts_with_scan_activity(
                scan_id=str(scan_uuid),
                finding_id=str(finding.id),
                proof_artifacts=list(finding.proof_artifacts),
                evidence_store=evidence_store,
            )
            endpoint = finding.affected_endpoint
            if endpoint is None:
                continue

            evidence_notes = " ".join(str(artifact.evidence_notes or "") for artifact in finding.proof_artifacts)
            follow_ups = _sensitive_exposure_follow_up_payloads(
                finding_id=str(finding.id),
                evidence_notes=evidence_notes,
            )
            follow_ups.extend(
                _safe_secret_replay_follow_up_payloads(
                    scan_id=str(scan_uuid),
                    finding_id=str(finding.id),
                    proof_artifacts=finding.proof_artifacts,
                    evidence_store=evidence_store,
                )
            )
            replay_payload = next(
                (
                    payload
                    for _target_parameter, payload in follow_ups
                    if payload.get("probe_type") == "impact_secret_replay"
                ),
                None,
            )
            if replay_payload is not None and scan_asset_map is not None:
                secret_kind = replay_payload.get("secret_kind")
                secret_value = replay_payload.get("secret_value")
                if isinstance(secret_kind, str) and isinstance(secret_value, str):
                    follow_ups.extend(
                        _blast_radius_follow_up_payloads(
                            scan_id=str(scan_uuid),
                            finding_id=str(finding.id),
                            source_endpoint_pattern=(
                                str(replay_payload.get("source_endpoint_pattern"))
                                if isinstance(replay_payload.get("source_endpoint_pattern"), str)
                                else None
                            ),
                            asset_map=scan_asset_map,
                            secret_kind=secret_kind,
                            secret_value=secret_value,
                        )
                    )
            for target_parameter, payload in follow_ups:
                persisted_payload = _redacted_follow_up_payload(payload)
                existing = await db.execute(
                    select(AttackTask.id).where(
                        AttackTask.scan_id == scan_uuid,
                        AttackTask.endpoint_id == endpoint.id,
                        AttackTask.attack_class == "sensitive_exposure",
                        AttackTask.target_parameter == target_parameter,
                    )
                )
                if existing.scalar_one_or_none() is not None:
                    continue

                task = AttackTask(
                    scan_id=scan_uuid,
                    endpoint_id=endpoint.id,
                    attack_class="sensitive_exposure",
                    target_parameter=target_parameter,
                    hypothesis=json.dumps(persisted_payload, sort_keys=True),
                    priority_score=99.0,
                    status=AttackTaskStatus.pending,
                )
                db.add(task)
                await db.flush()
                created_follow_ups.append(
                    {
                        "task_id": str(task.id),
                        "hypothesis_override": json.dumps(payload, sort_keys=True)
                        if payload.get("probe_type") in {"impact_secret_replay", "impact_secret_blast_radius"}
                        else None,
                    }
                )

        await db.commit()

    logger.info(
        "autonomous_attack_followups_created",
        scan_id=str(scan_uuid),
        task_count=len(created_follow_ups),
    )
    return created_follow_ups


def _sensitive_exposure_follow_up_payloads(
    *,
    finding_id: str,
    evidence_notes: str,
) -> list[tuple[str, dict[str, object]]]:
    normalized_notes = evidence_notes.lower()
    payloads: list[tuple[str, dict[str, object]]] = [
        (
            f"impact.unauthenticated_repeat.{finding_id}",
            {
                "probe_type": "impact_unauthenticated_repeat",
                "parent_finding_id": finding_id,
                "safe_mode": True,
                "goal": "repeat the exposure safely to prove unauthenticated reachability",
            },
        )
    ]

    if "credential" in normalized_notes or "token" in normalized_notes:
        payloads.append(
            (
                f"impact.secret_classification.{finding_id}",
                {
                    "probe_type": "impact_secret_classification",
                    "parent_finding_id": finding_id,
                    "safe_mode": True,
                    "goal": "classify exposed secret-like material without replaying it destructively",
                },
            )
        )

    if "pii" in normalized_notes:
        payloads.append(
            (
                f"impact.data_abuse.{finding_id}",
                {
                    "probe_type": "impact_data_abuse",
                    "parent_finding_id": finding_id,
                    "safe_mode": True,
                    "goal": "confirm whether exposed data supports user targeting or privacy impact",
                },
            )
        )
    return payloads


def _redacted_follow_up_payload(payload: dict[str, object]) -> dict[str, object]:
    redacted = dict(payload)
    if "secret_value" in redacted:
        redacted["secret_value"] = "[REDACTED]"
    return redacted


def _safe_secret_replay_follow_up_payloads(
    *,
    scan_id: str,
    finding_id: str,
    proof_artifacts: list[object],
    evidence_store: object,
) -> list[tuple[str, dict[str, object]]]:
    for artifact in proof_artifacts:
        notes = str(getattr(artifact, "evidence_notes", "") or "").lower()
        if "credential" not in notes and "token" not in notes:
            continue

        attack_probe_id = getattr(artifact, "attack_probe_id", None)
        if attack_probe_id is None:
            continue
        try:
            probe_payload = evidence_store.read_probe(scan_id=scan_id, finding_id=finding_id, probe_id=str(attack_probe_id))
        except Exception:
            continue

        secret = _extract_replayable_secret(probe_payload)
        if secret is None:
            continue

        secret_kind, secret_value = secret
        source_endpoint_pattern = _extract_source_endpoint_pattern(probe_payload)
        return [
            (
                f"impact.secret_replay.{secret_kind}.{finding_id}",
                {
                    "probe_type": "impact_secret_replay",
                    "parent_finding_id": finding_id,
                    "secret_kind": secret_kind,
                    "secret_value": secret_value,
                    "source_endpoint_pattern": source_endpoint_pattern,
                    "safe_mode": True,
                    "goal": "replay an exposed secret once against the same read-only endpoint to confirm it is active",
                },
            )
        ]
    return []


def _annotate_replay_artifacts_with_scan_activity(
    *,
    scan_id: str,
    finding_id: str,
    proof_artifacts: list[object],
    evidence_store: object,
) -> None:
    for artifact in proof_artifacts:
        if not _is_impact_secret_replay_artifact(artifact):
            continue
        existing_notes = str(getattr(artifact, "evidence_notes", "") or "")
        if "active_during_scan=" in existing_notes.lower():
            continue
        active_during_scan = _replay_artifact_active_during_scan(
            scan_id=scan_id,
            finding_id=finding_id,
            artifact=artifact,
            evidence_store=evidence_store,
        )
        suffix = "true" if active_during_scan else "false"
        setattr(artifact, "evidence_notes", f"{existing_notes}; active_during_scan={suffix}")


def _is_impact_secret_replay_artifact(artifact: object) -> bool:
    direct_probe_type = getattr(artifact, "probe_type", None)
    if isinstance(direct_probe_type, str) and direct_probe_type.strip().lower() == "impact_secret_replay":
        return True

    attack_task = getattr(artifact, "attack_task", None)
    hypothesis = getattr(attack_task, "hypothesis", None)
    if isinstance(hypothesis, str) and hypothesis.strip():
        import json

        try:
            parsed = json.loads(hypothesis)
        except json.JSONDecodeError:
            parsed = {}
        if isinstance(parsed, dict):
            probe_type = parsed.get("probe_type")
            if isinstance(probe_type, str) and probe_type.strip().lower() == "impact_secret_replay":
                return True

    evidence_notes = str(getattr(artifact, "evidence_notes", "") or "").lower()
    return "impact_probe=impact_secret_replay" in evidence_notes or "probe_type=impact_secret_replay" in evidence_notes


def _replay_artifact_active_during_scan(*, scan_id: str, finding_id: str, artifact: object, evidence_store: object) -> bool:
    attack_probe_id = getattr(artifact, "attack_probe_id", None)
    if attack_probe_id is not None:
        try:
            probe_payload = evidence_store.read_probe(scan_id=scan_id, finding_id=finding_id, probe_id=str(attack_probe_id))
        except Exception:
            probe_payload = None
        if isinstance(probe_payload, dict):
            status_code = _probe_status_code(probe_payload)
            if status_code is not None:
                return status_code < 400

    confidence_score = getattr(artifact, "confidence_score", None)
    if isinstance(confidence_score, (int, float)):
        return float(confidence_score) >= 0.95
    return False


def _probe_status_code(probe_payload: dict[str, object]) -> int | None:
    response = probe_payload.get("response")
    if not isinstance(response, dict):
        return None
    raw_status_code = response.get("status_code", response.get("status"))
    if isinstance(raw_status_code, bool):
        return None
    if isinstance(raw_status_code, int):
        return raw_status_code
    if isinstance(raw_status_code, str) and raw_status_code.strip():
        try:
            return int(raw_status_code.strip())
        except ValueError:
            return None
    return None


def _blast_radius_follow_up_payloads(
    *,
    scan_id: str,
    finding_id: str,
    source_endpoint_pattern: str | None,
    asset_map: object,
    secret_kind: str,
    secret_value: str,
) -> list[tuple[str, dict[str, object]]]:
    del scan_id
    from execution_plane.crawler.asset_map import AssetMap as RuntimeAssetMap
    from execution_plane.crawler.asset_map import Endpoint as RuntimeEndpoint
    from execution_plane.planner.secret_blast_radius import BlastRadiusSelector

    runtime_asset_map = RuntimeAssetMap(endpoints=[])
    raw_endpoints = getattr(asset_map, "endpoints", [])
    if not isinstance(raw_endpoints, list):
        return []

    for endpoint in raw_endpoints:
        url_pattern = getattr(endpoint, "url_pattern", None)
        method = getattr(endpoint, "method", None)
        auth_required = getattr(endpoint, "auth_required", False)
        if not isinstance(url_pattern, str) or not isinstance(method, str):
            continue
        runtime_asset_map.endpoints.append(
            RuntimeEndpoint(
                url_pattern=url_pattern,
                method=method,
                in_scope=True,
                auth_required=bool(auth_required),
                parameters=[],
            )
        )

    selected = BlastRadiusSelector(runtime_asset_map, source_endpoint_pattern=source_endpoint_pattern).select()
    payloads: list[tuple[str, dict[str, object]]] = []
    for index, endpoint in enumerate(selected):
        payloads.append(
            (
                f"impact.blast_radius.{secret_kind}.{finding_id}.{index}",
                {
                    "probe_type": "impact_secret_blast_radius",
                    "parent_finding_id": finding_id,
                    "secret_kind": secret_kind,
                    "secret_value": secret_value,
                    "target_url": endpoint["url_pattern"],
                    "target_method": endpoint["method"],
                    "priority_rank": endpoint["priority_rank"],
                    "safe_mode": True,
                    "goal": "map blast radius of active secret across read-only endpoints",
                },
            )
        )
    return payloads


def _extract_source_endpoint_pattern(probe_payload: dict[str, object]) -> str | None:
    from execution_plane.crawler.asset_map import normalize_url_pattern

    request = probe_payload.get("request")
    if not isinstance(request, dict):
        return None
    request_url = request.get("url")
    if not isinstance(request_url, str) or not request_url:
        return None
    return normalize_url_pattern(request_url)


def _extract_replayable_secret(probe_payload: dict[str, object]) -> tuple[str, str] | None:
    import json
    import re

    response = probe_payload.get("response")
    if not isinstance(response, dict):
        return None
    body = response.get("body")
    if not isinstance(body, str):
        body = json.dumps(body, default=str)

    bearer_match = re.search(r"(?i)\b(?:bearer\s+)?(eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)\b", body)
    if bearer_match:
        return ("bearer", bearer_match.group(1))

    token_match = re.search(
        r"(?i)(?:access[_-]?token|refresh[_-]?token|session[_-]?token|jwt)\s*[\"']?\s*[:=]\s*[\"']?([a-z0-9\-\._~\+/=]{16,})",
        body,
    )
    if token_match:
        return ("bearer", token_match.group(1))

    api_key_match = re.search(
        r"(?i)(?:api[_-]?key|client[_-]?secret|secret)\s*[\"']?\s*[:=]\s*[\"']?([a-z0-9_\-\.=]{16,})",
        body,
    )
    if api_key_match:
        return ("api_key", api_key_match.group(1))

    return None


async def _validate_and_score_evidence(*, scan_uuid: object, redis_connection: object, logger: object) -> None:
    from control_plane.finding_scorer import _score_artifact_async
    from execution_plane.planner.decision_log import FeedbackPayload, TaskOutcome
    from execution_plane.planner.planner import rq_enqueue_replan
    from execution_plane.validator.validator import ExploitValidator
    from storage.evidence.store import EvidenceStore

    class _InlineFindingQueue:
        def __init__(self) -> None:
            self.jobs: list[tuple[str, str, dict[str, object]]] = []

        def enqueue(self, _job_path: str, scan_id: str, finding_id: str, artifact_payload: dict[str, object]) -> None:
            self.jobs.append((scan_id, finding_id, artifact_payload))

    inline_queue = _InlineFindingQueue()
    validator = ExploitValidator(redis_client=redis_connection, evidence_store=EvidenceStore())
    validator._finding_queue = inline_queue
    sensitive_followup_endpoints: set[str] = set()
    scan_id_str = str(scan_uuid)

    processed_messages = 0
    while True:
        processed = await validator.process_once(scan_uuid)
        if hasattr(validator, "drain_feedback"):
            drained = validator.drain_feedback()
            await _forward_feedback_to_replan(
                scan_id=scan_id_str,
                feedback_items=drained,
                sensitive_followup_endpoints=sensitive_followup_endpoints,
                logger=logger,
                rq_enqueue_replan_fn=rq_enqueue_replan,
                task_outcome=TaskOutcome,
                feedback_payload_cls=FeedbackPayload,
            )
        if processed == 0:
            break
        processed_messages += processed

    if hasattr(validator, "drain_feedback"):
        drained = validator.drain_feedback()
        await _forward_feedback_to_replan(
            scan_id=scan_id_str,
            feedback_items=drained,
            sensitive_followup_endpoints=sensitive_followup_endpoints,
            logger=logger,
            rq_enqueue_replan_fn=rq_enqueue_replan,
            task_outcome=TaskOutcome,
            feedback_payload_cls=FeedbackPayload,
        )

    for score_scan_id, finding_id, artifact_payload in inline_queue.jobs:
        await _score_artifact_async(
            scan_id=score_scan_id,
            finding_id=finding_id,
            artifact_payload=artifact_payload,
        )

    logger.info(
        "scan_evidence_validated",
        scan_id=str(scan_uuid),
        evidence_messages=processed_messages,
        scoring_jobs=len(inline_queue.jobs),
    )


async def _forward_feedback_to_replan(
    *,
    scan_id: str,
    feedback_items: list[object],
    sensitive_followup_endpoints: set[str],
    logger: object,
    rq_enqueue_replan_fn: object,
    task_outcome: object,
    feedback_payload_cls: object,
) -> None:
    task_outcome_no_signal = getattr(task_outcome, "no_signal", "no_signal")
    task_outcome_needs_followup = getattr(task_outcome, "needs_followup", "needs_followup")
    is_active = await _scan_is_active(scan_id)
    for item in feedback_items:
        if not isinstance(item, feedback_payload_cls):
            continue
        if item.outcome != task_outcome_no_signal:
            rq_enqueue_replan_fn(scan_id, item)

        finding_class = str(item.finding_class).lower()
        if finding_class not in {"sensitive_exposure", "secret_exposure"}:
            continue
        if float(item.confidence) < 0.5:
            continue
        endpoint = str(item.endpoint)
        if endpoint in sensitive_followup_endpoints or not is_active:
            continue

        sensitive_followup_endpoints.add(endpoint)
        rq_enqueue_replan_fn(
            scan_id,
            feedback_payload_cls(
                outcome=task_outcome_needs_followup,
                scan_id=scan_id,
                task_id=str(item.task_id),
                endpoint=endpoint,
                finding_class=str(item.finding_class),
                confidence=float(item.confidence),
                follow_up_hints=["replay_with_token", "blast_radius_map"],
                parent_evidence_ref=item.parent_evidence_ref,
                metadata=dict(item.metadata),
            ),
        )
        logger.info(
            "sensitive_exposure_followup_replan_enqueued",
            scan_id=scan_id,
            endpoint=endpoint,
            task_id=str(item.task_id),
        )


async def _scan_is_active(scan_id: str) -> bool:
    from uuid import UUID

    from sqlalchemy import select
    from storage.db.models import Scan, ScanStatus
    from storage.db.session import AsyncSessionLocal

    try:
        async with AsyncSessionLocal() as db:
            result = await db.execute(select(Scan.status).where(Scan.id == UUID(scan_id)))
            status = result.scalar_one_or_none()
            return status in {ScanStatus.created, ScanStatus.running}
    except Exception:
        return False
