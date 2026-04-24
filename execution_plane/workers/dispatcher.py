from __future__ import annotations
# dispatcher.py - RQ jobs for attack dispatch and scan finalization

AUTONOMOUS_ATTACK_ROUNDS_ENV = "AUTONOMOUS_ATTACK_ROUNDS"
DEFAULT_AUTONOMOUS_ATTACK_ROUNDS = 2


def dispatch_attack_tasks(scan_id: str) -> None:
    import asyncio

    asyncio.run(_dispatch_attack_tasks_async(scan_id))


async def _dispatch_attack_tasks_async(scan_id: str) -> None:
    import os
    from uuid import UUID

    import structlog
    from redis import Redis
    from rq import Queue
    from rq.job import Dependency
    from sqlalchemy import select
    from storage.db.models import AttackTask, AttackTaskStatus
    from storage.db.session import AsyncSessionLocal

    logger = structlog.get_logger(__name__)
    scan_uuid = UUID(scan_id)

    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(AttackTask).where(
                AttackTask.scan_id == scan_uuid,
                AttackTask.status == AttackTaskStatus.pending,
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

    jobs = [queue.enqueue(execute_attack, str(task.id)) for task in pending_tasks]

    queue.enqueue(
        finalize_scan,
        scan_id,
        depends_on=Dependency(jobs=jobs, allow_failure=True),
    )

    logger.info("attack_tasks_dispatched", scan_id=scan_id, task_count=len(pending_tasks))


def execute_attack(attack_task_id: str) -> None:
    import asyncio

    asyncio.run(_execute_attack_async(attack_task_id))


async def _execute_attack_async(attack_task_id: str) -> None:
    from uuid import UUID

    import structlog
    from control_plane.auth_manager import AuthManager, default_pause_scan
    from execution_plane.workers.attack_worker import AttackWorker
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
                raise RuntimeError("Auth context is not initialized")
            session_snapshot = _session_snapshot_from_auth_context(auth_context, scan.id)
            manager._session_snapshot = session_snapshot
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
            await worker.execute(task, session_snapshot)
            task.status = AttackTaskStatus.done
            await db.commit()
        except Exception:
            logger.exception("attack_task_execution_failed", attack_task_id=attack_task_id, scan_id=str(scan.id))
            task.status = AttackTaskStatus.failed
            await db.commit()
        finally:
            await manager.close()


def _session_snapshot_from_auth_context(auth_context: object, scan_id: object) -> object:
    from datetime import UTC, datetime
    from typing import Any
    from uuid import UUID

    from control_plane.auth_manager import SessionSnapshot, _decrypt_snapshot_field

    scan_uuid = scan_id if isinstance(scan_id, UUID) else UUID(str(scan_id))
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


def finalize_scan(scan_id: str) -> None:
    import asyncio

    asyncio.run(_finalize_scan_async(scan_id))


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
    max_rounds = _autonomous_attack_rounds(os.getenv(AUTONOMOUS_ATTACK_ROUNDS_ENV))
    for round_index in range(max_rounds + 1):
        await _validate_and_score_evidence(scan_uuid=scan_uuid, redis_connection=connection, logger=logger)
        if round_index >= max_rounds:
            break

        follow_up_task_ids = await _create_autonomous_follow_up_tasks(scan_uuid=scan_uuid, logger=logger)
        if not follow_up_task_ids:
            break

        logger.info(
            "autonomous_attack_followups_executing",
            scan_id=str(scan_uuid),
            round=round_index + 1,
            task_count=len(follow_up_task_ids),
        )
        for task_id in follow_up_task_ids:
            await _execute_attack_async(str(task_id))

    async with AsyncSessionLocal() as db:
        from control_plane.orchestrator import ScanOrchestrator
        from control_plane.reporting import ReportingService
        from storage.evidence.store import EvidenceStore

        evidence_store = EvidenceStore()
        reporting_service = ReportingService(db=db, evidence_store=evidence_store)
        orchestrator = ScanOrchestrator(AsyncSessionLocal, reporting_service)
        await orchestrator.on_all_validated(scan_uuid)

    logger.info("scan_finalized", scan_id=scan_id)


def _autonomous_attack_rounds(raw_value: object) -> int:
    if raw_value is None:
        return DEFAULT_AUTONOMOUS_ATTACK_ROUNDS
    try:
        parsed = int(str(raw_value))
    except ValueError:
        return DEFAULT_AUTONOMOUS_ATTACK_ROUNDS
    return min(max(parsed, 0), 5)


async def _create_autonomous_follow_up_tasks(*, scan_uuid: object, logger: object) -> list[object]:
    import json

    from sqlalchemy import select
    from sqlalchemy.orm import selectinload
    from storage.db.models import AttackTask, AttackTaskStatus, Finding, ProofArtifact
    from storage.db.session import AsyncSessionLocal

    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(Finding)
            .where(Finding.scan_id == scan_uuid)
            .options(
                selectinload(Finding.affected_endpoint),
                selectinload(Finding.proof_artifacts).selectinload(ProofArtifact.attack_task),
            )
        )
        findings = result.scalars().all()

        created_task_ids: list[object] = []
        for finding in findings:
            if finding.attack_class != "sensitive_exposure":
                continue
            endpoint = finding.affected_endpoint
            if endpoint is None:
                continue

            evidence_notes = " ".join(str(artifact.evidence_notes or "") for artifact in finding.proof_artifacts)
            follow_ups = _sensitive_exposure_follow_up_payloads(
                finding_id=str(finding.id),
                evidence_notes=evidence_notes,
            )
            for target_parameter, payload in follow_ups:
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
                    hypothesis=json.dumps(payload, sort_keys=True),
                    priority_score=99.0,
                    status=AttackTaskStatus.pending,
                )
                db.add(task)
                await db.flush()
                created_task_ids.append(task.id)

        await db.commit()

    logger.info(
        "autonomous_attack_followups_created",
        scan_id=str(scan_uuid),
        task_count=len(created_task_ids),
    )
    return created_task_ids


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


async def _validate_and_score_evidence(*, scan_uuid: object, redis_connection: object, logger: object) -> None:
    from control_plane.finding_scorer import _score_artifact_async
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

    processed_messages = 0
    while True:
        processed = await validator.process_once(scan_uuid)
        if processed == 0:
            break
        processed_messages += processed

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
