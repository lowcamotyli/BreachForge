from __future__ import annotations
# dispatcher.py - RQ jobs for attack dispatch and scan finalization

AUTONOMOUS_ATTACK_ROUNDS_ENV = "AUTONOMOUS_ATTACK_ROUNDS"
LIFECYCLE_SECOND_CHECK_DELAY_ENV = "LIFECYCLE_SECOND_CHECK_DELAY_SECONDS"
LIFECYCLE_SECOND_CHECK_CAP_SECONDS = 300
DEFAULT_LIFECYCLE_SECOND_CHECK_DELAY = 0
DEFAULT_AUTONOMOUS_ATTACK_ROUNDS = 2


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
