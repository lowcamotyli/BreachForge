from __future__ import annotations

import asyncio
import json
import os
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any
from uuid import NAMESPACE_URL, UUID, uuid4, uuid5

import structlog
from redis import Redis
from rq import Queue
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from execution_plane.validator.strategies.auth_bypass import AuthBypassStrategy
from execution_plane.validator.strategies.base import ValidationStrategy
from execution_plane.validator.strategies.bola import BolaStrategy
from execution_plane.validator.strategies.injection import InjectionStrategy
from execution_plane.validator.strategies.misconfiguration import MisconfigurationStrategy
from execution_plane.validator.strategies.privilege_escalation import PrivilegeEscalationStrategy
from execution_plane.validator.strategies.rate_limit_abuse import RateLimitAbuseStrategy
from execution_plane.validator.strategies.session_misuse import SessionMisuseStrategy
from execution_plane.validator.strategies.sensitive_exposure import SensitiveExposureStrategy
from execution_plane.validator.strategies.workflow_abuse import WorkflowAbuseStrategy
from execution_plane.validator.state_diff import compute_diff
from storage.db.models import AttackTask, ProofArtifact, RawProbe
from storage.db.session import AsyncSessionLocal
from storage.evidence.store import EvidenceStore
from storage.evidence.state_store import StateSnapshot

try:
    from execution_plane.validator.strategies.tenant_isolation import TenantIsolationStrategy as _TenantIsolationStrategyBase
except ModuleNotFoundError:
    _TenantIsolationStrategyBase = BolaStrategy

if TYPE_CHECKING:
    from control_plane.auth_manager import IdentityContext

logger = structlog.get_logger(__name__)

DEFAULT_PROOF_CONFIDENCE_THRESHOLD = float(os.getenv("DEFAULT_PROOF_CONFIDENCE_THRESHOLD", "0.85"))
LOW_CONFIDENCE_STORE_THRESHOLD = 0.50
SUPPORTED_ATTACK_CLASSES: set[str] = {
    "bola",
    "tenant_isolation",
    "auth_bypass",
    "privilege_escalation",
    "sensitive_exposure",
    "workflow_abuse",
    "injection",
    "session_misuse",
    "rate_limit_abuse",
    "misconfiguration",
}


class _BolaStrategy(BolaStrategy):
    def expected_attack_class(self) -> str:
        return "bola"


class _TenantIsolationStrategy(_TenantIsolationStrategyBase):
    def expected_attack_class(self) -> str:
        return "tenant_isolation"


class _AuthBypassStrategy(AuthBypassStrategy):
    def expected_attack_class(self) -> str:
        return "auth_bypass"


class _PrivilegeEscalationStrategy(PrivilegeEscalationStrategy):
    def expected_attack_class(self) -> str:
        return "privilege_escalation"


class _SensitiveExposureStrategy(SensitiveExposureStrategy):
    def expected_attack_class(self) -> str:
        return "sensitive_exposure"


class _WorkflowAbuseStrategy(WorkflowAbuseStrategy):
    def expected_attack_class(self) -> str:
        return "workflow_abuse"


class _InjectionStrategy(InjectionStrategy):
    def expected_attack_class(self) -> str:
        return "injection"


class _SessionMisuseStrategy(SessionMisuseStrategy):
    def expected_attack_class(self) -> str:
        return "session_misuse"


class _RateLimitAbuseStrategy(RateLimitAbuseStrategy):
    def expected_attack_class(self) -> str:
        return "rate_limit_abuse"


class _MisconfigurationStrategy(MisconfigurationStrategy):
    def expected_attack_class(self) -> str:
        return "misconfiguration"


class ExploitValidator:
    def __init__(
        self,
        redis_client: Redis | None = None,
        evidence_store: EvidenceStore | None = None,
        strategies: dict[str, ValidationStrategy] | None = None,
        proof_threshold: float = DEFAULT_PROOF_CONFIDENCE_THRESHOLD,
        low_confidence_threshold: float = LOW_CONFIDENCE_STORE_THRESHOLD,
    ) -> None:
        redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
        self._redis = redis_client or Redis.from_url(redis_url, decode_responses=True)
        self._finding_queue = Queue(
            name=os.getenv("RQ_FINDING_SCORER_QUEUE", "finding_scorer"),
            connection=self._redis,
        )
        self._evidence_store = evidence_store or EvidenceStore()
        self._strategies = strategies or self._default_strategies()
        self._validate_strategy_registry()
        self._proof_threshold = proof_threshold
        self._low_confidence_threshold = low_confidence_threshold
        self._last_stream_ids: dict[str, str] = {}
        self._probe_cache: dict[str, RawProbe] = {}
        self._probe_cache_order: list[str] = []
        self._max_probe_cache_size = 5000

    async def run(self, scan_id: UUID | str) -> None:
        stream_key = self._stream_key(scan_id)
        self._last_stream_ids.setdefault(stream_key, "0-0")

        while True:
            entries = await asyncio.to_thread(
                self._redis.xread,
                {stream_key: self._last_stream_ids[stream_key]},
                block=1000,
                count=100,
            )

            if not entries:
                continue

            for returned_stream_key, messages in entries:
                for stream_message_id, payload in messages:
                    self._last_stream_ids[returned_stream_key] = stream_message_id
                    await self._process_message(scan_id, stream_message_id, payload)

    async def process_once(self, scan_id: UUID | str) -> int:
        stream_key = self._stream_key(scan_id)
        self._last_stream_ids.setdefault(stream_key, "0-0")

        entries = await asyncio.to_thread(
            self._redis.xread,
            {stream_key: self._last_stream_ids[stream_key]},
            block=1,
            count=100,
        )

        processed = 0
        for returned_stream_key, messages in entries:
            for stream_message_id, payload in messages:
                self._last_stream_ids[returned_stream_key] = stream_message_id
                await self._process_message(scan_id, stream_message_id, payload)
                processed += 1

        return processed

    async def _process_message(self, scan_id: UUID | str, stream_message_id: str, payload: dict[str, str]) -> None:
        attack_probe = self._probe_from_stream_payload(payload=payload, stream_message_id=stream_message_id)

        attack_task = await self._load_attack_task(attack_probe.attack_task_id)
        if attack_task is None:
            logger.warning(
                "validator_attack_task_missing",
                scan_id=str(scan_id),
                attack_task_id=str(attack_probe.attack_task_id),
                stream_message_id=stream_message_id,
            )
            return

        strategy = self._strategies.get(attack_task.attack_class)
        if strategy is None:
            if attack_task.attack_class in SUPPORTED_ATTACK_CLASSES:
                logger.error(
                    "validator_supported_strategy_missing",
                    scan_id=str(scan_id),
                    attack_class=attack_task.attack_class,
                    attack_task_id=str(attack_task.id),
                )
                return
            logger.info(
                "validator_no_strategy",
                scan_id=str(scan_id),
                attack_class=attack_task.attack_class,
                attack_task_id=str(attack_task.id),
            )
            return

        control_probe = self._resolve_control_probe(attack_probe)
        artifact = self.validate(strategy=strategy, attack_probe=attack_probe, control_probe=control_probe)
        estimated_confidence = self._estimate_confidence(
            strategy=strategy,
            attack_probe=attack_probe,
            control_probe=control_probe,
            artifact=artifact,
        )

        if artifact is None:
            if estimated_confidence >= self._low_confidence_threshold:
                low_confidence_finding_id = f"low-confidence-{attack_task.attack_class}"
                self._evidence_store.write_probe(scan_id=scan_id, finding_id=low_confidence_finding_id, probe=attack_probe)
                logger.info(
                    "validator_low_confidence_probe_stored",
                    scan_id=str(scan_id),
                    attack_task_id=str(attack_task.id),
                    confidence=estimated_confidence,
                )
            else:
                logger.info(
                    "validator_probe_discarded",
                    scan_id=str(scan_id),
                    attack_task_id=str(attack_task.id),
                    confidence=estimated_confidence,
                )
            return

        if artifact.confidence_score < self._proof_threshold:
            if artifact.confidence_score >= self._low_confidence_threshold:
                low_confidence_finding_id = f"low-confidence-{attack_task.attack_class}"
                self._evidence_store.write_probe(scan_id=scan_id, finding_id=low_confidence_finding_id, probe=attack_probe)
                logger.info(
                    "validator_low_confidence_artifact_dropped",
                    scan_id=str(scan_id),
                    attack_task_id=str(attack_task.id),
                    confidence=artifact.confidence_score,
                )
            return

        finding_id = artifact.finding_id or uuid4()
        artifact.finding_id = finding_id
        if artifact.id is None:
            artifact.id = uuid4()

        await self._persist_probes_to_db(attack_probe=attack_probe, control_probe=control_probe)

        probe_key = self._evidence_store.write_probe(scan_id=scan_id, finding_id=finding_id, probe=attack_probe)
        artifact_key = self._evidence_store.write_artifact(scan_id=scan_id, finding_id=finding_id, artifact=artifact)

        self._finding_queue.enqueue(
            "control_plane.finding_scorer.score_artifact",
            str(scan_id),
            str(finding_id),
            {
                "artifact_id": str(artifact.id),
                "attack_task_id": str(artifact.attack_task_id),
                "proof_type": artifact.proof_type,
                "confidence_score": artifact.confidence_score,
                "attack_probe_id": str(artifact.attack_probe_id),
                "control_probe_id": str(artifact.control_probe_id) if artifact.control_probe_id else None,
                "summary": artifact.summary,
                "evidence_notes": artifact.evidence_notes,
                "identity_role": artifact.identity_role,
                "state_diff": artifact.state_diff,
                "artifact_key": artifact_key,
                "probe_key": probe_key,
            },
        )

        logger.info(
            "validator_artifact_published_to_finding_scorer",
            scan_id=str(scan_id),
            finding_id=str(finding_id),
            attack_task_id=str(attack_task.id),
            proof_type=artifact.proof_type,
            confidence=artifact.confidence_score,
        )

    def validate(
        self,
        strategy: ValidationStrategy,
        attack_probe: RawProbe,
        control_probe: RawProbe | None,
        identity_context: IdentityContext | None = None,
        before_snapshot: StateSnapshot | None = None,
        after_snapshot: StateSnapshot | None = None,
    ) -> ProofArtifact | None:
        artifact = strategy.validate(attack_probe=attack_probe, control_probe=control_probe)
        if artifact is None:
            return None

        identity_role: str | None = None
        if identity_context is not None:
            from control_plane.auth_manager import IdentityContext as _IdentityContext

            if not isinstance(identity_context, _IdentityContext):
                raise TypeError("identity_context must be IdentityContext")
            identity_role = identity_context.role.value

        artifact.identity_role = identity_role

        if before_snapshot is not None and after_snapshot is not None:
            state_diff = compute_diff(before=before_snapshot, after=after_snapshot)
            artifact.state_diff = {
                "added": state_diff.added,
                "removed": state_diff.removed,
                "changed": {key: [value[0], value[1]] for key, value in state_diff.changed.items()},
            }
        else:
            artifact.state_diff = None

        return artifact

    async def _load_attack_task(self, attack_task_id: UUID) -> AttackTask | None:
        async with AsyncSessionLocal() as session:
            return await self._select_attack_task(session, attack_task_id)

    async def _persist_probes_to_db(self, attack_probe: RawProbe, control_probe: RawProbe | None) -> None:
        async with AsyncSessionLocal() as session:
            if control_probe is not None:
                await session.merge(control_probe)
                await session.flush()
            await session.merge(attack_probe)
            await session.commit()

    async def _select_attack_task(self, session: AsyncSession, attack_task_id: UUID) -> AttackTask | None:
        statement = select(AttackTask).where(AttackTask.id == attack_task_id)
        result = await session.execute(statement)
        return result.scalar_one_or_none()

    def _probe_from_stream_payload(self, payload: dict[str, str], stream_message_id: str) -> RawProbe:
        timestamp_raw = payload.get("timestamp")
        timestamp = self._parse_timestamp(timestamp_raw)

        request_payload = self._parse_json_dict(payload.get("request"))
        response_payload = self._parse_json_dict(payload.get("response"))

        attack_task_raw = payload.get("attack_task_id")
        if not attack_task_raw:
            raise ValueError("Missing attack_task_id in evidence stream payload")

        probe_id_raw = payload.get("probe_id")
        control_probe_id_raw = payload.get("control_probe_id")

        probe = RawProbe(
            id=self._parse_uuid(probe_id_raw) if probe_id_raw else self._probe_id_from_stream_id(stream_message_id),
            attack_task_id=self._parse_uuid(attack_task_raw),
            worker_id=payload.get("worker_id", "unknown-worker"),
            timestamp=timestamp,
            request=request_payload,
            response=response_payload,
            control_probe_id=self._parse_uuid(control_probe_id_raw) if control_probe_id_raw else None,
        )

        self._remember_probe(probe)
        return probe

    def _resolve_control_probe(self, attack_probe: RawProbe) -> RawProbe | None:
        if attack_probe.control_probe_id is not None:
            return self._probe_cache.get(str(attack_probe.control_probe_id))

        for cached_probe in reversed(self._probe_cache.values()):
            if cached_probe.attack_task_id == attack_probe.attack_task_id and cached_probe.id != attack_probe.id:
                return cached_probe

        return None

    def _estimate_confidence(
        self,
        strategy: ValidationStrategy,
        attack_probe: RawProbe,
        control_probe: RawProbe | None,
        artifact: ProofArtifact | None,
    ) -> float:
        if artifact is not None:
            return artifact.confidence_score

        if isinstance(strategy, (BolaStrategy, _TenantIsolationStrategyBase)):
            if control_probe is None:
                return 0.0
            attack_body = strategy._extract_semantic_body(attack_probe.response)
            control_body = strategy._extract_semantic_body(control_probe.response)
            if attack_body != control_body:
                return 0.90
            attack_status = strategy._extract_status(attack_probe.response)
            control_status = strategy._extract_status(control_probe.response)
            if attack_status != control_status:
                return 0.70

        return 0.0

    def _default_strategies(self) -> dict[str, ValidationStrategy]:
        return {
            "bola": _BolaStrategy(),
            "tenant_isolation": _TenantIsolationStrategy(),
            "auth_bypass": _AuthBypassStrategy(),
            "privilege_escalation": _PrivilegeEscalationStrategy(),
            "sensitive_exposure": _SensitiveExposureStrategy(),
            "workflow_abuse": _WorkflowAbuseStrategy(),
            "injection": _InjectionStrategy(),
            "session_misuse": _SessionMisuseStrategy(),
            "rate_limit_abuse": _RateLimitAbuseStrategy(),
            "misconfiguration": _MisconfigurationStrategy(),
        }

    def _validate_strategy_registry(self) -> None:
        for attack_class, strategy in self._strategies.items():
            expected = strategy.expected_attack_class()
            if attack_class != expected:
                raise ValueError(
                    f"Validator strategy registry mismatch: key='{attack_class}' expected='{expected}' "
                    f"for {strategy.__class__.__name__}"
                )

    def _remember_probe(self, probe: RawProbe) -> None:
        key = str(probe.id)
        self._probe_cache[key] = probe
        self._probe_cache_order.append(key)

        while len(self._probe_cache_order) > self._max_probe_cache_size:
            oldest = self._probe_cache_order.pop(0)
            self._probe_cache.pop(oldest, None)

    def _parse_json_dict(self, raw_value: str | None) -> dict[str, Any]:
        if raw_value is None:
            return {}

        parsed = json.loads(raw_value)
        if not isinstance(parsed, dict):
            raise ValueError("Expected JSON object in stream payload")
        return parsed

    def _parse_timestamp(self, raw_value: str | None) -> datetime:
        if raw_value is None:
            return datetime.now(UTC)
        parsed = datetime.fromisoformat(raw_value)
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=UTC)
        return parsed

    def _parse_uuid(self, raw_value: str) -> UUID:
        return UUID(raw_value)

    def _probe_id_from_stream_id(self, stream_message_id: str) -> UUID:
        if not stream_message_id:
            return uuid4()
        return uuid5(NAMESPACE_URL, f"evidence-stream:{stream_message_id}")

    def _stream_key(self, scan_id: UUID | str) -> str:
        return f"evidence:{scan_id}"
