from __future__ import annotations

import asyncio
import inspect
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
from execution_plane.validator.strategies.bfla import BflaStrategy
from execution_plane.validator.strategies.bola import BolaStrategy
from execution_plane.validator.strategies.graphql import (
    GraphqlBatchStrategy,
    GraphqlDepthStrategy,
    GraphqlFieldSuggestionStrategy,
    GraphqlIntrospectionStrategy,
)
from execution_plane.validator.strategies.injection import InjectionStrategy
from execution_plane.validator.strategies.misconfiguration import MisconfigurationStrategy
from execution_plane.validator.strategies.oauth import (
    OauthErrorDisclosureStrategy,
    OauthRedirectStrategy,
    OauthStateCsrfStrategy,
    OauthTokenReuseStrategy,
)
from execution_plane.validator.strategies.privilege_escalation import PrivilegeEscalationStrategy
from execution_plane.validator.strategies.rate_limit_abuse import RateLimitAbuseStrategy
from execution_plane.validator.strategies.session_misuse import SessionMisuseStrategy
from execution_plane.validator.strategies.sensitive_exposure import SensitiveExposureStrategy
from execution_plane.validator.strategies.jwt_attack import JwtAttackStrategy
from execution_plane.validator.strategies.mass_assignment import ExcessiveExposureStrategy, MassAssignmentStrategy
from execution_plane.validator.strategies.ssrf import SsrfStrategy
from execution_plane.validator.strategies.workflow_abuse import WorkflowAbuseStrategy
from execution_plane.validator.strategies.nosql_injection import NoSqlInjectionStrategy
from execution_plane.validator.strategies.ssti import SstiStrategy
from execution_plane.validator.strategies.advanced_injection import (
    LdapInjectionStrategy,
    XpathInjectionStrategy,
    HeaderInjectionStrategy,
)
from execution_plane.validator.strategies.xxe import XxeClassicStrategy, XxeErrorStrategy, XxeBlindStrategy
from execution_plane.validator.strategies.deserialization import DeserializationProbeStrategy, YamlDeserializationStrategy
from execution_plane.validator.strategies.http_smuggling import (
    HttpSmugglingStrategy,
    HttpMethodOverrideStrategy,
    HttpParameterPollutionStrategy,
)
from execution_plane.validator.strategies.cache_poisoning import CachePoisoningStrategy, WebCacheDeceptionStrategy
from execution_plane.validator.strategies.cookie_analysis import CookieAnalysisStrategy
from execution_plane.validator.strategies.api_inventory import (
    ApiInventoryStrategy,
    ApiDocExposureStrategy,
    BackupFileExposureStrategy,
)
from execution_plane.validator.strategies.csrf import CsrfStrategy
from execution_plane.validator.strategies.business_logic_advanced import (
    NegativeValueStrategy,
    IntegerOverflowStrategy,
    PriceManipulationStrategy,
    AccountEnumerationTimingStrategy,
    InventoryReservationStrategy,
)
from execution_plane.validator.strategies.security_headers import (
    SecurityHeadersStrategy,
    CorsAnalysisStrategy,
    TlsAnalysisStrategy,
)
from execution_plane.validator.strategies.race_advanced import (
    LimitOverrideRaceStrategy,
    DoubleSpendStrategy,
    IdempotencyBypassStrategy,
    DistributedLockEvasionStrategy,
)
from execution_plane.validator.strategies.race_condition import RaceConditionStrategy
from execution_plane.validator.state_diff import compute_diff
from execution_plane.planner.decision_log import FeedbackPayload, FeedbackReason, TaskOutcome
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
_FORBIDDEN_IDENTITY_LABEL_TOKENS: tuple[str, ...] = ("token", "cookie", "bearer", "authorization", "password", "secret")
_RACE_RECONCILE_CLASSES: frozenset[str] = frozenset(
    {
        "race_condition",
        "double_spend",
        "limit_override_race",
        "inventory_reservation_abuse",
        "idempotency_bypass",
        "distributed_lock_evasion",
    }
)
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
    "jwt_attack",
    "ssrf",
    "mass_assignment",
    "excessive_exposure",
    "bfla",
    "graphql_introspection",
    "graphql_batch",
    "graphql_field_suggestion",
    "graphql_depth",
    "oauth_redirect",
    "oauth_state_csrf",
    "oauth_token_reuse",
    "oauth_error_disclosure",
    "xxe_classic",
    "xxe_error",
    "xxe_blind",
    "deserialization_probe",
    "yaml_deserialization",
    "http_smuggling",
    "web_cache_deception",
    "cache_poisoning",
    "http_method_override",
    "http_parameter_pollution",
    "cookie_analysis",
    "csrf",
    "negative_value",
    "integer_overflow",
    "price_manipulation",
    "account_enumeration_timing",
    "inventory_reservation",
    "security_headers",
    "cors_analysis",
    "tls_analysis",
    "race_condition",
}

_OUTCOME_TO_REASON: dict[TaskOutcome, FeedbackReason] = {
    TaskOutcome.no_signal: FeedbackReason.no_signal,
    TaskOutcome.blocked: FeedbackReason.auth_drift,
    TaskOutcome.unsafe_blocked: FeedbackReason.unsafe_blocked,
    TaskOutcome.interesting: FeedbackReason.interesting_diff,
    TaskOutcome.needs_followup: FeedbackReason.state_changed,
    TaskOutcome.success: FeedbackReason.interesting_diff,
}


def _outcome_to_reason(outcome: TaskOutcome) -> FeedbackReason | None:
    return _OUTCOME_TO_REASON.get(outcome)


class _BolaStrategy(BolaStrategy):
    def expected_attack_class(self) -> str:
        return "bola"


class _BflaStrategy(BflaStrategy):
    def expected_attack_class(self) -> str:
        return "bfla"


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


class _JwtAttackStrategy(JwtAttackStrategy):
    def expected_attack_class(self) -> str:
        return "jwt_attack"


class _SsrfStrategy(SsrfStrategy):
    def expected_attack_class(self) -> str:
        return "ssrf"


class _MassAssignmentStrategy(MassAssignmentStrategy):
    def expected_attack_class(self) -> str:
        return "mass_assignment"


class _ExcessiveExposureStrategy(ExcessiveExposureStrategy):
    def expected_attack_class(self) -> str:
        return "excessive_exposure"


class _GraphqlIntrospectionStrategy(GraphqlIntrospectionStrategy):
    def expected_attack_class(self) -> str:
        return "graphql_introspection"


class _GraphqlBatchStrategy(GraphqlBatchStrategy):
    def expected_attack_class(self) -> str:
        return "graphql_batch"


class _GraphqlFieldSuggestionStrategy(GraphqlFieldSuggestionStrategy):
    def expected_attack_class(self) -> str:
        return "graphql_field_suggestion"


class _GraphqlDepthStrategy(GraphqlDepthStrategy):
    def expected_attack_class(self) -> str:
        return "graphql_depth"


class _OauthRedirectStrategy(OauthRedirectStrategy):
    def expected_attack_class(self) -> str:
        return "oauth_redirect"


class _OauthStateCsrfStrategy(OauthStateCsrfStrategy):
    def expected_attack_class(self) -> str:
        return "oauth_state_csrf"


class _OauthTokenReuseStrategy(OauthTokenReuseStrategy):
    def expected_attack_class(self) -> str:
        return "oauth_token_reuse"


class _OauthErrorDisclosureStrategy(OauthErrorDisclosureStrategy):
    def expected_attack_class(self) -> str:
        return "oauth_error_disclosure"


class _NoSqlInjectionStrategy(NoSqlInjectionStrategy):
    def expected_attack_class(self) -> str:
        return "nosql_injection"


class _SstiStrategy(SstiStrategy):
    def expected_attack_class(self) -> str:
        return "ssti"


class _LdapInjectionStrategy(LdapInjectionStrategy):
    def expected_attack_class(self) -> str:
        return "ldap_injection"


class _XpathInjectionStrategy(XpathInjectionStrategy):
    def expected_attack_class(self) -> str:
        return "xpath_injection"


class _HeaderInjectionStrategy(HeaderInjectionStrategy):
    def expected_attack_class(self) -> str:
        return "header_injection"


class _XxeClassicStrategy(XxeClassicStrategy):
    def expected_attack_class(self) -> str:
        return "xxe_classic"


class _XxeErrorStrategy(XxeErrorStrategy):
    def expected_attack_class(self) -> str:
        return "xxe_error"


class _XxeBlindStrategy(XxeBlindStrategy):
    def expected_attack_class(self) -> str:
        return "xxe_blind"


class _DeserializationProbeStrategy(DeserializationProbeStrategy):
    def expected_attack_class(self) -> str:
        return "deserialization_probe"


class _YamlDeserializationStrategy(YamlDeserializationStrategy):
    def expected_attack_class(self) -> str:
        return "yaml_deserialization"


class _HttpSmugglingStrategy(HttpSmugglingStrategy):
    def expected_attack_class(self) -> str:
        return "http_smuggling"


class _WebCacheDeceptionStrategy(WebCacheDeceptionStrategy):
    def expected_attack_class(self) -> str:
        return "web_cache_deception"


class _CachePoisoningStrategy(CachePoisoningStrategy):
    def expected_attack_class(self) -> str:
        return "cache_poisoning"


class _HttpMethodOverrideStrategy(HttpMethodOverrideStrategy):
    def expected_attack_class(self) -> str:
        return "http_method_override"


class _HttpParameterPollutionStrategy(HttpParameterPollutionStrategy):
    def expected_attack_class(self) -> str:
        return "http_parameter_pollution"


class _CookieAnalysisStrategy(CookieAnalysisStrategy):
    def expected_attack_class(self) -> str:
        return "cookie_analysis"


class _CsrfStrategy(CsrfStrategy):
    def expected_attack_class(self) -> str:
        return "csrf"


class _NegativeValueStrategy(NegativeValueStrategy):
    def expected_attack_class(self) -> str:
        return "negative_value"


class _IntegerOverflowStrategy(IntegerOverflowStrategy):
    def expected_attack_class(self) -> str:
        return "integer_overflow"


class _PriceManipulationStrategy(PriceManipulationStrategy):
    def expected_attack_class(self) -> str:
        return "price_manipulation"


class _AccountEnumerationTimingStrategy(AccountEnumerationTimingStrategy):
    def expected_attack_class(self) -> str:
        return "account_enumeration_timing"


class _InventoryReservationStrategy(InventoryReservationStrategy):
    def expected_attack_class(self) -> str:
        return "inventory_reservation"


class _SecurityHeadersStrategy(SecurityHeadersStrategy):
    def expected_attack_class(self) -> str:
        return "security_headers"


class _CorsAnalysisStrategy(CorsAnalysisStrategy):
    def expected_attack_class(self) -> str:
        return "cors_analysis"


class _TlsAnalysisStrategy(TlsAnalysisStrategy):
    def expected_attack_class(self) -> str:
        return "tls_analysis"


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
        self._feedback_buffer: list[FeedbackPayload] = []

    def drain_feedback(self) -> list[FeedbackPayload]:
        drained = self._feedback_buffer
        self._feedback_buffer = []
        return drained

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
        before_snap, after_snap = self._extract_state_snapshots_from_payload(
            payload=payload,
            scan_id=scan_id,
            attack_task_id=attack_probe.attack_task_id,
        )

        attack_task = await self._load_attack_task(attack_probe.attack_task_id)
        if attack_task is None:
            logger.warning(
                "validator_attack_task_missing",
                scan_id=str(scan_id),
                attack_task_id=str(attack_probe.attack_task_id),
                stream_message_id=stream_message_id,
            )
            return

        race_reconcile_passed = self._race_reconcile_passed(
            scan_id=scan_id,
            attack_task=attack_task,
            attack_probe=attack_probe,
        )
        if race_reconcile_passed is False:
            self._feedback_buffer.append(
                FeedbackPayload(
                    outcome=TaskOutcome.no_signal,
                    scan_id=str(scan_id),
                    task_id=str(attack_task.id),
                    endpoint=str(attack_task.endpoint_id),
                    finding_class=attack_task.attack_class,
                    confidence=0.0,
                    follow_up_hints=[],
                    parent_evidence_ref=None,
                    reason=FeedbackReason.no_signal,
                    metadata={"reconcile_required": True, "reconcile_passed": False},
                )
            )
            logger.info(
                "validator_race_probe_downgraded_no_signal",
                scan_id=str(scan_id),
                attack_task_id=str(attack_task.id),
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
        artifact = await self.validate(
            strategy=strategy,
            attack_probe=attack_probe,
            control_probe=control_probe,
            before_snapshot=before_snap,
            after_snapshot=after_snap,
        )
        if artifact is not None and strategy.requires_state_effect():
            state_diff_data = artifact.state_diff
            has_meaningful_diff = (
                state_diff_data is not None
                and isinstance(state_diff_data, dict)
                and any(bool(value) for value in state_diff_data.values())
            )
            if not has_meaningful_diff:
                artifact.confidence_score = min(artifact.confidence_score, 0.60)
                artifact.evidence_notes = (artifact.evidence_notes or "") + "; state_effect_required=no_diff_found"
        if artifact is not None and race_reconcile_passed is not None:
            artifact.evidence_notes = (
                f"{artifact.evidence_notes}; reconcile_required=true; "
                f"reconcile_passed={'true' if race_reconcile_passed else 'false'}"
            )
            setattr(
                artifact,
                "metadata",
                {
                    **(getattr(artifact, "metadata", {}) if isinstance(getattr(artifact, "metadata", None), dict) else {}),
                    "reconcile_required": True,
                    "reconcile_passed": race_reconcile_passed,
                },
            )
        artifact = await self._apply_differential_proof_gate(
            attack_task=attack_task,
            strategy=strategy,
            attack_probe=attack_probe,
            control_probe=control_probe,
            artifact=artifact,
        )
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
            self._emit_feedback_payload(
                scan_id=scan_id,
                attack_task=attack_task,
                attack_probe=attack_probe,
                artifact=None,
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
            self._emit_feedback_payload(
                scan_id=scan_id,
                attack_task=attack_task,
                attack_probe=attack_probe,
                artifact=artifact,
                confidence=artifact.confidence_score,
            )
            return

        self._emit_feedback_payload(
            scan_id=scan_id,
            attack_task=attack_task,
            attack_probe=attack_probe,
            artifact=artifact,
            confidence=artifact.confidence_score,
        )

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
                "identity_labels": getattr(artifact, "identity_labels", []),
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

    async def validate(
        self,
        strategy: ValidationStrategy,
        attack_probe: RawProbe,
        control_probe: RawProbe | None,
        identity_context: IdentityContext | None = None,
        before_snapshot: StateSnapshot | None = None,
        after_snapshot: StateSnapshot | None = None,
    ) -> ProofArtifact | None:
        artifact_or_awaitable = strategy.validate(attack_probe=attack_probe, control_probe=control_probe)
        artifact = (
            await artifact_or_awaitable
            if inspect.isawaitable(artifact_or_awaitable)
            else artifact_or_awaitable
        )
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

    async def _apply_differential_proof_gate(
        self,
        attack_task: AttackTask,
        strategy: ValidationStrategy,
        attack_probe: RawProbe,
        control_probe: RawProbe | None,
        artifact: ProofArtifact | None,
    ) -> ProofArtifact | None:
        hypothesis = self._parse_hypothesis_config(attack_task.hypothesis)
        if not bool(hypothesis.get("differential_probe")):
            return artifact

        attacker_identity = self._sanitize_identity_label(hypothesis.get("identity_selector"))
        owner_identity = self._sanitize_identity_label(hypothesis.get("owner_identity"))

        probes: list[tuple[RawProbe, str | None]] = [(attack_probe, attacker_identity)]
        if control_probe is not None:
            control_task = await self._load_attack_task(control_probe.attack_task_id)
            control_hypothesis = self._parse_hypothesis_config(control_task.hypothesis) if control_task is not None else {}
            control_identity = self._sanitize_identity_label(control_hypothesis.get("identity_selector"))
            probes.append((control_probe, control_identity))
            if owner_identity is None and control_identity != attacker_identity:
                owner_identity = control_identity

        attacker_probe = self._probe_for_identity(probes, attacker_identity)
        owner_probe = self._probe_for_identity(probes, owner_identity)
        identity_labels = [label for label in (attacker_identity, owner_identity) if isinstance(label, str)]

        if attacker_probe is None or owner_probe is None:
            return self._downgrade_or_attach_identity_labels(
                artifact=artifact,
                confidence=0.20,
                identity_labels=identity_labels,
                notes="differential_probe=missing_pair",
            )

        attacker_status = self._extract_status_from_probe(attack_probe=attacker_probe)
        owner_status = self._extract_status_from_probe(attack_probe=owner_probe)
        attacker_body = self._normalize_probe_body(attacker_probe)
        owner_body = self._normalize_probe_body(owner_probe)

        same_body = attacker_body == owner_body
        attacker_is_denied = attacker_status in {401, 403}
        owner_is_success = owner_status == 200
        both_success = attacker_status == 200 and owner_status == 200

        if both_success and same_body:
            finding = artifact or ProofArtifact(
                attack_task_id=attack_probe.attack_task_id,
                finding_id=uuid5(NAMESPACE_URL, f"differential:{attack_task.id}:{owner_identity}:{attacker_identity}"),
                proof_type=strategy.expected_proof_type(),
                confidence_score=max(self._proof_threshold, 0.90),
                attack_probe_id=attack_probe.id,
                control_probe_id=control_probe.id if control_probe is not None else None,
                summary="Differential proof indicates unauthorized identity-level access parity.",
                evidence_notes="differential_probe=confirmed; attacker_owner_response_parity=true",
            )
            finding.confidence_score = max(finding.confidence_score, self._proof_threshold, 0.90)
            self._set_identity_labels(finding, identity_labels)
            finding.evidence_notes = f"{finding.evidence_notes}; identity_labels={','.join(identity_labels)}"
            return finding

        if attacker_is_denied and owner_is_success:
            return self._downgrade_or_attach_identity_labels(
                artifact=artifact,
                confidence=0.10,
                identity_labels=identity_labels,
                notes="differential_probe=access_control_enforced",
            )

        return self._downgrade_or_attach_identity_labels(
            artifact=artifact,
            confidence=min(self._proof_threshold - 0.01, 0.84),
            identity_labels=identity_labels,
            notes="differential_probe=inconclusive",
        )

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

    def _extract_state_snapshots_from_payload(
        self,
        payload: dict[str, str],
        scan_id: UUID | str,
        attack_task_id: UUID,
    ) -> tuple[StateSnapshot | None, StateSnapshot | None]:
        try:
            state_evidence_raw = payload.get("state_evidence")
            if not state_evidence_raw:
                return None, None

            state_evidence = json.loads(state_evidence_raw)
            if not isinstance(state_evidence, dict):
                return None, None

            before_dict = state_evidence.get("before")
            after_dict = state_evidence.get("after")
            if not isinstance(before_dict, dict) or not isinstance(after_dict, dict):
                return None, None

            timestamp = datetime.now(UTC)
            before_snapshot = StateSnapshot(
                scan_id=str(scan_id),
                step_id=str(attack_task_id),
                timestamp=timestamp,
                state_dict=before_dict,
                version=1,
            )
            after_snapshot = StateSnapshot(
                scan_id=str(scan_id),
                step_id=str(attack_task_id),
                timestamp=timestamp,
                state_dict=after_dict,
                version=2,
            )
            return before_snapshot, after_snapshot
        except Exception:
            return None, None

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
            "bfla": _BflaStrategy(),
            "tenant_isolation": _TenantIsolationStrategy(),
            "auth_bypass": _AuthBypassStrategy(),
            "privilege_escalation": _PrivilegeEscalationStrategy(),
            "sensitive_exposure": _SensitiveExposureStrategy(),
            "workflow_abuse": _WorkflowAbuseStrategy(),
            "injection": _InjectionStrategy(),
            "session_misuse": _SessionMisuseStrategy(),
            "rate_limit_abuse": _RateLimitAbuseStrategy(),
            "misconfiguration": _MisconfigurationStrategy(),
            "jwt_attack": _JwtAttackStrategy(),
            "ssrf": _SsrfStrategy(),
            "mass_assignment": _MassAssignmentStrategy(),
            "excessive_exposure": _ExcessiveExposureStrategy(),
            "graphql_introspection": _GraphqlIntrospectionStrategy(),
            "graphql_batch": _GraphqlBatchStrategy(),
            "graphql_field_suggestion": _GraphqlFieldSuggestionStrategy(),
            "graphql_depth": _GraphqlDepthStrategy(),
            "oauth_redirect": _OauthRedirectStrategy(),
            "oauth_state_csrf": _OauthStateCsrfStrategy(),
            "oauth_token_reuse": _OauthTokenReuseStrategy(),
            "oauth_error_disclosure": _OauthErrorDisclosureStrategy(),
            "nosql_injection": _NoSqlInjectionStrategy(),
            "ssti": _SstiStrategy(),
            "ldap_injection": _LdapInjectionStrategy(),
            "xpath_injection": _XpathInjectionStrategy(),
            "header_injection": _HeaderInjectionStrategy(),
            "xxe_classic": _XxeClassicStrategy(),
            "xxe_error": _XxeErrorStrategy(),
            "xxe_blind": _XxeBlindStrategy(),
            "deserialization_probe": _DeserializationProbeStrategy(),
            "yaml_deserialization": _YamlDeserializationStrategy(),
            "http_smuggling": _HttpSmugglingStrategy(),
            "web_cache_deception": _WebCacheDeceptionStrategy(),
            "cache_poisoning": _CachePoisoningStrategy(),
            "http_method_override": _HttpMethodOverrideStrategy(),
            "http_parameter_pollution": _HttpParameterPollutionStrategy(),
            "cookie_analysis": _CookieAnalysisStrategy(),
            "csrf": _CsrfStrategy(),
            "negative_value": _NegativeValueStrategy(),
            "integer_overflow": _IntegerOverflowStrategy(),
            "price_manipulation": _PriceManipulationStrategy(),
            "account_enumeration_timing": _AccountEnumerationTimingStrategy(),
            "inventory_reservation": _InventoryReservationStrategy(),
            "api_inventory": ApiInventoryStrategy(),
            "api_doc_exposure": ApiDocExposureStrategy(),
            "backup_file_exposure": BackupFileExposureStrategy(),
            "security_headers": _SecurityHeadersStrategy(),
            "cors_analysis": _CorsAnalysisStrategy(),
            "tls_analysis": _TlsAnalysisStrategy(),
            "limit_override_race": LimitOverrideRaceStrategy(),
            "race_condition": RaceConditionStrategy(),
            "double_spend": DoubleSpendStrategy(),
            "idempotency_bypass": IdempotencyBypassStrategy(),
            "distributed_lock_evasion": DistributedLockEvasionStrategy(),
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

    def _parse_hypothesis_config(self, raw_hypothesis: str | None) -> dict[str, Any]:
        if not raw_hypothesis:
            return {}
        try:
            parsed = json.loads(raw_hypothesis)
        except json.JSONDecodeError:
            return {}
        return parsed if isinstance(parsed, dict) else {}

    def _probe_for_identity(self, probes: list[tuple[RawProbe, str | None]], identity_name: str | None) -> RawProbe | None:
        for probe, selector in probes:
            if selector == identity_name:
                return probe
        return None

    def _extract_status_from_probe(self, attack_probe: RawProbe) -> int | None:
        status_raw = attack_probe.response.get("status")
        return status_raw if isinstance(status_raw, int) else None

    def _normalize_probe_body(self, attack_probe: RawProbe) -> str:
        body = attack_probe.response.get("body")
        if isinstance(body, str):
            return body.strip()
        if isinstance(body, (dict, list)):
            return json.dumps(body, sort_keys=True, separators=(",", ":"))
        if body is None:
            return ""
        return str(body).strip()

    def _sanitize_identity_label(self, raw_label: object) -> str | None:
        if not isinstance(raw_label, str):
            return None
        stripped = raw_label.strip()
        if not stripped:
            return None
        lowered = stripped.lower()
        for token in _FORBIDDEN_IDENTITY_LABEL_TOKENS:
            if token in lowered:
                return None
        return stripped

    def _race_reconcile_passed(
        self,
        *,
        scan_id: UUID | str,
        attack_task: AttackTask,
        attack_probe: RawProbe,
    ) -> bool | None:
        attack_class = str(attack_task.attack_class).strip().lower()
        if attack_class not in _RACE_RECONCILE_CLASSES and "race" not in attack_class:
            return None

        race_group_id = self._race_group_id_from_probe(attack_probe)
        if race_group_id is None:
            return None

        key = f"race_reconcile:{scan_id}:{race_group_id}"
        try:
            payload = self._redis.hgetall(key)
        except Exception:
            return None
        if not isinstance(payload, dict) or not payload:
            return None
        raw_value = payload.get("reconcile_passed")
        if raw_value is None:
            raw_value = payload.get(b"reconcile_passed")
        if isinstance(raw_value, bytes):
            raw_value = raw_value.decode("utf-8", errors="ignore")
        if isinstance(raw_value, bool):
            return raw_value
        if isinstance(raw_value, str):
            normalized = raw_value.strip().lower()
            if normalized in {"true", "1", "yes", "passed"}:
                return True
            if normalized in {"false", "0", "no", "failed", "no_signal"}:
                return False
        return None

    def _race_group_id_from_probe(self, attack_probe: RawProbe) -> str | None:
        request = attack_probe.request
        direct = request.get("_race_group_id") if isinstance(request, dict) else None
        if isinstance(direct, str) and direct.strip():
            return direct.strip()

        body = request.get("body") if isinstance(request, dict) else None
        if not isinstance(body, str) or not body.strip():
            return None
        try:
            parsed = json.loads(body)
        except json.JSONDecodeError:
            return None
        if not isinstance(parsed, dict):
            return None
        for key in ("_race_group_id", "race_group_id"):
            value = parsed.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
        return None

    def _set_identity_labels(self, artifact: ProofArtifact, identity_labels: list[str]) -> None:
        setattr(artifact, "identity_labels", identity_labels)

    def _downgrade_or_attach_identity_labels(
        self,
        artifact: ProofArtifact | None,
        confidence: float,
        identity_labels: list[str],
        notes: str,
    ) -> ProofArtifact | None:
        if artifact is None:
            return None
        artifact.confidence_score = min(artifact.confidence_score, confidence)
        self._set_identity_labels(artifact, identity_labels)
        artifact.evidence_notes = f"{artifact.evidence_notes}; {notes}; identity_labels={','.join(identity_labels)}"
        return artifact

    def _emit_feedback_payload(
        self,
        scan_id: UUID | str,
        attack_task: AttackTask,
        attack_probe: RawProbe,
        artifact: ProofArtifact | None,
        confidence: float,
    ) -> None:
        outcome = self._feedback_outcome(artifact=artifact, attack_probe=attack_probe, confidence=confidence)
        should_emit = confidence >= self._low_confidence_threshold or outcome in {
            TaskOutcome.blocked,
            TaskOutcome.unsafe_blocked,
        }
        if not should_emit:
            return

        endpoint = str(attack_task.endpoint_id)

        parent_evidence_ref = str(artifact.id) if artifact is not None and artifact.id is not None else None
        finding_class = attack_task.attack_class
        self._feedback_buffer.append(
            FeedbackPayload(
                outcome=outcome,
                scan_id=str(scan_id),
                task_id=str(attack_task.id),
                endpoint=endpoint,
                finding_class=finding_class,
                confidence=float(confidence),
                follow_up_hints=self._follow_up_hints_for_finding_class(finding_class),
                parent_evidence_ref=parent_evidence_ref,
                reason=_outcome_to_reason(outcome),
            )
        )

    def _feedback_outcome(
        self,
        artifact: ProofArtifact | None,
        attack_probe: RawProbe,
        confidence: float,
    ) -> TaskOutcome:
        if artifact is not None:
            if confidence >= self._proof_threshold:
                return TaskOutcome.success
            if confidence >= self._low_confidence_threshold:
                return TaskOutcome.interesting

        response_status = self._extract_status_from_probe(attack_probe=attack_probe)
        notes = (artifact.evidence_notes if artifact is not None else "").lower()
        if response_status == 403 or "blocked" in notes or "forbidden" in notes:
            return TaskOutcome.blocked
        if "unsafe" in notes:
            return TaskOutcome.unsafe_blocked
        if confidence >= self._low_confidence_threshold:
            return TaskOutcome.needs_followup
        return TaskOutcome.no_signal

    def _follow_up_hints_for_finding_class(self, finding_class: str) -> list[str]:
        lowered = finding_class.lower()
        hints: list[str] = []
        if lowered == "sensitive_exposure":
            hints.extend(["replay_with_token", "blast_radius_map"])
        if lowered.startswith("graphql"):
            hints.extend(["schema_introspection_fields", "depth_probe"])
        if "bfla" in lowered:
            hints.extend(["bfla_follow_up", "privilege_drift"])
        deduped: list[str] = []
        for hint in hints:
            if hint not in deduped:
                deduped.append(hint)
        return deduped

    def _stream_key(self, scan_id: UUID | str) -> str:
        return f"evidence:{scan_id}"
