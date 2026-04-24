from __future__ import annotations

import asyncio
import os
import re
from dataclasses import dataclass
from typing import Any
from uuid import UUID

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from storage.db.models import AttackTask, Endpoint, Finding, ProofArtifact, Severity
from storage.db.session import AsyncSessionLocal

logger = structlog.get_logger(__name__)

DEFAULT_PROOF_CONFIDENCE_THRESHOLD = float(os.getenv("DEFAULT_PROOF_CONFIDENCE_THRESHOLD", "0.85"))
_NUMERIC_SEGMENT_RE = re.compile(r"/\d+(?=/|$)")
_CRITICAL_HIGH_CLASSES: frozenset[str] = frozenset({"bola", "tenant_isolation"})
_AUTHZ_CLASSES: frozenset[str] = frozenset({"auth_bypass", "privilege_escalation"})


def _ensure_unit_interval(name: str, value: float) -> float:
    numeric_value = float(value)
    if not 0.0 <= numeric_value <= 1.0:
        raise ValueError(f"{name} must be within [0, 1], got {numeric_value}")
    return numeric_value


@dataclass(slots=True)
class ExploitabilityScoreV2:
    confidence: float
    impact: float
    reachability: float
    repeatability: float
    blast_radius: float
    total: float
    explanation: str

    def __post_init__(self) -> None:
        self.confidence = _ensure_unit_interval("confidence", self.confidence)
        self.impact = _ensure_unit_interval("impact", self.impact)
        self.reachability = _ensure_unit_interval("reachability", self.reachability)
        self.repeatability = _ensure_unit_interval("repeatability", self.repeatability)
        self.blast_radius = _ensure_unit_interval("blast_radius", self.blast_radius)
        self.total = float(self.total)
        self.explanation = str(self.explanation)


def compute_score_v2(
    confidence: float,
    impact: float,
    reachability: float,
    repeatability: float,
    blast_radius: float,
) -> ExploitabilityScoreV2:
    confidence_value = _ensure_unit_interval("confidence", confidence)
    impact_value = _ensure_unit_interval("impact", impact)
    reachability_value = _ensure_unit_interval("reachability", reachability)
    repeatability_value = _ensure_unit_interval("repeatability", repeatability)
    blast_radius_value = _ensure_unit_interval("blast_radius", blast_radius)
    total = confidence_value * impact_value * reachability_value * repeatability_value * blast_radius_value
    explanation = (
        f"conf={confidence_value:.2f} x impact={impact_value:.2f} x reach={reachability_value:.2f} "
        f"x repeat={repeatability_value:.2f} x blast={blast_radius_value:.2f} = {total:.4f}"
    )
    return ExploitabilityScoreV2(
        confidence=confidence_value,
        impact=impact_value,
        reachability=reachability_value,
        repeatability=repeatability_value,
        blast_radius=blast_radius_value,
        total=total,
        explanation=explanation,
    )


class FindingScorer:
    def __init__(self, db: AsyncSession, proof_threshold: float = DEFAULT_PROOF_CONFIDENCE_THRESHOLD) -> None:
        self._db = db
        self._proof_threshold = proof_threshold

    async def score(self, artifact: ProofArtifact, endpoint: Endpoint) -> Finding | None:
        attack_task = artifact.attack_task
        if attack_task is None:
            raise ValueError("ProofArtifact.attack_task is required for scoring")

        if artifact.confidence_score < self._proof_threshold:
            return None

        fingerprint = self.compute_fingerprint(artifact=artifact, endpoint=endpoint)
        duplicate = await self._find_duplicate(scan_id=attack_task.scan_id, fingerprint=fingerprint)

        # Dedup must happen before any Finding write.
        if duplicate is not None:
            artifact.finding = duplicate
            artifact.finding_id = duplicate.id
            return None

        scoring_output = self._build_scoring_output(artifact=artifact)
        finding = Finding(
            scan_id=attack_task.scan_id,
            title=self._build_title(attack_class=attack_task.attack_class, endpoint=endpoint),
            description=self._build_description(attack_class=attack_task.attack_class, artifact=artifact),
            severity=self._severity_for(
                attack_class=attack_task.attack_class,
                confidence=scoring_output["confidence_score"],
                evidence_notes=artifact.evidence_notes,
            ),
            attack_class=attack_task.attack_class,
            affected_endpoint_id=endpoint.id,
            repro_steps=self._build_repro_steps(attack_task=attack_task, endpoint=endpoint),
            fix_guidance=self._fix_guidance_for(attack_class=attack_task.attack_class),
        )

        artifact.finding = finding
        self._db.add(finding)
        return finding

    def score_output(self, artifact: ProofArtifact) -> dict[str, Any]:
        return self._build_scoring_output(artifact=artifact)

    def compute_fingerprint(self, artifact: ProofArtifact, endpoint: Endpoint) -> tuple[str, str, str]:
        attack_task = artifact.attack_task
        if attack_task is None:
            raise ValueError("ProofArtifact.attack_task is required to compute fingerprint")

        return (
            attack_task.attack_class,
            self.normalize_url_pattern(endpoint.url_pattern),
            self._classify_parameter(attack_task.attack_class, attack_task.target_parameter),
        )

    def normalize_url_pattern(self, url_pattern: str) -> str:
        return _NUMERIC_SEGMENT_RE.sub("/{id}", url_pattern)

    async def _find_duplicate(self, scan_id: UUID, fingerprint: tuple[str, str, str]) -> Finding | None:
        attack_class, _, _ = fingerprint
        result = await self._db.execute(
            select(Finding)
            .where(Finding.scan_id == scan_id, Finding.attack_class == attack_class)
            .options(
                selectinload(Finding.affected_endpoint),
                selectinload(Finding.proof_artifacts).selectinload(ProofArtifact.attack_task),
            )
        )
        existing_findings = result.scalars().all()

        for finding in existing_findings:
            if finding.affected_endpoint is None:
                continue
            existing_fingerprint = self._fingerprint_for_existing_finding(finding)
            if existing_fingerprint == fingerprint:
                return finding
        return None

    def _fingerprint_for_existing_finding(self, finding: Finding) -> tuple[str, str, str]:
        param_class = "none"
        for proof in finding.proof_artifacts:
            if proof.attack_task is None:
                continue
            param_class = self._classify_parameter(finding.attack_class, proof.attack_task.target_parameter)
            break

        return (
            finding.attack_class,
            self.normalize_url_pattern(finding.affected_endpoint.url_pattern),
            param_class,
        )

    def _classify_parameter(self, attack_class: str, target_parameter: str | None) -> str:
        if attack_class == "session_misuse":
            return "auth"
        if attack_class in {"rate_limit_abuse", "misconfiguration"}:
            return "none"

        if not target_parameter:
            return "none"

        parameter = target_parameter.lower()
        if any(token in parameter for token in ("authorization", "auth", "cookie", "token")):
            return "auth"
        if any(token in parameter for token in ("tenant", "org", "company", "account")):
            return "tenant"
        if any(token in parameter for token in ("role", "permission", "scope", "privilege")):
            return "privilege"
        if "id" in parameter:
            return "identifier"
        return "generic"

    def _severity_for(self, attack_class: str, confidence: float, evidence_notes: str | None = None) -> Severity:
        lowered_evidence_notes = (evidence_notes or "").lower()

        if attack_class in _CRITICAL_HIGH_CLASSES:
            return Severity.critical if confidence >= 0.90 else Severity.high
        if attack_class in _AUTHZ_CLASSES:
            return Severity.critical if confidence >= 0.85 else Severity.high
        if attack_class == "session_misuse":
            return Severity.critical if confidence >= 0.90 else Severity.high
        if attack_class == "rate_limit_abuse":
            return Severity.medium if confidence >= 0.85 else Severity.info
        if attack_class == "misconfiguration":
            if "probe_type=cors_wildcard" in lowered_evidence_notes:
                return Severity.critical
            return Severity.high if confidence >= 0.90 else Severity.medium
        if attack_class == "sensitive_exposure":
            return Severity.high if confidence >= 0.85 else Severity.medium
        if attack_class == "workflow_abuse":
            return Severity.medium if confidence >= 0.85 else Severity.info
        if attack_class == "injection":
            return Severity.high if confidence >= 0.90 else Severity.medium
        return Severity.high if confidence >= 0.90 else Severity.medium

    def _build_scoring_output(self, artifact: ProofArtifact) -> dict[str, Any]:
        confidence = float(artifact.confidence_score)
        score_components = self._score_components_from_artifact(artifact=artifact)
        if score_components is not None:
            try:
                v2_score = compute_score_v2(
                    confidence=confidence,
                    impact=score_components["impact"],
                    reachability=score_components["reachability"],
                    repeatability=score_components["repeatability"],
                    blast_radius=score_components["blast_radius"],
                )
                return {
                    "confidence_score": confidence,
                    "score_version": "v2",
                    "exploitability_score": v2_score.total,
                    "score_explanation": v2_score.explanation,
                }
            except ValueError:
                pass

        return {
            "confidence_score": confidence,
            "score_version": "v1",
            "exploitability_score": confidence,
            "score_explanation": f"conf={confidence:.2f}",
        }

    def _score_components_from_artifact(self, artifact: ProofArtifact) -> dict[str, float] | None:
        impact = getattr(artifact, "_score_impact", None)
        reachability = getattr(artifact, "_score_reachability", None)
        repeatability = getattr(artifact, "_score_repeatability", None)
        blast_radius = getattr(artifact, "_score_blast_radius", None)
        components = (impact, reachability, repeatability, blast_radius)
        if any(component is None for component in components):
            return None
        return {
            "impact": float(impact),
            "reachability": float(reachability),
            "repeatability": float(repeatability),
            "blast_radius": float(blast_radius),
        }

    def _build_title(self, attack_class: str, endpoint: Endpoint) -> str:
        return f"{attack_class.replace('_', ' ').title()} on {endpoint.method.upper()} {endpoint.url_pattern}"

    def _build_description(self, attack_class: str, artifact: ProofArtifact) -> str:
        return f"{attack_class} behavior validated with confidence {artifact.confidence_score:.2f}: {artifact.summary}"

    def _build_repro_steps(self, attack_task: AttackTask, endpoint: Endpoint) -> str:
        parameter = attack_task.target_parameter or "N/A"
        return (
            f"1. Send {endpoint.method.upper()} request to {endpoint.url_pattern}.\n"
            f"2. Execute attack class '{attack_task.attack_class}' against parameter '{parameter}'.\n"
            f"3. Observe proof signal described in evidence notes."
        )

    def _fix_guidance_for(self, attack_class: str) -> str:
        if attack_class in _CRITICAL_HIGH_CLASSES:
            return "Enforce object-level authorization checks on every resource access using requester identity."
        if attack_class in _AUTHZ_CLASSES:
            return "Require server-side authorization checks for every sensitive action and reject downgraded auth contexts."
        if attack_class == "sensitive_exposure":
            return "Minimize sensitive data exposure, enforce field-level authorization, and redact unnecessary response fields."
        if attack_class == "workflow_abuse":
            return "Enforce workflow state transitions server-side and validate preconditions on every step."
        if attack_class == "injection":
            return "Apply strict input validation, parameterized queries, and output encoding where relevant."
        return "Apply server-side validation and authorization checks for this attack surface."


def score_artifact(scan_id: str, finding_id: str, artifact_payload: dict[str, Any]) -> None:
    asyncio.run(_score_artifact_async(scan_id=scan_id, finding_id=finding_id, artifact_payload=artifact_payload))


async def _score_artifact_async(scan_id: str, finding_id: str, artifact_payload: dict[str, Any]) -> None:
    scan_uuid = UUID(scan_id)
    finding_uuid = UUID(finding_id)
    artifact_id = UUID(artifact_payload["artifact_id"])
    attack_task_id = UUID(artifact_payload["attack_task_id"])
    attack_probe_id = UUID(artifact_payload["attack_probe_id"])
    control_probe_raw = artifact_payload.get("control_probe_id")
    control_probe_id = UUID(control_probe_raw) if control_probe_raw else None

    async with AsyncSessionLocal() as db:
        attack_task = await _load_attack_task_with_endpoint(db=db, attack_task_id=attack_task_id, scan_id=scan_uuid)
        if attack_task is None or attack_task.endpoint is None:
            logger.warning(
                "finding_scorer_attack_task_or_endpoint_missing",
                scan_id=str(scan_uuid),
                finding_id=str(finding_uuid),
                attack_task_id=str(attack_task_id),
            )
            return

        artifact = await _load_or_build_artifact(
            db=db,
            artifact_id=artifact_id,
            attack_task=attack_task,
            finding_id=finding_uuid,
            artifact_payload=artifact_payload,
            attack_probe_id=attack_probe_id,
            control_probe_id=control_probe_id,
        )

        scorer = FindingScorer(db=db)
        with db.no_autoflush:
            finding = await scorer.score(artifact=artifact, endpoint=attack_task.endpoint)
        scoring_output = scorer.score_output(artifact=artifact)
        await db.commit()

        logger.info(
            "finding_scored",
            scan_id=str(scan_uuid),
            attack_task_id=str(attack_task.id),
            artifact_id=str(artifact.id),
            finding_id=str(artifact.finding_id) if artifact.finding_id else str(finding_uuid),
            created_new_finding=finding is not None,
            score_version=scoring_output["score_version"],
            exploitability_score=scoring_output["exploitability_score"],
            score_explanation=scoring_output["score_explanation"],
        )


async def _load_attack_task_with_endpoint(db: AsyncSession, attack_task_id: UUID, scan_id: UUID) -> AttackTask | None:
    result = await db.execute(
        select(AttackTask)
        .where(AttackTask.id == attack_task_id, AttackTask.scan_id == scan_id)
        .options(selectinload(AttackTask.endpoint))
    )
    return result.scalar_one_or_none()


async def _load_or_build_artifact(
    db: AsyncSession,
    artifact_id: UUID,
    attack_task: AttackTask,
    finding_id: UUID,
    artifact_payload: dict[str, Any],
    attack_probe_id: UUID,
    control_probe_id: UUID | None,
) -> ProofArtifact:
    score_components = _extract_v2_score_components(artifact_payload=artifact_payload)

    existing = await db.get(ProofArtifact, artifact_id)
    if existing is not None:
        existing.finding_id = finding_id
        existing.proof_type = str(artifact_payload["proof_type"])
        existing.confidence_score = float(artifact_payload["confidence_score"])
        existing.attack_probe_id = attack_probe_id
        existing.control_probe_id = control_probe_id
        identity_role_raw = artifact_payload.get("identity_role")
        existing.identity_role = str(identity_role_raw) if identity_role_raw is not None else None
        state_diff_raw = artifact_payload.get("state_diff")
        existing.state_diff = state_diff_raw if isinstance(state_diff_raw, dict) else None
        existing.summary = str(artifact_payload["summary"])
        existing.evidence_notes = str(artifact_payload["evidence_notes"])
        existing.attack_task = attack_task
        _attach_v2_score_components(artifact=existing, components=score_components)
        return existing

    identity_role_raw = artifact_payload.get("identity_role")
    state_diff_raw = artifact_payload.get("state_diff")
    artifact = ProofArtifact(
        id=artifact_id,
        attack_task_id=attack_task.id,
        finding_id=finding_id,
        proof_type=str(artifact_payload["proof_type"]),
        confidence_score=float(artifact_payload["confidence_score"]),
        attack_probe_id=attack_probe_id,
        control_probe_id=control_probe_id,
        identity_role=str(identity_role_raw) if identity_role_raw is not None else None,
        state_diff=state_diff_raw if isinstance(state_diff_raw, dict) else None,
        summary=str(artifact_payload["summary"]),
        evidence_notes=str(artifact_payload["evidence_notes"]),
    )
    artifact.attack_task = attack_task
    _attach_v2_score_components(artifact=artifact, components=score_components)
    db.add(artifact)
    return artifact


def _extract_v2_score_components(artifact_payload: dict[str, Any]) -> dict[str, float] | None:
    v2_payload = artifact_payload.get("exploitability_v2")
    if isinstance(v2_payload, dict):
        impact = v2_payload.get("impact")
        reachability = v2_payload.get("reachability")
        repeatability = v2_payload.get("repeatability")
        blast_radius = v2_payload.get("blast_radius")
    else:
        impact = artifact_payload.get("impact")
        reachability = artifact_payload.get("reachability")
        repeatability = artifact_payload.get("repeatability")
        blast_radius = artifact_payload.get("blast_radius")

    components = (impact, reachability, repeatability, blast_radius)
    if any(component is None for component in components):
        return None

    try:
        return {
            "impact": float(impact),
            "reachability": float(reachability),
            "repeatability": float(repeatability),
            "blast_radius": float(blast_radius),
        }
    except (TypeError, ValueError):
        return None


def _attach_v2_score_components(artifact: ProofArtifact, components: dict[str, float] | None) -> None:
    if components is None:
        return
    setattr(artifact, "_score_impact", components["impact"])
    setattr(artifact, "_score_reachability", components["reachability"])
    setattr(artifact, "_score_repeatability", components["repeatability"])
    setattr(artifact, "_score_blast_radius", components["blast_radius"])
