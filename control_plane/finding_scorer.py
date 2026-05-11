from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
from dataclasses import dataclass
from typing import Any
from uuid import UUID

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from control_plane.attack_chain_builder import ChainConfidenceResult, adjust_chain_severity
from control_plane.secret_correlation import CorrelationResult, SecretExposureCorrelator
from execution_plane.validator.secret_intelligence import PrivilegeFingerprint, PrivilegeLevel
from storage.db.models import AttackTask, Endpoint, Finding, ProofArtifact, Severity
from storage.db.session import AsyncSessionLocal

logger = structlog.get_logger(__name__)

DEFAULT_PROOF_CONFIDENCE_THRESHOLD = float(os.getenv("DEFAULT_PROOF_CONFIDENCE_THRESHOLD", "0.85"))
_NUMERIC_SEGMENT_RE = re.compile(r"/\d+(?=/|$)")
_CRITICAL_HIGH_CLASSES: frozenset[str] = frozenset({"bola", "tenant_isolation"})
_AUTHZ_CLASSES: frozenset[str] = frozenset({"auth_bypass", "privilege_escalation"})
_SEVERITY_RANK: dict[str, int] = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}
_SEVERITY_BY_CORRELATOR_VALUE: dict[str, Severity] = {
    "info": Severity.info,
    "medium": Severity.medium,
    "high": Severity.high,
    "critical": Severity.critical,
}


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
    privilege: float
    safety_confidence: float
    total: float
    explanation: str

    def __post_init__(self) -> None:
        self.confidence = _ensure_unit_interval("confidence", self.confidence)
        self.impact = _ensure_unit_interval("impact", self.impact)
        self.reachability = _ensure_unit_interval("reachability", self.reachability)
        self.repeatability = _ensure_unit_interval("repeatability", self.repeatability)
        self.blast_radius = _ensure_unit_interval("blast_radius", self.blast_radius)
        self.privilege = _ensure_unit_interval("privilege", self.privilege)
        self.safety_confidence = _ensure_unit_interval("safety_confidence", self.safety_confidence)
        self.total = float(self.total)
        self.explanation = str(self.explanation)


def compute_score_v2(
    confidence: float,
    impact: float,
    reachability: float,
    repeatability: float,
    blast_radius: float,
    privilege: float = 1.0,
    safety_confidence: float = 1.0,
) -> ExploitabilityScoreV2:
    confidence_value = _ensure_unit_interval("confidence", confidence)
    impact_value = _ensure_unit_interval("impact", impact)
    reachability_value = _ensure_unit_interval("reachability", reachability)
    repeatability_value = _ensure_unit_interval("repeatability", repeatability)
    blast_radius_value = _ensure_unit_interval("blast_radius", blast_radius)
    privilege_value = _ensure_unit_interval("privilege", privilege)
    safety_confidence_value = _ensure_unit_interval("safety_confidence", safety_confidence)
    total = (
        confidence_value
        * impact_value
        * reachability_value
        * repeatability_value
        * blast_radius_value
        * privilege_value
        * safety_confidence_value
    )
    explanation = (
        f"conf={confidence_value:.2f} x impact={impact_value:.2f} x reach={reachability_value:.2f} "
        f"x repeat={repeatability_value:.2f} x blast={blast_radius_value:.2f} "
        f"x privilege={privilege_value:.2f} x safety={safety_confidence_value:.2f} = {total:.4f}"
    )
    return ExploitabilityScoreV2(
        confidence=confidence_value,
        impact=impact_value,
        reachability=reachability_value,
        repeatability=repeatability_value,
        blast_radius=blast_radius_value,
        privilege=privilege_value,
        safety_confidence=safety_confidence_value,
        total=total,
        explanation=explanation,
    )


def compute_root_cause_fingerprint(findings_fingerprints: list[str]) -> str:
    material = "||".join(sorted(findings_fingerprints))
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]


class FindingScorer:
    def __init__(self, db: AsyncSession, proof_threshold: float = DEFAULT_PROOF_CONFIDENCE_THRESHOLD) -> None:
        self._db = db
        self._proof_threshold = proof_threshold

    async def score(
        self,
        artifact: ProofArtifact,
        endpoint: Endpoint,
        privilege_fingerprint: PrivilegeFingerprint | None = None,
    ) -> Finding | None:
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
            self._attach_privilege_fingerprint_metadata(
                finding=duplicate,
                privilege_fingerprint=privilege_fingerprint,
            )
            self._record_secret_blast_radius_matrix(artifact=artifact, finding=duplicate, endpoint=endpoint)
            self._attach_leak_source_metadata(finding=duplicate, artifact=artifact)
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
            metadata={
                "privilege_fingerprint": _build_privilege_fingerprint_entry(privilege_fingerprint),
            },
        )

        artifact.finding = finding
        self._record_secret_blast_radius_matrix(artifact=artifact, finding=finding, endpoint=endpoint)
        self._attach_leak_source_metadata(finding=finding, artifact=artifact)
        self._apply_secret_exposure_correlation(finding=finding, artifact=artifact)
        chain_root_cause = self._chain_root_cause_id([str(fingerprint)])
        extra_metadata_raw = getattr(finding, "extra_metadata", None)
        if isinstance(extra_metadata_raw, dict):
            extra_metadata_raw["chain_root_cause"] = chain_root_cause
            finding.extra_metadata = extra_metadata_raw
        elif hasattr(finding, "metadata"):
            metadata_raw = getattr(finding, "metadata", None)
            metadata = metadata_raw if isinstance(metadata_raw, dict) else {}
            metadata["chain_root_cause"] = chain_root_cause
            finding.metadata = metadata
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

    def _chain_root_cause_id(self, fingerprints: list[str]) -> str:
        return compute_root_cause_fingerprint(fingerprints)

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

    def _record_secret_blast_radius_matrix(self, artifact: ProofArtifact, finding: Finding, endpoint: Endpoint) -> None:
        if self._probe_type_for_artifact(artifact=artifact) != "impact_secret_blast_radius":
            return

        probe_artifact = getattr(artifact, "attack_probe", None)
        matrix_entry = _build_blast_radius_entry(probe_artifact=probe_artifact)
        if matrix_entry["endpoint"] is None:
            matrix_entry["endpoint"] = getattr(endpoint, "url_pattern", None)
        if matrix_entry["method"] is None:
            endpoint_method = getattr(endpoint, "method", None)
            matrix_entry["method"] = str(endpoint_method).upper() if endpoint_method is not None else None

        metadata_raw = getattr(finding, "metadata", None)
        metadata: dict[str, Any]
        if isinstance(metadata_raw, dict):
            metadata = metadata_raw
        else:
            metadata = {}
        matrix_raw = metadata.get("secret_blast_radius_matrix")
        matrix: list[dict[str, Any]]
        if isinstance(matrix_raw, list):
            matrix = matrix_raw
        else:
            matrix = []
            metadata["secret_blast_radius_matrix"] = matrix
        matrix.append(matrix_entry)
        finding.metadata = metadata

    def _attach_privilege_fingerprint_metadata(
        self,
        finding: Finding,
        privilege_fingerprint: PrivilegeFingerprint | None,
    ) -> None:
        metadata_raw = getattr(finding, "metadata", None)
        metadata: dict[str, Any]
        if isinstance(metadata_raw, dict):
            metadata = metadata_raw
        else:
            metadata = {}
        metadata["privilege_fingerprint"] = _build_privilege_fingerprint_entry(privilege_fingerprint)
        finding.metadata = metadata

    def _parse_leak_source_from_notes(self, evidence_notes: str | None) -> dict[str, Any] | None:
        if not isinstance(evidence_notes, str) or not evidence_notes.strip():
            return None

        parsed_pairs: dict[str, str] = {}
        for segment in evidence_notes.split(";"):
            if "=" not in segment:
                continue
            key_value = segment.split("=", 1)
            if len(key_value) != 2:
                continue
            key = key_value[0].strip()
            value = key_value[1].strip()
            if not key or not value:
                continue
            parsed_pairs[key] = value

        leak_type = parsed_pairs.get("leak_source")
        if leak_type is None:
            return None
        confidence_raw = parsed_pairs.get("leak_source_confidence")
        if confidence_raw is None:
            return None
        try:
            confidence = float(confidence_raw)
        except ValueError:
            return None
        return {"type": leak_type, "confidence": confidence}

    def _attach_leak_source_metadata(self, finding: Finding, artifact: ProofArtifact) -> None:
        leak_source_metadata = self._parse_leak_source_from_notes(artifact.evidence_notes)
        if leak_source_metadata is None:
            return

        metadata_raw = getattr(finding, "metadata", None)
        metadata: dict[str, Any]
        if isinstance(metadata_raw, dict):
            metadata = metadata_raw
        else:
            metadata = {}
        metadata["leak_source"] = leak_source_metadata
        finding.metadata = metadata

    def _probe_type_for_artifact(self, artifact: ProofArtifact) -> str | None:
        direct_probe_type = getattr(artifact, "probe_type", None)
        if isinstance(direct_probe_type, str) and direct_probe_type.strip():
            return direct_probe_type.strip().lower()

        attack_task = getattr(artifact, "attack_task", None)
        hypothesis_raw = getattr(attack_task, "hypothesis", None) if attack_task is not None else None
        if isinstance(hypothesis_raw, str) and hypothesis_raw.strip():
            try:
                parsed_hypothesis = json.loads(hypothesis_raw)
            except json.JSONDecodeError:
                parsed_hypothesis = None
            if isinstance(parsed_hypothesis, dict):
                probe_type = parsed_hypothesis.get("probe_type")
                if isinstance(probe_type, str) and probe_type.strip():
                    return probe_type.strip().lower()

        evidence_notes = str(getattr(artifact, "evidence_notes", "")).lower()
        if "impact_probe=impact_secret_blast_radius" in evidence_notes:
            return "impact_secret_blast_radius"
        if "probe_type=impact_secret_blast_radius" in evidence_notes:
            return "impact_secret_blast_radius"
        return None

    def _apply_secret_exposure_correlation(self, finding: Finding, artifact: ProofArtifact) -> None:
        if not self._is_secret_exposure_finding(finding=finding, artifact=artifact):
            return

        signals = self._secret_correlation_signals(finding=finding, artifact=artifact)
        result = SecretExposureCorrelator().correlate(signals)
        if result.noise_guard_triggered:
            logger.debug(
                "noise_guard_triggered, no severity upgrade",
                finding_id=str(getattr(finding, "id", "")),
                attack_class=finding.attack_class,
            )
            return

        if result.severity_upgrade is None:
            return

        upgrade = _severity_from_correlator_result(result=result)
        if upgrade is None or not _is_severity_upgrade(current=finding.severity, candidate=upgrade):
            return

        finding.severity = upgrade
        metadata = _metadata_dict(getattr(finding, "metadata", None))
        metadata["severity_factors"] = [
            {"source": factor.source, "confidence": factor.confidence, "description": factor.description}
            for factor in result.severity_factors
        ]
        metadata["severity_explanation"] = "; ".join(factor.description for factor in result.severity_factors)
        finding.metadata = metadata

    def _is_secret_exposure_finding(self, finding: Finding, artifact: ProofArtifact) -> bool:
        if finding.attack_class == "sensitive_exposure":
            return True

        evidence_notes = str(getattr(artifact, "evidence_notes", "")).lower()
        return any(token in evidence_notes for token in ("secret", "credential", "api_key", "token"))

    def _secret_correlation_signals(self, finding: Finding, artifact: ProofArtifact) -> dict[str, Any]:
        metadata = _metadata_dict(getattr(finding, "metadata", None))
        artifact_metadata = _metadata_dict(getattr(artifact, "metadata", None))
        evidence_metadata = _parse_evidence_notes_metadata(getattr(artifact, "evidence_notes", None))
        sources = (metadata, artifact_metadata, evidence_metadata)

        return {
            "active_replay": _first_bool(sources=sources, keys=("replay_confirmed", "active_replay"), default=False),
            "blast_radius_score": _first_float(sources=sources, key="blast_radius_score", default=0.0),
            "cors_permissive": _first_bool(sources=sources, keys=("cors_permissive",), default=False),
            "cache_permissive": _first_bool(sources=sources, keys=("cache_permissive",), default=False),
            "unauthenticated_exposure": _first_bool(
                sources=sources,
                keys=("unauthenticated_exposure",),
                default=False,
            ),
        }


def _build_blast_radius_entry(probe_artifact: Any) -> dict[str, Any]:
    endpoint = None
    method = None
    status: int | None = None
    content_type = None
    response_size: int | None = None

    request_payload = getattr(probe_artifact, "request", None)
    if isinstance(request_payload, dict):
        request_url = request_payload.get("url")
        endpoint = str(request_url) if request_url is not None else None
        request_method = request_payload.get("method")
        method = str(request_method).upper() if request_method is not None else None

    response_payload = getattr(probe_artifact, "response", None)
    if isinstance(response_payload, dict):
        payload_status = response_payload.get("status")
        if isinstance(payload_status, int):
            status = payload_status
        else:
            try:
                status = int(payload_status) if payload_status is not None else None
            except (TypeError, ValueError):
                status = None
        headers_payload = response_payload.get("headers")
        if isinstance(headers_payload, dict):
            for header_name, header_value in headers_payload.items():
                if str(header_name).lower() == "content-type":
                    content_type = str(header_value)
                    break
        body_payload = response_payload.get("body")
        if isinstance(body_payload, str):
            response_size = len(body_payload.encode("utf-8"))
        elif isinstance(body_payload, bytes):
            response_size = len(body_payload)

    if endpoint is None:
        endpoint = getattr(probe_artifact, "url_pattern", None)
    if endpoint is None:
        endpoint = getattr(probe_artifact, "url", None)
    if endpoint is None:
        endpoint = getattr(probe_artifact, "target_url", None)

    if method is None:
        method = getattr(probe_artifact, "method", None)
        if isinstance(method, str):
            method = method.upper()

    if status is None:
        status_raw = getattr(probe_artifact, "status", None)
        if isinstance(status_raw, int):
            status = status_raw
        else:
            try:
                status = int(status_raw) if status_raw is not None else None
            except (TypeError, ValueError):
                status = None

    if content_type is None:
        content_type = getattr(probe_artifact, "content_type", None)
    if content_type is None:
        content_type = getattr(probe_artifact, "response_content_type", None)

    if response_size is None:
        response_size_raw = getattr(probe_artifact, "response_size", None)
        if response_size_raw is None:
            response_size_raw = getattr(probe_artifact, "response_size_bytes", None)
        if isinstance(response_size_raw, int):
            response_size = response_size_raw
        else:
            try:
                response_size = int(response_size_raw) if response_size_raw is not None else None
            except (TypeError, ValueError):
                response_size = None

    auth_accepted = status is not None and 200 <= status <= 399
    return {
        "endpoint": str(endpoint) if endpoint is not None else None,
        "method": str(method) if method is not None else None,
        "status": status,
        "content_type": str(content_type) if content_type is not None else None,
        "response_size": response_size,
        "auth_accepted": auth_accepted,
    }


def _metadata_dict(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    return {}


def _parse_evidence_notes_metadata(evidence_notes: str | None) -> dict[str, str]:
    if not isinstance(evidence_notes, str) or not evidence_notes.strip():
        return {}

    parsed: dict[str, str] = {}
    for segment in evidence_notes.split(";"):
        if "=" not in segment:
            continue
        key, raw_value = segment.split("=", 1)
        key = key.strip()
        value = raw_value.strip()
        if key:
            parsed[key] = value
    return parsed


def _first_bool(sources: tuple[dict[str, Any], ...], keys: tuple[str, ...], default: bool) -> bool:
    for source in sources:
        for key in keys:
            if key in source:
                return _coerce_bool(source[key])
    return default


def _first_float(sources: tuple[dict[str, Any], ...], key: str, default: float) -> float:
    for source in sources:
        if key not in source:
            continue
        try:
            return float(source[key])
        except (TypeError, ValueError):
            return default
    return default


def _coerce_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"true", "1", "yes", "y", "on"}:
            return True
        if lowered in {"false", "0", "no", "n", "off", ""}:
            return False
    return bool(value)


def _severity_from_correlator_result(result: CorrelationResult) -> Severity | None:
    if result.severity_upgrade is None:
        return None
    return _SEVERITY_BY_CORRELATOR_VALUE.get(result.severity_upgrade.strip().lower())


def _is_severity_upgrade(current: Severity, candidate: Severity) -> bool:
    return _SEVERITY_RANK[candidate.value] > _SEVERITY_RANK[current.value]


def _build_privilege_fingerprint_entry(
    fingerprint: PrivilegeFingerprint | None,
) -> dict[str, Any] | None:
    if fingerprint is None:
        return None
    observed_access_level: PrivilegeLevel = fingerprint.observed_access_level
    inferred_level: PrivilegeLevel = fingerprint.inferred_level
    return {
        "observed_access_level": observed_access_level.value,
        "inferred_level": inferred_level.value,
        "confidence": fingerprint.confidence,
        "evidence_endpoints": fingerprint.evidence_endpoints,
        "hint_count": len(fingerprint.hints),
    }


def score_artifact(
    scan_id: str,
    finding_id: str,
    artifact_payload: dict[str, Any],
    privilege_fingerprint: PrivilegeFingerprint | None = None,
) -> None:
    asyncio.run(
        _score_artifact_async(
            scan_id=scan_id,
            finding_id=finding_id,
            artifact_payload=artifact_payload,
            privilege_fingerprint=privilege_fingerprint,
        )
    )


async def _score_artifact_async(
    scan_id: str,
    finding_id: str,
    artifact_payload: dict[str, Any],
    privilege_fingerprint: PrivilegeFingerprint | None = None,
) -> None:
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
            finding = await scorer.score(
                artifact=artifact,
                endpoint=attack_task.endpoint,
                privilege_fingerprint=privilege_fingerprint,
            )
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
