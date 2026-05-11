from __future__ import annotations

import json
from typing import Any

from storage.db.models import ProofArtifact, RawProbe

from execution_plane.validator.differential import DifferentialProbeResult
from execution_plane.validator.strategies.base import ValidationStrategy


class TenantIsolationStrategy(ValidationStrategy):
    _MIN_PROOF_CONFIDENCE_THRESHOLD = 0.85
    _STATUS_ONLY_CONFIDENCE = 0.70
    _DIFFERENTIAL_BODY_CONFIDENCE = 0.90

    def validate(
        self,
        attack_probe: RawProbe,
        control_probe: RawProbe | None,
        differential_result: DifferentialProbeResult | None = None,
    ) -> ProofArtifact | None:
        if control_probe is None:
            return None

        attack_response = attack_probe.response
        control_response = control_probe.response

        attack_status = self._extract_status(attack_response)
        control_status = self._extract_status(control_response)
        attack_body = self._extract_semantic_body(attack_response)
        control_body = self._extract_semantic_body(control_response)

        confidence: float | None = None
        summary: str | None = None
        evidence_parts: list[str] = []

        if attack_body != control_body:
            confidence = self._DIFFERENTIAL_BODY_CONFIDENCE
            summary = "Tenant isolation differential proof: attack and control response bodies are semantically different."
            evidence_parts.append(
                f"attack_status={attack_status}, control_status={control_status}, difference_type=semantic_body"
            )
        elif attack_status != control_status:
            confidence = self._STATUS_ONLY_CONFIDENCE
            summary = "Tenant isolation differential signal: status differs but response body semantics match."
            evidence_parts.append(
                f"attack_status={attack_status}, control_status={control_status}, difference_type=status_only"
            )

        supporting_evidence = True
        if differential_result is not None:
            tenant_mismatch = (
                (not differential_result.status_differs)
                and differential_result.challenger_status in (200, 201, 204)
                and differential_result.ownership_markers_differ
            )
            supporting_evidence = (not differential_result.status_differs) and differential_result.ownership_markers_differ
            evidence_parts.append(
                "differential_status_differs="
                f"{differential_result.status_differs}, "
                "differential_ownership_markers_differ="
                f"{differential_result.ownership_markers_differ}, "
                "differential_challenger_status="
                f"{differential_result.challenger_status}"
            )
            if tenant_mismatch:
                evidence_parts.append("cross-tenant data accessible")
                confidence = min(1.0, (confidence or 0.0) + 0.2)

        if confidence is None or confidence < self._MIN_PROOF_CONFIDENCE_THRESHOLD:
            return None
        if confidence >= self._MIN_PROOF_CONFIDENCE_THRESHOLD and not supporting_evidence:
            return None

        return ProofArtifact(
            attack_task_id=attack_probe.attack_task_id,
            proof_type=self.expected_proof_type(),
            confidence_score=confidence,
            attack_probe_id=attack_probe.id,
            control_probe_id=control_probe.id,
            summary=summary or "Tenant isolation validation proof",
            evidence_notes=", ".join(evidence_parts),
        )

    def expected_proof_type(self) -> str:
        return "differential"

    def expected_attack_class(self) -> str:
        return "tenant_isolation"

    def _extract_status(self, response: dict[str, Any]) -> int | str | None:
        for key in ("status", "status_code", "code"):
            if key in response:
                return response[key]
        return None

    def _extract_semantic_body(self, response: dict[str, Any]) -> Any:
        for key in ("body", "json", "data", "content", "text"):
            if key in response:
                return self._normalize_value(response[key])
        return None

    def _normalize_value(self, value: Any) -> Any:
        if isinstance(value, str):
            stripped = value.strip()
            if not stripped:
                return ""
            try:
                parsed = json.loads(stripped)
            except (TypeError, ValueError):
                return stripped
            return self._normalize_value(parsed)
        if isinstance(value, dict):
            return {str(key): self._normalize_value(value[key]) for key in sorted(value)}
        if isinstance(value, list):
            return [self._normalize_value(item) for item in value]
        return value
