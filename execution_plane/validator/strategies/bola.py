from __future__ import annotations

import json
from typing import Any

from execution_plane.validator.differential import DifferentialProbeResult
from storage.db.models import ProofArtifact, RawProbe

from execution_plane.validator.strategies.base import ValidationStrategy


class BolaStrategy(ValidationStrategy):
    _MIN_PROOF_CONFIDENCE_THRESHOLD = 0.85
    _STATUS_ONLY_CONFIDENCE = 0.70
    _DIFFERENTIAL_BODY_CONFIDENCE = 0.90

    def validate(
        self,
        attack_probe: RawProbe,
        control_probe: RawProbe | None,
        differential_result: DifferentialProbeResult | None = None,
    ) -> ProofArtifact | None:
        if differential_result is None:
            return self._validate_single_identity(attack_probe=attack_probe, control_probe=control_probe)

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
        evidence_notes: list[str] = []

        if attack_body != control_body:
            confidence = self._DIFFERENTIAL_BODY_CONFIDENCE
            summary = "BOLA differential proof: attack and control response bodies are semantically different."
            evidence_notes.append(
                f"attack_status={attack_status}, control_status={control_status}, "
                "difference_type=semantic_body"
            )
        elif attack_status != control_status:
            confidence = self._STATUS_ONLY_CONFIDENCE
            summary = "BOLA differential signal: status differs but response body semantics match."
            evidence_notes.append(
                f"attack_status={attack_status}, control_status={control_status}, "
                "difference_type=status_only"
            )

        owner_accessed = differential_result.baseline_status in (200, 201, 204)
        cross_user_accessed = differential_result.challenger_status in (200, 201, 204)
        challenger_identity = differential_result.challenger_identity.strip().lower()
        challenger_is_anon = challenger_identity in {"anon", "anonymous", "unauthenticated", "unauth", "guest"}
        anon_blocked = differential_result.challenger_status in (401, 403) if challenger_is_anon else False

        evidence_notes.append(
            f"owner_accessed={owner_accessed}, cross_user_accessed={cross_user_accessed}, anon_blocked={anon_blocked}"
        )

        if owner_accessed and cross_user_accessed and not differential_result.status_differs:
            base_confidence = confidence if confidence is not None else self._STATUS_ONLY_CONFIDENCE
            confidence = min(1.0, base_confidence + 0.2)
            if summary is None:
                summary = "BOLA differential proof: owner and challenger both accessed resource with matching statuses."
            evidence_notes.append("bola_v2_strong_signal=true")

        if differential_result.ownership_markers_differ is False and cross_user_accessed:
            evidence_notes.append("ownership_markers_differ=false (same data returned)")

        if confidence is None or confidence < self._MIN_PROOF_CONFIDENCE_THRESHOLD:
            return None

        return ProofArtifact(
            attack_task_id=attack_probe.attack_task_id,
            proof_type=self.expected_proof_type(),
            confidence_score=confidence,
            attack_probe_id=attack_probe.id,
            control_probe_id=control_probe.id,
            summary=summary or "BOLA validation proof",
            evidence_notes=", ".join(evidence_notes),
        )

    def _validate_single_identity(self, attack_probe: RawProbe, control_probe: RawProbe | None) -> ProofArtifact | None:
        if control_probe is None:
            return None

        attack_response = attack_probe.response
        control_response = control_probe.response

        attack_status = self._extract_status(attack_response)
        control_status = self._extract_status(control_response)
        attack_body = self._extract_semantic_body(attack_response)
        control_body = self._extract_semantic_body(control_response)

        has_differential_signal = attack_status != control_status or attack_body != control_body
        if not has_differential_signal:
            return None

        confidence: float | None = None
        summary: str | None = None
        evidence_notes: str | None = None

        if attack_body != control_body:
            confidence = self._DIFFERENTIAL_BODY_CONFIDENCE
            summary = "BOLA differential proof: attack and control response bodies are semantically different."
            evidence_notes = (
                f"attack_status={attack_status}, control_status={control_status}, "
                "difference_type=semantic_body"
            )
        elif attack_status != control_status:
            confidence = self._STATUS_ONLY_CONFIDENCE
            summary = "BOLA differential signal: status differs but response body semantics match."
            evidence_notes = (
                f"attack_status={attack_status}, control_status={control_status}, "
                "difference_type=status_only"
            )

        if confidence is None or confidence < self._MIN_PROOF_CONFIDENCE_THRESHOLD:
            return None

        return ProofArtifact(
            attack_task_id=attack_probe.attack_task_id,
            proof_type=self.expected_proof_type(),
            confidence_score=confidence,
            attack_probe_id=attack_probe.id,
            control_probe_id=control_probe.id,
            summary=summary or "BOLA validation proof",
            evidence_notes=evidence_notes or "",
        )

    def expected_proof_type(self) -> str:
        return "differential"

    def expected_attack_class(self) -> str:
        return "bola"

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
