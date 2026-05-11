from __future__ import annotations

import json
from difflib import SequenceMatcher
from typing import Any

from execution_plane.validator.strategies.base import ValidationStrategy
from storage.db.models import ProofArtifact, RawProbe


class JwtAttackStrategy(ValidationStrategy):
    _MIN_BODY_MATCH_RATIO = 0.70
    _ALG_NONE_CONFIDENCE = 0.92
    _EXPIRED_CONFIDENCE = 0.88
    _KID_CONFIDENCE = 0.90
    _KID_ERROR_CONFIDENCE = 0.75
    _MIN_PROOF_CONFIDENCE_THRESHOLD = 0.85

    def validate(self, attack_probe: RawProbe, control_probe: RawProbe | None) -> ProofArtifact | None:
        probe_type = self._extract_probe_type(attack_probe.request)
        if probe_type is None:
            return None

        attack_status = self._extract_status(attack_probe.response)
        if attack_status is None:
            return None

        if probe_type in ("alg_none", "claim_escalation_role", "claim_escalation_scope"):
            if control_probe is None:
                return None
            control_status = self._extract_status(control_probe.response)
            if control_status is None:
                return None
            if not self._is_success(attack_status) or not self._is_success(control_status):
                return None
            ratio = self._body_match_ratio(attack_probe, control_probe)
            confidence = self._ALG_NONE_CONFIDENCE
            if ratio >= self._MIN_BODY_MATCH_RATIO and confidence >= self._MIN_PROOF_CONFIDENCE_THRESHOLD:
                return ProofArtifact(
                    attack_task_id=attack_probe.attack_task_id,
                    proof_type=self.expected_proof_type(),
                    confidence_score=confidence,
                    attack_probe_id=attack_probe.id,
                    control_probe_id=control_probe.id,
                    summary=(
                        "JWT alg:none or claim escalation accepted: manipulated token matched "
                        "authenticated baseline response"
                    ),
                    evidence_notes=(
                        f"probe_type={probe_type}, body_match_ratio={ratio:.4f}, "
                        f"attack_status={attack_status}"
                    ),
                )
            return None

        if probe_type == "expired_token_acceptance":
            if not self._is_success(attack_status):
                return None
            confidence = self._EXPIRED_CONFIDENCE
            if confidence < self._MIN_PROOF_CONFIDENCE_THRESHOLD:
                return None
            return ProofArtifact(
                attack_task_id=attack_probe.attack_task_id,
                proof_type=self.expected_proof_type(),
                confidence_score=confidence,
                attack_probe_id=attack_probe.id,
                control_probe_id=control_probe.id if control_probe is not None else None,
                summary="Server accepted expired JWT: expected 401/403 but received 200-series response",
                evidence_notes=(
                    f"probe_type=expired_token_acceptance, attack_status={attack_status}"
                ),
            )

        if probe_type in ("kid_path_traversal", "kid_sql_injection"):
            if self._is_success(attack_status) and control_probe is not None:
                ratio = self._body_match_ratio(attack_probe, control_probe)
                confidence = self._KID_CONFIDENCE
                if ratio >= self._MIN_BODY_MATCH_RATIO and confidence >= self._MIN_PROOF_CONFIDENCE_THRESHOLD:
                    return ProofArtifact(
                        attack_task_id=attack_probe.attack_task_id,
                        proof_type=self.expected_proof_type(),
                        confidence_score=confidence,
                        attack_probe_id=attack_probe.id,
                        control_probe_id=control_probe.id,
                        summary="JWT kid injection: manipulated kid header accepted by server",
                        evidence_notes=f"probe_type={probe_type}, attack_status={attack_status}",
                    )
                return None
            if attack_status == 500:
                confidence = self._KID_ERROR_CONFIDENCE
                if confidence < self._MIN_PROOF_CONFIDENCE_THRESHOLD:
                    return None
            return None

        return None

    def expected_proof_type(self) -> str:
        return "differential"

    def expected_attack_class(self) -> str:
        return "jwt_attack"

    def _extract_probe_type(self, request: dict[str, Any]) -> str | None:
        probe_type = request.get("probe_type")
        if isinstance(probe_type, str) and probe_type:
            return probe_type

        hypothesis = request.get("hypothesis")
        if not isinstance(hypothesis, str):
            return None

        try:
            parsed = json.loads(hypothesis)
        except (TypeError, ValueError):
            return None

        parsed_probe_type = parsed.get("probe_type") if isinstance(parsed, dict) else None
        if isinstance(parsed_probe_type, str) and parsed_probe_type:
            return parsed_probe_type
        return None

    def _extract_status(self, response: dict[str, Any]) -> int | None:
        for key in ("status", "status_code", "code"):
            value = response.get(key)
            if isinstance(value, int):
                return value
            if isinstance(value, str) and value.isdigit():
                return int(value)
        return None

    def _is_success(self, status: int | None) -> bool:
        return status is not None and 200 <= status < 300

    def _extract_body(self, response: dict[str, Any]) -> Any:
        for key in ("body", "json", "data", "content", "text"):
            if key in response:
                return response[key]
        return None

    def _normalize(self, value: Any) -> Any:
        if isinstance(value, str):
            stripped = value.strip()
            if not stripped:
                return ""
            try:
                parsed = json.loads(stripped)
            except (TypeError, ValueError):
                return stripped
            return self._normalize(parsed)
        if isinstance(value, dict):
            return {str(key): self._normalize(value[key]) for key in sorted(value)}
        if isinstance(value, list):
            return [self._normalize(item) for item in value]
        return value

    def _body_match_ratio(self, attack_probe: RawProbe, control_probe: RawProbe) -> float:
        attack_body = self._extract_body(attack_probe.response)
        control_body = self._extract_body(control_probe.response)
        attack_dump = json.dumps(self._normalize(attack_body), sort_keys=True, separators=(",", ":"))
        control_dump = json.dumps(self._normalize(control_body), sort_keys=True, separators=(",", ":"))
        return SequenceMatcher(a=attack_dump, b=control_dump).ratio()
