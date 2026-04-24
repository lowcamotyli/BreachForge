from __future__ import annotations

import json
from difflib import SequenceMatcher
from typing import Any

from execution_plane.validator.strategies.base import ValidationStrategy
from storage.db.models import ProofArtifact, RawProbe


class AuthBypassStrategy(ValidationStrategy):
    _MIN_PROOF_CONFIDENCE_THRESHOLD = 0.85
    _ABSOLUTE_CONFIDENCE = 0.95
    _MIN_STRUCTURAL_MATCH_RATIO = 0.80

    def validate(self, attack_probe: RawProbe, control_probe: RawProbe | None) -> ProofArtifact | None:
        if control_probe is None:
            return None

        attack_status = self._extract_status(attack_probe.response)
        control_status = self._extract_status(control_probe.response)

        if not self._is_success_status(attack_status) or not self._is_success_status(control_status):
            return None

        attack_body = self._extract_semantic_body(attack_probe.response)
        control_body = self._extract_semantic_body(control_probe.response)

        ratio = self._structural_similarity(attack_body, control_body)
        if ratio <= self._MIN_STRUCTURAL_MATCH_RATIO:
            return None

        confidence = self._ABSOLUTE_CONFIDENCE
        if confidence < self._MIN_PROOF_CONFIDENCE_THRESHOLD:
            return None

        return ProofArtifact(
            attack_task_id=attack_probe.attack_task_id,
            proof_type=self.expected_proof_type(),
            confidence_score=confidence,
            attack_probe_id=attack_probe.id,
            control_probe_id=control_probe.id,
            summary="Auth bypass absolute proof: unauthenticated response structurally matches authenticated baseline.",
            evidence_notes=(
                f"structural_match_ratio={ratio:.4f}, attack_status={attack_status}, "
                f"control_status={control_status}"
            ),
        )

    def expected_proof_type(self) -> str:
        return "absolute"

    def expected_attack_class(self) -> str:
        return "auth_bypass"

    def _extract_status(self, response: dict[str, Any]) -> int | str | None:
        for key in ("status", "status_code", "code"):
            if key in response:
                return response[key]
        return None

    def _is_success_status(self, status: int | str | None) -> bool:
        if isinstance(status, int):
            return 200 <= status < 300
        if isinstance(status, str) and status.isdigit():
            parsed = int(status)
            return 200 <= parsed < 300
        return False

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

    def _structure_signature(self, value: Any) -> Any:
        if isinstance(value, dict):
            return {str(key): self._structure_signature(item) for key, item in value.items()}
        if isinstance(value, list):
            return [self._structure_signature(item) for item in value]
        if value is None:
            return "null"
        return type(value).__name__

    def _structural_similarity(self, attack_body: Any, control_body: Any) -> float:
        attack_signature = self._structure_signature(attack_body)
        control_signature = self._structure_signature(control_body)
        attack_dump = json.dumps(attack_signature, sort_keys=True, separators=(",", ":"))
        control_dump = json.dumps(control_signature, sort_keys=True, separators=(",", ":"))
        return SequenceMatcher(a=attack_dump, b=control_dump).ratio()
