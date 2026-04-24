from __future__ import annotations

import json
from typing import Any

from execution_plane.validator.strategies.base import ValidationStrategy
from storage.db.models import AttackTask, ProofArtifact, RawProbe


class InjectionStrategy(ValidationStrategy):
    _MIN_PROOF_CONFIDENCE_THRESHOLD = 0.85
    _SQL_ERROR_PATTERNS = (
        "syntax error",
        "ora-",
        "mysql_fetch",
        "pg_query",
        "sqlite",
        "sqlstate",
    )

    def validate(self, attack_probe: RawProbe, control_probe: RawProbe | None) -> ProofArtifact | None:
        task = self._extract_task(attack_probe, control_probe)
        probe_type = self._extract_probe_type(task=task, probe=attack_probe)

        response = attack_probe.response
        body = self._extract_textual_body(response)
        latency_ms = self._extract_latency_ms(response)

        confidence = 0.0
        summary = ""

        if probe_type == "error_based" and self._contains_sql_error_signature(body):
            confidence = 0.90
            summary = "Error-based injection signature detected in response body."
        elif probe_type == "timing_based" and latency_ms is not None and latency_ms > 4500:
            confidence = 0.86
            summary = "Timing-based injection signal detected due to elevated response latency."

        if confidence < self._MIN_PROOF_CONFIDENCE_THRESHOLD:
            return None

        return ProofArtifact(
            attack_task_id=attack_probe.attack_task_id,
            proof_type=self.expected_proof_type(),
            confidence_score=confidence,
            attack_probe_id=attack_probe.id,
            control_probe_id=self._extract_control_probe_id(control_probe),
            summary=summary,
            evidence_notes=f"probe_type={probe_type or 'unknown'}, latency_ms={latency_ms}",
        )

    def expected_proof_type(self) -> str:
        return "absolute"

    def expected_attack_class(self) -> str:
        return "injection"

    def _extract_task(self, attack_probe: RawProbe, control_probe: RawProbe | None) -> AttackTask | None:
        if isinstance(control_probe, AttackTask):
            return control_probe
        for source in (attack_probe.request, attack_probe.response):
            candidate = source.get("attack_task")
            if isinstance(candidate, AttackTask):
                return candidate
        return None

    def _extract_probe_type(self, task: AttackTask | None, probe: RawProbe) -> str | None:
        if task is not None:
            hypothesis = self._parse_hypothesis(task.hypothesis)
            probe_type = hypothesis.get("probe_type")
            if isinstance(probe_type, str) and probe_type.strip():
                return probe_type.strip().lower()

        request_probe_type = probe.request.get("probe_type")
        if isinstance(request_probe_type, str) and request_probe_type.strip():
            return request_probe_type.strip().lower()

        response_probe_type = probe.response.get("probe_type")
        if isinstance(response_probe_type, str) and response_probe_type.strip():
            return response_probe_type.strip().lower()

        return None

    def _parse_hypothesis(self, hypothesis: str) -> dict[str, Any]:
        try:
            parsed = json.loads(hypothesis)
        except (TypeError, ValueError):
            return {}
        if isinstance(parsed, dict):
            return parsed
        return {}

    def _extract_textual_body(self, response: dict[str, Any]) -> str:
        for key in ("body", "text", "content"):
            value = response.get(key)
            if isinstance(value, str):
                return value
        for key in ("json", "data"):
            value = response.get(key)
            if value is not None:
                return json.dumps(value, default=str)
        return ""

    def _contains_sql_error_signature(self, body: str) -> bool:
        lowered = body.lower()
        for pattern in self._SQL_ERROR_PATTERNS:
            if pattern in lowered:
                return True
        return False

    def _extract_latency_ms(self, response: dict[str, Any]) -> float | None:
        value = response.get("latency_ms")
        if isinstance(value, (int, float)):
            return float(value)
        if isinstance(value, str):
            try:
                return float(value.strip())
            except ValueError:
                return None
        return None

    def _extract_control_probe_id(self, control_probe: RawProbe | None) -> Any:
        if isinstance(control_probe, RawProbe):
            return control_probe.id
        return None
