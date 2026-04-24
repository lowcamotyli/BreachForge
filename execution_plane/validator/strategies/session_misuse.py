from __future__ import annotations

import json
from typing import Any

from execution_plane.validator.strategies.base import ValidationStrategy
from storage.db.models import AttackTask, ProofArtifact, RawProbe


class SessionMisuseStrategy(ValidationStrategy):
    _MIN_PROOF_CONFIDENCE_THRESHOLD = 0.85

    def validate(self, attack_probe: RawProbe, control_probe: RawProbe | None) -> ProofArtifact | None:
        task = self._extract_task(attack_probe, control_probe)
        probe_type = self._extract_probe_type(task=task, probe=attack_probe)

        response = attack_probe.response
        status = self._extract_status(response)
        body = self._extract_semantic_body(response)

        confidence = 0.0
        summary = ""

        if probe_type == "replay" and self._is_success_status(status) and self._has_material_body(body):
            confidence = 0.87
            summary = "Session replay probe succeeded with non-empty response body."
        elif probe_type == "token_swap" and self._is_success_status(status):
            expected_user = self._extract_expected_user(task=task, probe=attack_probe)
            actual_user = self._extract_actual_user(response)
            if expected_user is not None and actual_user is not None and actual_user != expected_user:
                confidence = 0.90
                summary = "Token-swap probe returned data for a different user than expected."
        elif probe_type == "stale_session" and self._is_success_status(status):
            confidence = 0.86
            summary = "Stale session probe succeeded; session appears not invalidated."

        if confidence < self._MIN_PROOF_CONFIDENCE_THRESHOLD:
            return None

        return ProofArtifact(
            attack_task_id=attack_probe.attack_task_id,
            proof_type=self.expected_proof_type(),
            confidence_score=confidence,
            attack_probe_id=attack_probe.id,
            control_probe_id=self._extract_control_probe_id(control_probe),
            summary=summary,
            evidence_notes=f"probe_type={probe_type or 'unknown'}, status={status}",
        )

    def expected_proof_type(self) -> str:
        return "absolute"

    def expected_attack_class(self) -> str:
        return "session_misuse"

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

    def _extract_expected_user(self, task: AttackTask | None, probe: RawProbe) -> Any:
        if task is not None:
            hypothesis = self._parse_hypothesis(task.hypothesis)
            for key in ("expected_user", "expected_user_data", "expected_user_id", "expected"):
                if key in hypothesis:
                    return hypothesis[key]

        for source in (probe.request, probe.response):
            for key in ("expected_user", "expected_user_data", "expected_user_id", "expected"):
                if key in source:
                    return source[key]
        return None

    def _extract_actual_user(self, response: dict[str, Any]) -> Any:
        for key in ("user", "user_data", "account", "data", "json", "body"):
            if key in response:
                return self._normalize_value(response[key])
        return None

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
            return {str(key): self._normalize_value(item) for key, item in sorted(value.items())}
        if isinstance(value, list):
            return [self._normalize_value(item) for item in value]
        return value

    def _parse_hypothesis(self, hypothesis: str) -> dict[str, Any]:
        try:
            parsed = json.loads(hypothesis)
        except (TypeError, ValueError):
            return {}
        if isinstance(parsed, dict):
            return parsed
        return {}

    def _is_success_status(self, status: int | str | None) -> bool:
        if isinstance(status, int):
            return status == 200
        if isinstance(status, str) and status.isdigit():
            return int(status) == 200
        return False

    def _has_material_body(self, body: Any) -> bool:
        if body is None:
            return False
        if isinstance(body, str):
            stripped = body.strip().lower()
            if not stripped:
                return False
            if stripped in {"401", "403", "unauthorized", "forbidden"}:
                return False
            return True
        if isinstance(body, (list, dict)):
            return len(body) > 0
        return True

    def _extract_control_probe_id(self, control_probe: RawProbe | None) -> Any:
        if isinstance(control_probe, RawProbe):
            return control_probe.id
        return None
