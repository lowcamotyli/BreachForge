from __future__ import annotations

import json
from typing import Any

from execution_plane.validator.strategies.base import ValidationStrategy
from storage.db.models import AttackTask, ProofArtifact, RawProbe


class MisconfigurationStrategy(ValidationStrategy):
    _MIN_PROOF_CONFIDENCE_THRESHOLD = 0.85

    def validate(self, attack_probe: RawProbe, control_probe: RawProbe | None) -> ProofArtifact | None:
        task = self._extract_task(attack_probe, control_probe)
        probe_type = self._extract_probe_type(task=task, probe=attack_probe)
        response = attack_probe.response

        status = self._extract_status(response)
        headers = self._extract_headers(response)
        body_text = self._extract_textual_body(response)
        method = self._extract_method(attack_probe.request)
        path = self._extract_path(attack_probe.request)

        confidence = 0.0
        summary = ""

        if probe_type == "cors_wildcard" and str(headers.get("access-control-allow-origin", "")).strip() == "*":
            confidence = 0.90
            summary = "CORS misconfiguration detected: Access-Control-Allow-Origin wildcard is enabled."
        elif probe_type == "debug_endpoint" and self._is_success_status(status) and self._is_debug_path(path):
            confidence = 0.88
            summary = "Debug endpoint accessible with successful response."
        elif probe_type == "unsafe_methods" and method == "TRACE" and self._is_success_status(status):
            confidence = 0.89
            summary = "Unsafe HTTP method TRACE is enabled and returns success."
        elif probe_type == "verbose_error" and self._contains_verbose_error(body_text):
            confidence = 0.87
            summary = "Verbose error disclosure detected in response body."

        if confidence < self._MIN_PROOF_CONFIDENCE_THRESHOLD:
            return None

        return ProofArtifact(
            attack_task_id=attack_probe.attack_task_id,
            proof_type=self.expected_proof_type(),
            confidence_score=confidence,
            attack_probe_id=attack_probe.id,
            control_probe_id=self._extract_control_probe_id(control_probe),
            summary=summary,
            evidence_notes=f"probe_type={probe_type or 'unknown'}, status={status}, path={path}, method={method}",
        )

    def expected_proof_type(self) -> str:
        return "absolute"

    def expected_attack_class(self) -> str:
        return "misconfiguration"

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

    def _extract_status(self, response: dict[str, Any]) -> int | str | None:
        for key in ("status", "status_code", "code"):
            if key in response:
                return response[key]
        return None

    def _is_success_status(self, status: int | str | None) -> bool:
        if isinstance(status, int):
            return status == 200
        if isinstance(status, str) and status.isdigit():
            return int(status) == 200
        return False

    def _extract_headers(self, response: dict[str, Any]) -> dict[str, Any]:
        headers = response.get("headers")
        if not isinstance(headers, dict):
            return {}
        normalized: dict[str, Any] = {}
        for key, value in headers.items():
            normalized[str(key).lower()] = value
        return normalized

    def _extract_textual_body(self, response: dict[str, Any]) -> str:
        for key in ("body", "text", "content"):
            value = response.get(key)
            if isinstance(value, str):
                return value
        json_body = response.get("json")
        if json_body is not None:
            return json.dumps(json_body, default=str)
        data_body = response.get("data")
        if data_body is not None:
            return json.dumps(data_body, default=str)
        return ""

    def _extract_method(self, request: dict[str, Any]) -> str:
        method = request.get("method")
        if isinstance(method, str):
            return method.strip().upper()
        return ""

    def _extract_path(self, request: dict[str, Any]) -> str:
        for key in ("path", "url", "endpoint", "target"):
            value = request.get(key)
            if isinstance(value, str):
                return value.strip().lower()
        return ""

    def _is_debug_path(self, path: str) -> bool:
        return any(token in path for token in ("/debug", "/health", "/actuator"))

    def _contains_verbose_error(self, body_text: str) -> bool:
        lowered = body_text.lower()
        return "traceback" in lowered or "stack trace" in lowered or "exception at" in lowered

    def _extract_control_probe_id(self, control_probe: RawProbe | None) -> Any:
        if isinstance(control_probe, RawProbe):
            return control_probe.id
        return None
