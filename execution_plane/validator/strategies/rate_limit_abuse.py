from __future__ import annotations

import json
from typing import Any

from execution_plane.validator.strategies.base import ValidationStrategy
from storage.db.models import AttackTask, ProofArtifact, RawProbe


class RateLimitAbuseStrategy(ValidationStrategy):
    _MIN_PROOF_CONFIDENCE_THRESHOLD = 0.85
    _THROTTLE_STATUSES = {429, 503}

    def validate(self, attack_probe: RawProbe, control_probe: RawProbe | None) -> ProofArtifact | None:
        task = self._extract_task(attack_probe, control_probe)
        probe_type = self._extract_probe_type(task=task, probe=attack_probe)

        response = attack_probe.response
        statuses = self._extract_status_sequence(response)

        confidence = 0.0
        summary = ""

        if probe_type == "burst" and statuses and self._all_status_200(statuses):
            confidence = 0.88
            summary = "Burst rate-limit probe returned only HTTP 200 responses without throttling."
        elif probe_type == "staircase" and statuses and not self._has_throttle_status(statuses):
            confidence = 0.86
            summary = "Staircase rate-limit probe showed no throttling across request steps."
        elif probe_type == "retry_after" and self._missing_retry_after(response):
            confidence = 0.85
            summary = "Repeated requests lacked Retry-After header in rate-limit responses."

        if confidence < self._MIN_PROOF_CONFIDENCE_THRESHOLD:
            return None

        return ProofArtifact(
            attack_task_id=attack_probe.attack_task_id,
            proof_type=self.expected_proof_type(),
            confidence_score=confidence,
            attack_probe_id=attack_probe.id,
            control_probe_id=self._extract_control_probe_id(control_probe),
            summary=summary,
            evidence_notes=f"probe_type={probe_type or 'unknown'}, statuses={statuses}",
        )

    def expected_proof_type(self) -> str:
        return "absolute"

    def expected_attack_class(self) -> str:
        return "rate_limit_abuse"

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

    def _extract_status(self, response: dict[str, Any]) -> int | None:
        for key in ("status", "status_code", "code"):
            value = response.get(key)
            if isinstance(value, int):
                return value
            if isinstance(value, str) and value.isdigit():
                return int(value)
        return None

    def _extract_status_sequence(self, response: dict[str, Any]) -> list[int]:
        for key in ("statuses", "status_codes", "burst_statuses", "step_statuses"):
            raw = response.get(key)
            parsed = self._coerce_status_list(raw)
            if parsed:
                return parsed

        windows = response.get("responses")
        if isinstance(windows, list):
            collected: list[int] = []
            for item in windows:
                if isinstance(item, dict):
                    status = self._extract_status(item)
                    if status is not None:
                        collected.append(status)
            if collected:
                return collected

        status = self._extract_status(response)
        if status is None:
            return []
        return [status]

    def _coerce_status_list(self, value: Any) -> list[int]:
        if not isinstance(value, list):
            return []
        statuses: list[int] = []
        for item in value:
            if isinstance(item, int):
                statuses.append(item)
            elif isinstance(item, str) and item.isdigit():
                statuses.append(int(item))
        return statuses

    def _all_status_200(self, statuses: list[int]) -> bool:
        if not statuses:
            return False
        for status in statuses:
            if status != 200:
                return False
        return True

    def _has_throttle_status(self, statuses: list[int]) -> bool:
        for status in statuses:
            if status in self._THROTTLE_STATUSES:
                return True
        return False

    def _missing_retry_after(self, response: dict[str, Any]) -> bool:
        headers = self._extract_headers(response)
        if "retry-after" in headers and str(headers["retry-after"]).strip():
            return False

        repeated_requests = response.get("responses")
        if isinstance(repeated_requests, list) and len(repeated_requests) > 1:
            for item in repeated_requests:
                if isinstance(item, dict):
                    item_headers = self._extract_headers(item)
                    if "retry-after" in item_headers and str(item_headers["retry-after"]).strip():
                        return False
            return True

        return True

    def _extract_headers(self, response: dict[str, Any]) -> dict[str, Any]:
        headers = response.get("headers")
        if not isinstance(headers, dict):
            return {}
        normalized: dict[str, Any] = {}
        for key, value in headers.items():
            normalized[str(key).lower()] = value
        return normalized

    def _extract_control_probe_id(self, control_probe: RawProbe | None) -> Any:
        if isinstance(control_probe, RawProbe):
            return control_probe.id
        return None
