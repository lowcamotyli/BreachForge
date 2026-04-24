from __future__ import annotations

import json
import re
from typing import Any

from execution_plane.validator.strategies.base import ValidationStrategy
from storage.db.models import ProofArtifact, RawProbe

_MIN_PROOF_CONFIDENCE_THRESHOLD = 0.85
_AUTH_HEADER_NAMES: set[str] = {"authorization", "cookie", "x-api-key", "x-auth-token", "proxy-authorization"}
_PATTERN_REGISTRY: dict[str, tuple[re.Pattern[str], ...]] = {
    "credential": (
        re.compile(r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"]?[^'\"\s]{6,}"),
        re.compile(r"(?i)(api[_-]?key|secret|client[_-]?secret)\s*[:=]\s*['\"]?[a-z0-9_\-\.=]{8,}"),
        re.compile(r"[A-Za-z0-9_-]{20,}"),
        re.compile(r'"password"\s*:\s*"[^"]+"'),
    ),
    "token": (
        re.compile(r"(?i)bearer\s+[a-z0-9\-\._~\+/]+=*"),
        re.compile(r"(?i)(access[_-]?token|refresh[_-]?token|session[_-]?token|jwt)\s*[:=]\s*['\"]?[a-z0-9\-\._~\+/]+=*"),
        re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),
    ),
    "pii": (
        re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
        re.compile(r"\b(?:\d[ -]*?){13,16}\b"),
        re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"),
        re.compile(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b"),
    ),
}


class SensitiveExposureStrategy(ValidationStrategy):
    def validate(self, attack_probe: RawProbe, control_probe: RawProbe | None) -> ProofArtifact | None:
        del control_probe

        flattened = self._flatten_response(attack_probe.response)
        matches = self._find_matches(flattened)
        if not matches:
            return None

        request_has_auth = self._request_has_auth_headers(attack_probe.request)
        confidence = 0.90 if len(matches) > 1 else 0.85
        if request_has_auth:
            confidence = 0.85
        else:
            confidence += 0.05
        if confidence < _MIN_PROOF_CONFIDENCE_THRESHOLD:
            return None

        summary = "Sensitive exposure proof: response contains credential/token/PII indicator patterns"
        evidence_notes = f"matches={', '.join(sorted(matches))}; request_has_auth={request_has_auth}"

        return ProofArtifact(
            attack_task_id=attack_probe.attack_task_id,
            proof_type=self.expected_proof_type(),
            confidence_score=confidence,
            attack_probe_id=attack_probe.id,
            control_probe_id=None,
            summary=summary,
            evidence_notes=evidence_notes,
        )

    def expected_proof_type(self) -> str:
        return "absolute"

    def expected_attack_class(self) -> str:
        return "sensitive_exposure"

    def _flatten_response(self, response: dict[str, Any]) -> str:
        chunks: list[str] = []
        for key in ("body", "json", "data", "text", "headers"):
            if key not in response:
                continue
            value = response[key]
            chunks.append(self._to_text(value))
        return "\n".join(chunk for chunk in chunks if chunk)

    def _to_text(self, value: Any) -> str:
        if isinstance(value, str):
            stripped = value.strip()
            if not stripped:
                return ""
            try:
                parsed = json.loads(stripped)
            except (TypeError, ValueError):
                return stripped
            return self._to_text(parsed)
        if isinstance(value, dict):
            ordered = {str(key): value[key] for key in sorted(value)}
            return json.dumps(ordered, sort_keys=True, separators=(",", ":"))
        if isinstance(value, list):
            return json.dumps(value, separators=(",", ":"))
        return str(value)

    def _find_matches(self, content: str) -> set[str]:
        discovered: set[str] = set()
        for group_name, patterns in _PATTERN_REGISTRY.items():
            for pattern in patterns:
                if pattern.search(content):
                    discovered.add(group_name)
                    break
        return discovered

    def _request_has_auth_headers(self, request: dict[str, Any]) -> bool:
        headers = request.get("headers")
        if isinstance(headers, dict):
            for header_name in headers:
                if str(header_name).lower() in _AUTH_HEADER_NAMES:
                    return True

        for key in request:
            if key.lower() in _AUTH_HEADER_NAMES:
                return True
        return False
