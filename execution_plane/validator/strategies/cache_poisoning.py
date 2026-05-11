from __future__ import annotations

import json
from typing import Any
from urllib.parse import urlparse
from uuid import NAMESPACE_URL, uuid5

from execution_plane.validator.strategies.base import ValidationStrategy
from storage.db.models import ProofArtifact, RawProbe


class WebCacheDeceptionStrategy(ValidationStrategy):
    _CONFIDENCE = 0.90
    _MIN_PROOF_CONFIDENCE_THRESHOLD = 0.85
    _PRIVATE_FIELD_NAMES = frozenset({"email", "user_id", "token", "profile", "account", "password", "phone", "address"})
    _STATIC_EXTENSIONS = frozenset({".css", ".js", ".ico", ".png", ".jpg", ".txt", ".woff"})

    def expected_attack_class(self) -> str:
        return "web_cache_deception"

    def expected_proof_type(self) -> str:
        return "absolute"

    def validate(self, attack_probe: RawProbe, control_probe: RawProbe | None) -> ProofArtifact | None:
        del control_probe

        request = attack_probe.request
        response = attack_probe.response

        url = self._extract_url(request)
        if url is None:
            return None

        parsed = urlparse(url)
        url_path = parsed.path or "/"
        if not any(url_path.lower().endswith(ext) for ext in self._STATIC_EXTENSIONS):
            return None

        status_code = self._extract_status(response)
        if status_code != 200:
            return None

        response_json = self._extract_json_body(response)
        if response_json is None:
            return None

        matched_names = sorted(name for name in response_json if name.lower() in self._PRIVATE_FIELD_NAMES)
        if not matched_names:
            return None

        confidence = self._CONFIDENCE
        if confidence < self._MIN_PROOF_CONFIDENCE_THRESHOLD:
            return None

        fingerprint = {
            "path": url_path,
            "detected_field_names": matched_names,
            "status_code": status_code,
        }

        return ProofArtifact(
            attack_task_id=attack_probe.attack_task_id,
            finding_id=uuid5(NAMESPACE_URL, f"web_cache_deception:{url_path}"),
            proof_type=self.expected_proof_type(),
            confidence_score=confidence,
            attack_probe_id=attack_probe.id,
            control_probe_id=None,
            state_diff=fingerprint,
            summary="web_cache_deception: private fields accessible via static extension path",
            evidence_notes=json.dumps(fingerprint, sort_keys=True, separators=(",", ":")),
        )

    def _extract_url(self, request: dict[str, Any]) -> str | None:
        for key in ("url", "request_url", "target_url"):
            value = request.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
        return None

    def _extract_status(self, response: dict[str, Any]) -> int | None:
        for key in ("status", "status_code", "code"):
            value = response.get(key)
            if isinstance(value, int):
                return value
            if isinstance(value, str) and value.isdigit():
                return int(value)
        return None

    def _extract_json_body(self, response: dict[str, Any]) -> dict[str, Any] | None:
        body = response.get("body")
        if isinstance(body, dict):
            return body
        if not isinstance(body, str):
            return None
        try:
            parsed = json.loads(body)
        except (TypeError, ValueError):
            return None
        if not isinstance(parsed, dict):
            return None
        return parsed


class CachePoisoningStrategy(ValidationStrategy):
    _CONFIDENCE = 0.87
    _MIN_PROOF_CONFIDENCE_THRESHOLD = 0.85
    _REFLECTION_HEADERS = frozenset({"location", "access-control-allow-origin", "content-location"})

    def expected_attack_class(self) -> str:
        return "cache_poisoning"

    def expected_proof_type(self) -> str:
        return "absolute"

    def validate(self, attack_probe: RawProbe, control_probe: RawProbe | None) -> ProofArtifact | None:
        del control_probe

        request = attack_probe.request
        response = attack_probe.response

        injected = self._extract_injected_host(request)
        if injected is None:
            return None

        header_name_used, injected_host = injected
        reflection = self._find_reflection(response=response, injected_host=injected_host)
        if reflection is None:
            return None

        confidence = self._CONFIDENCE
        if confidence < self._MIN_PROOF_CONFIDENCE_THRESHOLD:
            return None

        url = self._extract_url(request) or ""
        fingerprint = {
            "injected_header": header_name_used,
            "injected_value": injected_host,
            "reflection_location": reflection,
        }

        return ProofArtifact(
            attack_task_id=attack_probe.attack_task_id,
            finding_id=uuid5(NAMESPACE_URL, f"cache_poisoning:{url}:{injected_host}"),
            proof_type=self.expected_proof_type(),
            confidence_score=confidence,
            attack_probe_id=attack_probe.id,
            control_probe_id=None,
            state_diff=fingerprint,
            summary="cache_poisoning: injected host reflected in cache-influencing response channel",
            evidence_notes=json.dumps(fingerprint, sort_keys=True, separators=(",", ":")),
        )

    def _extract_url(self, request: dict[str, Any]) -> str | None:
        for key in ("url", "request_url", "target_url"):
            value = request.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
        return None

    def _extract_injected_host(self, request: dict[str, Any]) -> tuple[str, str] | None:
        headers = request.get("headers")
        if isinstance(headers, dict):
            for key in ("X-Forwarded-Host", "X-Host"):
                value = headers.get(key)
                if isinstance(value, str) and value.strip():
                    return key, value.strip()
                lowered_value = headers.get(key.lower())
                if isinstance(lowered_value, str) and lowered_value.strip():
                    return key, lowered_value.strip()

        for key in ("X-Forwarded-Host", "X-Host", "x-forwarded-host", "x-host"):
            value = request.get(key)
            if isinstance(value, str) and value.strip():
                normalized = "X-Forwarded-Host" if key.lower() == "x-forwarded-host" else "X-Host"
                return normalized, value.strip()

        return None

    def _find_reflection(self, *, response: dict[str, Any], injected_host: str) -> str | None:
        headers = response.get("headers")
        if isinstance(headers, dict):
            for key, value in headers.items():
                header_name = str(key).lower()
                if header_name not in self._REFLECTION_HEADERS:
                    continue
                if isinstance(value, str) and injected_host in value:
                    return f"header:{header_name}"
                if isinstance(value, list):
                    for item in value:
                        if isinstance(item, str) and injected_host in item:
                            return f"header:{header_name}"

        body = response.get("body")
        if isinstance(body, str) and injected_host in body:
            return "body"

        return None
