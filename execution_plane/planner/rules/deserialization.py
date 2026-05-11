from __future__ import annotations

import json
import re
from typing import Any, ClassVar

from execution_plane.planner.rules.base import AssetMap, AttackRule, ScanContext
from storage.db.models import AttackTask, Endpoint

_BINARY_CONTENT_TYPES: set[str] = {
    "application/x-java-serialized-object",
    "application/octet-stream",
}
_YAML_CONTENT_TYPES: set[str] = {
    "application/x-yaml",
    "text/yaml",
    "application/yaml",
}
_FORM_CONTENT_TYPE = "application/x-www-form-urlencoded"
_BASE64_BLOB_RE = re.compile(r"(?:^|[^A-Za-z0-9+/=])[A-Za-z0-9+/]{40,}={0,2}(?:[^A-Za-z0-9+/=]|$)")


class DeserializationRule(AttackRule):
    requires_auth = False
    attack_class: ClassVar[str] = "deserialization"
    name: ClassVar[str] = "DeserializationRule"

    def matches(self, endpoint: Endpoint, asset_map: AssetMap) -> bool:
        del asset_map
        content_types = self._content_types(endpoint)
        if content_types & _BINARY_CONTENT_TYPES:
            return True
        if content_types & _YAML_CONTENT_TYPES:
            return True
        return _FORM_CONTENT_TYPE in content_types and self._has_base64_blob_parameter(endpoint)

    def generate_tasks(self, endpoint: Endpoint, context: ScanContext) -> list[AttackTask]:
        hypotheses: list[dict[str, Any]] = [
            {
                "probe_type": "deserialization_probe",
                "requires_auth": False,
                "mode": "truncated_or_malformed_serialized_payload",
            },
            {
                "probe_type": "yaml_deserialization",
                "requires_auth": False,
                "mode": "safe_yaml_probe",
            },
        ]

        tasks: list[AttackTask] = []
        for hypothesis in hypotheses:
            tasks.append(
                AttackTask(
                    scan_id=context.scan_id,
                    endpoint_id=endpoint.id,
                    attack_class=self.attack_class,
                    target_parameter="body",
                    hypothesis=json.dumps(hypothesis, sort_keys=True),
                    priority_score=0.8,
                )
            )
        return tasks

    def expected_proof_signal(self) -> str:
        return "framework_error_or_timeout_in_response"

    def _content_types(self, endpoint: Endpoint) -> set[str]:
        collected: set[str] = set()

        def add(value: Any) -> None:
            if isinstance(value, str):
                normalized = value.split(";", 1)[0].strip().lower()
                if normalized:
                    collected.add(normalized)
            elif isinstance(value, list):
                for item in value:
                    add(item)

        for attr in ("content_type", "request_content_type", "consumes"):
            add(getattr(endpoint, attr, None))

        for parameter in endpoint.parameters:
            if not isinstance(parameter, dict):
                continue
            add(parameter.get("content_type"))

        return collected

    def _has_base64_blob_parameter(self, endpoint: Endpoint) -> bool:
        for parameter in endpoint.parameters:
            if not isinstance(parameter, dict):
                continue
            location = str(parameter.get("in") or parameter.get("location") or "").strip().lower()
            if location not in {"form", "body", "json", "query"}:
                continue
            for key in ("example", "value", "default"):
                raw = parameter.get(key)
                if isinstance(raw, str) and self._is_base64_blob(raw):
                    return True
        return False

    def _is_base64_blob(self, value: str) -> bool:
        candidate = value.strip()
        if len(candidate) < 40:
            return False
        if _BASE64_BLOB_RE.search(candidate) is None:
            return False
        return True
