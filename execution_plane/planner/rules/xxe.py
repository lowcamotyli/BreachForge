from __future__ import annotations

import json
from typing import Any

from execution_plane.planner.rules.base import AssetMap, AttackRule, ScanContext
from storage.db.models import AttackTask, Endpoint

_XML_CONTENT_TYPES: tuple[str, ...] = (
    "application/xml",
    "text/xml",
    "application/soap+xml",
)
_XML_UPLOAD_EXTENSIONS: tuple[str, ...] = (".docx", ".xlsx", ".svg", ".xsd")
_FILE_PARAMETER_NAMES: set[str] = {"file"}


class XxeRule(AttackRule):
    requires_auth = False
    attack_class = "xxe"
    name = "XxeRule"

    def matches(self, endpoint: Endpoint, asset_map: AssetMap) -> bool:
        _ = asset_map
        if self._has_xml_content_type(endpoint):
            return True
        if self._has_xml_upload_extension(endpoint):
            return True
        return self._has_file_parameter(endpoint)

    def generate_tasks(self, endpoint: Endpoint, context: ScanContext) -> list[AttackTask]:
        tasks: list[AttackTask] = []
        probe_types: tuple[str, ...] = ("xxe_classic", "xxe_error", "xxe_blind")
        for probe_type in probe_types:
            hypothesis = {
                "probe_type": probe_type,
                "requires_auth": False,
                "method": "POST",
            }
            tasks.append(
                AttackTask(
                    scan_id=context.scan_id,
                    endpoint_id=endpoint.id,
                    attack_class=self.attack_class,
                    target_parameter="body.xml",
                    hypothesis=json.dumps(hypothesis, sort_keys=True),
                    priority_score=0.8 if probe_type == "xxe_classic" else 0.7,
                )
            )
        return tasks

    def expected_proof_signal(self) -> str:
        return "file_content_or_parser_error_in_response"

    def _has_xml_content_type(self, endpoint: Endpoint) -> bool:
        content_type = getattr(endpoint, "content_type", None)
        if not isinstance(content_type, str):
            return False
        lowered = content_type.lower()
        return any(marker in lowered for marker in _XML_CONTENT_TYPES)

    def _has_xml_upload_extension(self, endpoint: Endpoint) -> bool:
        path = getattr(endpoint, "path", None)
        if not isinstance(path, str):
            return False
        lowered = path.lower()
        return any(lowered.endswith(ext) for ext in _XML_UPLOAD_EXTENSIONS)

    def _has_file_parameter(self, endpoint: Endpoint) -> bool:
        for parameter in endpoint.parameters:
            if not isinstance(parameter, dict):
                continue
            raw_name = parameter.get("name")
            if not isinstance(raw_name, str):
                continue
            if raw_name.strip().lower() in _FILE_PARAMETER_NAMES:
                return True
            if self._path_like_filename(parameter.get("example")):
                return True
            if self._path_like_filename(parameter.get("default")):
                return True
            if self._path_like_filename(parameter.get("value")):
                return True
        return False

    def _path_like_filename(self, value: Any) -> bool:
        if not isinstance(value, str):
            return False
        lowered = value.strip().lower()
        return any(lowered.endswith(ext) for ext in _XML_UPLOAD_EXTENSIONS)
