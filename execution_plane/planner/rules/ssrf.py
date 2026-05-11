from __future__ import annotations

import json
import re
from typing import Any

from execution_plane.planner.rules.base import AssetMap, AttackRule, ScanContext
from storage.db.models import AttackTask, Endpoint

_SSRF_PARAMETER_NAMES: set[str] = {
    "url",
    "endpoint",
    "callback",
    "redirect",
    "webhook",
    "src",
    "href",
    "fetch",
    "load",
    "file",
}
_SSRF_NAME_PARTS: tuple[str, ...] = ("url", "uri", "callback", "redirect", "webhook", "endpoint")
_URL_VALUE_RE = re.compile(r"^(?:https?|file|gopher|dict)://", re.IGNORECASE)
_SUPPORTED_LOCATIONS: set[str] = {"query", "body", "form", "json"}


class SsrfRule(AttackRule):
    requires_auth = False
    attack_class = "ssrf"
    name = "SsrfRule"

    def matches(self, endpoint: Endpoint, asset_map: AssetMap) -> bool:
        return bool(self._ssrf_parameters(endpoint=endpoint, asset_map=asset_map))

    def generate_tasks(self, endpoint: Endpoint, context: ScanContext) -> list[AttackTask]:
        tasks: list[AttackTask] = []
        for candidate in self._ssrf_parameters(endpoint=endpoint, asset_map=context.asset_map):
            hypothesis = {
                "probe_type": "ssrf_metadata",
                "target_parameter": candidate["name"],
                "parameter_location": candidate["location"],
                "risk": candidate["risk"],
                "requires_auth": False,
                "allowed_targets": [
                    "http://169.254.169.254/latest/meta-data/",
                    "http://100.100.100.200/",
                    "http://metadata.google.internal/",
                ],
                "method": "GET",
            }
            tasks.append(
                AttackTask(
                    scan_id=context.scan_id,
                    endpoint_id=endpoint.id,
                    attack_class=self.attack_class,
                    target_parameter=str(candidate["target_parameter"]),
                    hypothesis=json.dumps(hypothesis, sort_keys=True),
                    priority_score=0.85 if candidate["risk"] == "high" else 0.65,
                )
            )
        return tasks

    def expected_proof_signal(self) -> str:
        return "Server-side fetch reaches cloud metadata, internal service, or restricted protocol target"

    def _ssrf_parameters(self, *, endpoint: Endpoint, asset_map: AssetMap) -> list[dict[str, str]]:
        candidates: list[dict[str, str]] = []
        seen: set[str] = set()

        def add(location: str, name: str, source: str) -> None:
            normalized_name = name.strip()
            if not normalized_name:
                return
            normalized_location = location.strip().lower()
            if normalized_location in {"form", "json"}:
                normalized_location = "body"
            if normalized_location not in {"query", "body", "har"}:
                return
            key = f"{normalized_location}:{normalized_name.lower()}"
            if key in seen:
                return
            seen.add(key)

            lowered = normalized_name.lower()
            exact = lowered in _SSRF_PARAMETER_NAMES
            risk = "high" if exact or lowered in {"callback", "webhook", "url"} else "medium"
            candidates.append(
                {
                    "location": normalized_location,
                    "name": normalized_name,
                    "risk": risk,
                    "source": source,
                    "target_parameter": normalized_name
                    if normalized_location == "har"
                    else f"{normalized_location}.{normalized_name}",
                }
            )

        for parameter in endpoint.parameters:
            if not isinstance(parameter, dict):
                continue
            location = str(parameter.get("in") or parameter.get("location") or "").lower()
            if location not in _SUPPORTED_LOCATIONS:
                continue
            raw_name = parameter.get("name")
            if not isinstance(raw_name, str):
                continue
            name = raw_name.strip()
            if not name:
                continue
            example = parameter.get("example") or parameter.get("value") or parameter.get("default")
            if self._looks_like_ssrf_name(name) or self._looks_like_url_value(example):
                add(location, name, "endpoint_parameter")

        for name in self._har_parameter_hints(asset_map):
            add("har", name, "har_hint")

        return candidates

    def _looks_like_ssrf_name(self, name: str) -> bool:
        lowered = name.lower()
        return lowered in _SSRF_PARAMETER_NAMES or any(part in lowered for part in _SSRF_NAME_PARTS)

    def _looks_like_url_value(self, value: Any) -> bool:
        if not isinstance(value, str):
            return False
        return bool(_URL_VALUE_RE.match(value.strip()))

    def _har_parameter_hints(self, asset_map: AssetMap) -> list[str]:
        raw_signals = getattr(asset_map, "signals", None)
        if raw_signals is None:
            raw_signals = getattr(asset_map, "planning_signals", None)
        if not isinstance(raw_signals, dict):
            return []

        names: list[str] = []
        for key in ("har_url_params", "har_body_fields", "url_parameters"):
            value = raw_signals.get(key)
            if isinstance(value, list):
                names.extend(str(item) for item in value if isinstance(item, str))
        return [name for name in names if self._looks_like_ssrf_name(name)]
