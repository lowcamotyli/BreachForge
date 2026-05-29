from __future__ import annotations

from typing import Any

from scripts.benchmark_importers.base import BaseImporter, map_to_attack_class


class HexStrikeImporter(BaseImporter):
    SEVERITY_MAP = {
        "critical": "HIGH",
        "high": "HIGH",
        "medium": "MEDIUM",
        "low": "LOW",
    }

    def normalize(self, raw: list[dict[str, Any]]) -> list[dict[str, Any]]:
        normalized: list[dict[str, Any]] = []
        for finding in raw:
            if not isinstance(finding, dict):
                continue
            attack_class = map_to_attack_class(str(finding.get("title") or ""))
            normalized.append(
                {
                    "id": str(finding.get("id") or ""),
                    "attack_class": attack_class or "UNKNOWN",
                    "endpoint": str(finding.get("endpoint") or ""),
                    "severity": self.SEVERITY_MAP.get(str(finding.get("severity") or "").casefold(), "MEDIUM"),
                    "confidence": 0.7,
                    "engine": "hexstrike",
                    "raw": finding,
                }
            )
        return normalized
