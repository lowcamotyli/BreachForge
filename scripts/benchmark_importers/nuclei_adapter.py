from __future__ import annotations

import json
from typing import Any

from scripts.benchmark_importers.base import BaseImporter


class NucleiImporter(BaseImporter):
    def parse_jsonl(self, text: str) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        for line in text.splitlines():
            if not line.strip():
                continue
            parsed = json.loads(line)
            if isinstance(parsed, dict):
                items.append(parsed)
        return items

    def normalize(self, raw: list[dict[str, Any]]) -> list[dict[str, Any]]:
        normalized: list[dict[str, Any]] = []
        for finding in raw:
            if not isinstance(finding, dict):
                continue
            info = finding.get("info") if isinstance(finding.get("info"), dict) else {}
            attack_class = str(info.get("name") or "").upper().replace("-", "_")
            normalized.append(
                {
                    "id": str(finding.get("template-id") or ""),
                    "attack_class": attack_class or "UNKNOWN",
                    "endpoint": str(finding.get("matched-at") or ""),
                    "severity": str(finding.get("severity") or info.get("severity") or "MEDIUM").upper(),
                    "confidence": 0.6,
                    "engine": "nuclei",
                    "raw": finding,
                }
            )
        return normalized
