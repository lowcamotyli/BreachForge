from __future__ import annotations

import json
from typing import Any

from scripts.benchmark_importers.base import ImportedFinding, map_to_attack_class


class NucleiImporter:
    SEVERITY_TO_CONFIDENCE = {
        "critical": 0.95,
        "high": 0.9,
        "medium": 0.7,
        "low": 0.4,
        "info": 0.2,
    }

    def parse_jsonl(self, content: str) -> list[ImportedFinding]:
        findings: list[ImportedFinding] = []
        for line in content.splitlines():
            if not line.strip():
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(item, dict):
                findings.append(self._from_item(item))
        return findings

    def _from_item(self, item: dict[str, Any]) -> ImportedFinding:
        info = item.get("info") if isinstance(item.get("info"), dict) else {}
        request = item.get("request") if isinstance(item.get("request"), dict) else {}
        template_id = str(item.get("template-id") or "")
        tags = info.get("tags") if isinstance(info, dict) else []
        category = map_to_attack_class(template_id)
        if category is None and isinstance(tags, list):
            for tag in tags:
                category = map_to_attack_class(str(tag))
                if category is not None:
                    break

        manual_review = category is None
        return ImportedFinding(
            id=template_id,
            source_engine="nuclei",
            finding_type=str(info.get("name") or template_id),
            endpoint=str(item.get("matched-at") or ""),
            method=str(request.get("method") or "GET"),
            evidence={"raw": item},
            confidence=self.SEVERITY_TO_CONFIDENCE.get(str(info.get("severity") or "").casefold(), 0.5),
            manual_review_flag=manual_review,
            category=category or "unknown",
        )
