from __future__ import annotations

from typing import Any
from uuid import uuid4

from scripts.benchmark_importers.base import ImportedFinding, category_for


class GenericDastImporter:
    SEVERITY_TO_CONFIDENCE = {"high": 0.9, "medium": 0.7, "low": 0.4}

    def parse(self, data: dict[str, Any]) -> list[ImportedFinding]:
        try:
            items = self._items(data)
            return [self._from_item(item) for item in items if isinstance(item, dict)]
        except Exception:
            return []

    def _items(self, data: dict[str, Any]) -> list[Any]:
        for key in ("findings", "results", "issues", "vulnerabilities"):
            value = data.get(key)
            if isinstance(value, list):
                return value
        return []

    def _from_item(self, item: dict[str, Any]) -> ImportedFinding:
        finding_type = str(item.get("type") or item.get("name") or item.get("title") or "")
        category, manual_review = category_for(finding_type)
        return ImportedFinding(
            id=str(item.get("id") or uuid4()),
            source_engine="generic_dast",
            finding_type=finding_type,
            endpoint=str(item.get("url") or item.get("endpoint") or item.get("uri") or ""),
            method=str(item.get("method") or "GET"),
            evidence={"raw": item},
            confidence=self._confidence(item),
            manual_review_flag=manual_review,
            category=category,
        )

    def _confidence(self, item: dict[str, Any]) -> float:
        raw = item.get("confidence", item.get("severity", 0.5))
        if isinstance(raw, int | float):
            return float(raw)
        return self.SEVERITY_TO_CONFIDENCE.get(str(raw).casefold(), 0.5)
