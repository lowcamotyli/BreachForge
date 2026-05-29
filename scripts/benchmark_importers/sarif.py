from __future__ import annotations

from typing import Any

from scripts.benchmark_importers.base import ImportedFinding, map_to_attack_class


class SarifImporter:
    LEVEL_TO_CONFIDENCE = {"error": 0.9, "warning": 0.7, "note": 0.4}

    def parse(self, data: dict[str, Any]) -> list[ImportedFinding]:
        try:
            runs = data.get("runs")
            if not isinstance(runs, list):
                return []
            findings: list[ImportedFinding] = []
            for run in runs:
                if isinstance(run, dict):
                    findings.extend(self._from_run(run))
            return findings
        except Exception:
            return []

    def _from_run(self, run: dict[str, Any]) -> list[ImportedFinding]:
        rules = self._rules_by_id(run)
        results = run.get("results")
        if not isinstance(results, list):
            return []

        findings: list[ImportedFinding] = []
        for result in results:
            if not isinstance(result, dict):
                continue
            rule_id = str(result.get("ruleId") or "")
            category = self._category(rule_id, rules.get(rule_id, []))
            manual_review = category is None
            findings.append(
                ImportedFinding(
                    id=rule_id,
                    source_engine="sarif",
                    finding_type=rule_id,
                    endpoint=self._endpoint(result),
                    method="GET",
                    evidence={"raw": result},
                    confidence=self.LEVEL_TO_CONFIDENCE.get(str(result.get("level") or "").casefold(), 0.5),
                    manual_review_flag=manual_review,
                    category=category or "unknown",
                )
            )
        return findings

    def _rules_by_id(self, run: dict[str, Any]) -> dict[str, list[str]]:
        driver = (
            run.get("tool", {})
            if isinstance(run.get("tool"), dict)
            else {}
        ).get("driver", {})
        rules = driver.get("rules") if isinstance(driver, dict) else []
        if not isinstance(rules, list):
            return {}

        by_id: dict[str, list[str]] = {}
        for rule in rules:
            if not isinstance(rule, dict):
                continue
            rule_id = str(rule.get("id") or "")
            properties = rule.get("properties") if isinstance(rule.get("properties"), dict) else {}
            tags = properties.get("tags")
            by_id[rule_id] = [str(tag) for tag in tags] if isinstance(tags, list) else []
        return by_id

    def _category(self, rule_id: str, tags: list[str]) -> str | None:
        category = map_to_attack_class(rule_id)
        if category is not None:
            return category
        for tag in tags:
            category = map_to_attack_class(tag)
            if category is not None:
                return category
        return None

    def _endpoint(self, result: dict[str, Any]) -> str:
        locations = result.get("locations")
        if not isinstance(locations, list) or not locations:
            return ""
        location = locations[0]
        if not isinstance(location, dict):
            return ""
        physical = location.get("physicalLocation")
        if not isinstance(physical, dict):
            return ""
        artifact = physical.get("artifactLocation")
        if not isinstance(artifact, dict):
            return ""
        return str(artifact.get("uri") or "")
