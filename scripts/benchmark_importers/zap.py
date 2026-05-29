from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import Any

from scripts.benchmark_importers.base import ImportedFinding, category_for


class ZapImporter:
    RISK_TO_CONFIDENCE = {"High": 0.9, "Medium": 0.7, "Low": 0.4, "Informational": 0.2}
    RISK_CODE_TO_CONFIDENCE = {"3": 0.9, "2": 0.7, "1": 0.4, "0": 0.2}

    def parse_json(self, data: dict[str, Any]) -> list[ImportedFinding]:
        try:
            alerts = self._extract_json_alerts(data)
            return [self._from_alert(alert) for alert in alerts if isinstance(alert, dict)]
        except Exception:
            return []

    def parse_xml(self, content: str) -> list[ImportedFinding]:
        if not content.strip():
            return []
        try:
            root = ET.fromstring(content)
        except ET.ParseError:
            return []

        findings: list[ImportedFinding] = []
        for item in root.findall(".//alertitem"):
            finding_type = self._node_text(item, "alert") or self._node_text(item, "name")
            endpoint = self._node_text(item, "uri")
            method = self._node_text(item, "method") or "GET"
            risk = self._node_text(item, "riskdesc") or self._node_text(item, "risk")
            risk_code = self._node_text(item, "riskcode")
            alert_id = self._node_text(item, "alertRef") or self._node_text(item, "pluginid") or finding_type
            confidence = self._confidence(risk, risk_code)
            category, manual_review = category_for(finding_type)
            findings.append(
                ImportedFinding(
                    id=alert_id,
                    source_engine="zap",
                    finding_type=finding_type,
                    endpoint=endpoint,
                    method=method,
                    evidence={"raw": ET.tostring(item, encoding="unicode")},
                    confidence=confidence,
                    manual_review_flag=manual_review,
                    category=category,
                )
            )
        return findings

    def _extract_json_alerts(self, data: dict[str, Any]) -> list[Any]:
        alerts = data.get("alerts")
        if isinstance(alerts, list):
            return alerts

        sites = data.get("site")
        if not isinstance(sites, list):
            return []

        extracted: list[Any] = []
        for site in sites:
            if not isinstance(site, dict):
                continue
            site_alerts = site.get("alerts")
            if isinstance(site_alerts, list):
                extracted.extend(site_alerts)
        return extracted

    def _from_alert(self, alert: dict[str, Any]) -> ImportedFinding:
        finding_type = str(alert.get("alert") or alert.get("name") or "")
        endpoint = str(alert.get("uri") or alert.get("url") or "")
        method = str(alert.get("method") or "GET")
        alert_id = str(alert.get("alertRef") or alert.get("pluginid") or finding_type)
        risk = str(alert.get("riskdesc") or alert.get("risk") or "")
        category, manual_review = category_for(finding_type)
        return ImportedFinding(
            id=alert_id,
            source_engine="zap",
            finding_type=finding_type,
            endpoint=endpoint,
            method=method,
            evidence={"raw": alert},
            confidence=self._confidence(risk, None),
            manual_review_flag=manual_review,
            category=category,
        )

    def _confidence(self, risk: str, risk_code: str | None) -> float:
        for label, confidence in self.RISK_TO_CONFIDENCE.items():
            if label.casefold() in risk.casefold():
                return confidence
        if risk_code is not None:
            return self.RISK_CODE_TO_CONFIDENCE.get(risk_code, 0.5)
        return 0.5

    def _node_text(self, item: ET.Element, name: str) -> str:
        node = item.find(name)
        if node is None or node.text is None:
            return ""
        return node.text.strip()
