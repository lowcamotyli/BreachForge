from __future__ import annotations

import hashlib
import structlog
from typing import Any

logger = structlog.get_logger()


class AuditorExporter:
    """Renders auditor-focused compliance summary for scan review."""

    _OWASP_API_TOP10_2023: tuple[str, ...] = (
        "broken_object_level_auth",
        "broken_authentication",
        "broken_object_property_level_auth",
        "unrestricted_resource_consumption",
        "broken_function_level_auth",
        "unrestricted_access_to_sensitive_business_flows",
        "server_side_request_forgery",
        "security_misconfiguration",
        "improper_inventory_management",
        "unsafe_consumption_of_apis",
    )

    def export(self, scan_data: dict, findings: list[dict]) -> dict:
        """Returns structured auditor report dict."""
        tested_classes = self._tested_classes(findings)
        tested_set = set(tested_classes)

        unique_paths = {str(f.get("path", "")) for f in findings}

        sessions_established = int(scan_data.get("sessions_established", 0) or 0)
        auth_failures = int(scan_data.get("auth_failures", 0) or 0)

        confidence_values = self._confidence_values(findings)
        avg_confidence = (
            sum(confidence_values) / len(confidence_values) if confidence_values else 0.0
        )

        return {
            "schema_version": "1.0",
            "persona": "auditor",
            "scope": {
                "target_url": scan_data.get("target_url", ""),
                "scan_start": scan_data.get("scan_start"),
                "scan_end": scan_data.get("scan_end"),
                "total_endpoints_tested": len(unique_paths),
            },
            "policy_compliance": {
                "owasp_api_top10": {
                    "tested": tested_classes,
                    "not_tested": [
                        c for c in self._OWASP_API_TOP10_2023 if c not in tested_set
                    ],
                },
                "total_classes_covered": len(tested_classes),
            },
            "auth_reliability": {
                "sessions_established": sessions_established,
                "auth_failures": auth_failures,
                "re_auth_required": int(scan_data.get("re_auth_required", 0) or 0),
                "reliability_score": sessions_established
                / max(1, sessions_established + auth_failures),
            },
            "evidence_integrity": {
                "total_findings": len(findings),
                "findings_with_proof": sum(
                    1
                    for f in findings
                    if self._safe_float(f.get("confidence_score")) >= 0.85
                ),
                "avg_confidence_score": avg_confidence,
                "evidence_hashes": {
                    str(f.get("finding_id", "")): hashlib.sha256(
                        str(f.get("finding_id", "")).encode()
                    ).hexdigest()
                    for f in findings
                },
            },
            "blocked_classes": self._status_classes(findings, "blocked"),
            "skipped_classes": self._status_classes(findings, "skipped"),
        }

    def _tested_classes(self, findings: list[dict]) -> list[str]:
        tested: list[str] = []
        seen: set[str] = set()

        for f in findings:
            attack_class = str(f.get("attack_class", "") or "")
            if not attack_class or attack_class in seen:
                continue
            tested.append(attack_class)
            seen.add(attack_class)

        return tested

    def _status_classes(self, findings: list[dict], status: str) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for f in findings:
            if f.get("status") != status:
                continue
            rows.append(
                {
                    "attack_class": f.get("attack_class"),
                    "reason": f.get("reason", ""),
                }
            )
        return rows

    def _confidence_values(self, findings: list[dict]) -> list[float]:
        return [self._safe_float(f.get("confidence_score")) for f in findings]

    def _safe_float(self, value: Any) -> float:
        try:
            if value is None:
                return 0.0
            return float(value)
        except (TypeError, ValueError):
            return 0.0
