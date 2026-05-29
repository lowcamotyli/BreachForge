from __future__ import annotations

import structlog
from typing import Any

logger = structlog.get_logger()


class DeveloperExporter:
    """Renders per-finding developer detail for remediation workflow."""

    _FIX_HINTS: dict[str, str] = {
        "broken_object_level_auth": "Add ownership check before returning resource data.",
        "broken_authentication": "Enforce token expiry and rotate credentials after exposure.",
        "broken_object_property_level_auth": "Allowlist returned fields; strip sensitive properties server-side.",
        "unrestricted_resource_consumption": "Apply rate limits and pagination caps on this endpoint.",
        "broken_function_level_auth": "Verify caller role/scope before executing privileged action.",
        "unrestricted_access_to_sensitive_business_flows": "Add bot-detection and business-logic rate limits.",
        "server_side_request_forgery": "Validate and allowlist outbound URL targets.",
        "security_misconfiguration": "Audit default credentials, debug flags, and exposed admin routes.",
        "improper_inventory_management": "Remove deprecated endpoints or add auth; update API inventory.",
        "unsafe_consumption_of_apis": "Validate and sanitize all data received from upstream APIs.",
    }

    def export(self, findings: list[dict[str, Any]], scan_data: dict[str, Any]) -> dict[str, Any]:
        """Returns structured developer report dict."""
        entries = []
        for f in findings:
            entries.append(self._render_finding(f))
        return {"schema_version": "1.0", "persona": "developer", "findings": entries}

    def _render_finding(self, f: dict[str, Any]) -> dict[str, Any]:
        meta = f.get("metadata", {})
        affected_endpoint = f'{f.get("method", "")} {f.get("path", "")}'.strip()
        return {
            "finding_id": f.get("id") or f.get("finding_id"),
            "attack_class": f.get("attack_class"),
            "severity": f.get("severity"),
            "affected_endpoint": affected_endpoint,
            "proof": {
                "confidence_score": f.get("confidence_score"),
                "artifact_type": f.get("artifact_type"),
            },
            "replay": self._build_replay(f),
            "owner": meta.get("owner") or "unassigned",
            "fix_hint": self._fix_hint(f.get("attack_class", "")),
            "state_diff": meta.get("state_diff"),
        }

    def _build_replay(self, f: dict[str, Any]) -> str | None:
        req = f.get("request") or f.get("metadata", {}).get("request")
        if not req:
            return None
        method = req.get("method", "GET")
        url = req.get("url", "")
        headers = {
            k: "[REDACTED]" if k.lower() in ("authorization", "cookie") else v
            for k, v in (req.get("headers") or {}).items()
        }
        header_flags = " ".join(f'-H "{k}: {v}"' for k, v in headers.items())
        body = req.get("body")
        body_flag = f' -d "{body}"' if body else ""
        return f"curl -X {method} {url} {header_flags}{body_flag}".strip()

    def _fix_hint(self, attack_class: str) -> str:
        return self._FIX_HINTS.get(attack_class, "Review attack class documentation for remediation guidance.")
