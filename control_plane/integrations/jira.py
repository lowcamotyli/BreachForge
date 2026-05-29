from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import httpx


@dataclass(frozen=True)
class JiraAdapter:
    def severity_to_priority(self, severity: str) -> str:
        mapping = {
            "critical": "Highest",
            "high": "High",
            "medium": "Medium",
            "info": "Low",
        }
        return mapping.get(str(severity).strip().lower(), "Medium")

    def format_description(self, finding: dict[str, Any]) -> str:
        attack_class = finding.get("attack_class") or "unknown"
        severity = finding.get("severity") or "unknown"
        repro_steps = finding.get("repro_steps") or "Not provided."
        fix_guidance = finding.get("fix_guidance") or "Not provided."

        lines = [
            "## Summary",
            f"- Attack class: {attack_class}",
            f"- Severity: {severity}",
            "",
            "## Reproduction Steps",
            self._stringify_block(repro_steps),
            "",
            "## Fix Guidance",
            self._stringify_block(fix_guidance),
            "",
            "## Evidence",
        ]

        for key, label in [
            ("proof_hash", "Proof hash"),
            ("safety_label", "Safety label"),
            ("owner_team", "Owner team"),
            ("owner_service", "Owner service"),
            ("owner_confidence", "Owner confidence"),
        ]:
            value = finding.get(key)
            if value not in (None, ""):
                lines.append(f"- {label}: {value}")

        replay_exports = finding.get("replay_exports")
        curl_cmd: str | None = None
        if isinstance(replay_exports, dict):
            curl_value = replay_exports.get("curl")
            if curl_value not in (None, ""):
                curl_cmd = str(curl_value)

        if curl_cmd:
            lines.extend(
                [
                    "",
                    "## Replay Exports",
                    "```bash",
                    curl_cmd,
                    "```",
                ]
            )

        return "\n".join(lines)[:32000]

    async def create_issue(
        self,
        finding: dict[str, Any],
        project_key: str,
        jira_url: str,
        token: str,
    ) -> str:
        url = f"{jira_url.rstrip('/')}/rest/api/2/issue"
        severity = str(finding.get("severity") or "unknown")
        summary = str(finding.get("title") or "Security finding")[:255]
        description = self.format_description(finding)

        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.post(
                url,
                headers={
                    "Authorization": f"Basic {token}",
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                },
                json={
                    "fields": {
                        "project": {"key": project_key},
                        "summary": summary,
                        "description": description,
                        "issuetype": {"name": "Bug"},
                        "priority": {"name": self.severity_to_priority(severity)},
                    }
                },
            )
        response.raise_for_status()
        payload = response.json()
        return str(payload["key"])

    def _stringify_block(self, value: Any) -> str:
        if isinstance(value, list):
            return "\n".join(f"{idx}. {item}" for idx, item in enumerate(value, start=1))
        return str(value)
