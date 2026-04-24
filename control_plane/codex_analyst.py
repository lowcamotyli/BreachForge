from __future__ import annotations

from collections import Counter
from typing import Any


class CodexAnalyst:
    """Advisory analyzer for next-step hypotheses.

    This component is planner input only. It does not create findings and does
    not participate in proof-gate decisions.
    """

    def suggest_next_actions(
        self,
        asset_map_summary: dict[str, Any],
        probe_history: list[dict[str, Any]],
        step_context: dict[str, Any],
    ) -> list[dict[str, Any]]:
        endpoints = self._extract_endpoints(asset_map_summary)
        endpoint_failure_counts = self._failed_probe_counts(probe_history)
        preferred_actions = self._preferred_actions(step_context)

        hypotheses: list[dict[str, Any]] = []
        for endpoint in endpoints:
            endpoint_path = str(endpoint.get("url_pattern") or endpoint.get("endpoint") or "")
            method = str(endpoint.get("method") or "GET").upper()
            failures = endpoint_failure_counts.get(endpoint_path, 0)

            for action in preferred_actions:
                priority = self._priority_for(action=action, method=method, failures=failures)
                hypotheses.append(
                    {
                        "action": action,
                        "endpoint": endpoint_path,
                        "priority": priority,
                        "rationale": self._rationale(action=action, method=method, failures=failures),
                    }
                )

        hypotheses.sort(key=lambda item: float(item["priority"]), reverse=True)
        return hypotheses

    def _extract_endpoints(self, asset_map_summary: dict[str, Any]) -> list[dict[str, Any]]:
        raw_endpoints = asset_map_summary.get("endpoints")
        if isinstance(raw_endpoints, list):
            return [item for item in raw_endpoints if isinstance(item, dict)]
        return []

    def _failed_probe_counts(self, probe_history: list[dict[str, Any]]) -> dict[str, int]:
        counter: Counter[str] = Counter()
        for probe in probe_history:
            endpoint = str(probe.get("endpoint") or "")
            status = str(probe.get("status") or "").lower()
            if endpoint and status in {"failed", "blocked", "no_signal"}:
                counter[endpoint] += 1
        return dict(counter)

    def _preferred_actions(self, step_context: dict[str, Any]) -> list[str]:
        raw_actions = step_context.get("candidate_actions")
        if isinstance(raw_actions, list):
            normalized = [str(item).strip() for item in raw_actions if str(item).strip()]
            if normalized:
                return normalized
        return ["bola_probe", "authz_probe", "state_change_probe"]

    def _priority_for(self, *, action: str, method: str, failures: int) -> float:
        base = 0.5
        if action in {"bola_probe", "authz_probe"}:
            base += 0.2
        if method in {"POST", "PUT", "PATCH", "DELETE"}:
            base += 0.2
        if failures > 0:
            base += min(failures * 0.05, 0.2)
        return round(base, 3)

    def _rationale(self, *, action: str, method: str, failures: int) -> str:
        details = [f"action={action}", f"method={method}"]
        if failures:
            details.append(f"prior_failures={failures}")
        else:
            details.append("no_recent_failures")
        return "; ".join(details)
