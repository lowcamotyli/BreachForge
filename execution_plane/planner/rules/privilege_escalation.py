from __future__ import annotations

import re

from execution_plane.planner.rules.base import AssetMap, AttackRule, ScanContext
from storage.db.models import AttackTask, Endpoint

_PRIVILEGE_PARAMS: tuple[str, ...] = ("role", "user_id", "account_id", "org_id", "scope")
_PATH_PARAM_RE = re.compile(r"\{([a-zA-Z_][a-zA-Z0-9_]*)\}")
_SUPPORTED_LOCATIONS: set[str] = {"path", "query", "body", "json", "form"}


class PrivilegeEscalation(AttackRule):
    requires_auth = False
    attack_class = "privilege_escalation"
    name = "PrivilegeEscalation"

    def matches(self, endpoint: Endpoint, asset_map: AssetMap) -> bool:
        del asset_map
        return bool(self._collect_targets(endpoint))

    def generate_tasks(self, endpoint: Endpoint, context: ScanContext) -> list[AttackTask]:
        substitution_targets = self._collect_targets(endpoint)
        return [
            AttackTask(
                scan_id=context.scan_id,
                endpoint_id=endpoint.id,
                attack_class=self.attack_class,
                target_parameter=target,
                hypothesis=f"Substitute {target} with elevated/foreign value and confirm privilege boundary failure",
            )
            for target in substitution_targets
        ]

    def expected_proof_signal(self) -> str:
        return "Response confirms attacker obtained higher privilege context than baseline"

    def _collect_targets(self, endpoint: Endpoint) -> list[str]:
        substitution_targets: list[str] = []
        seen: set[str] = set()

        def add(location: str, raw_name: str) -> None:
            normalized_name = raw_name.strip().lower()
            if not normalized_name or normalized_name not in _PRIVILEGE_PARAMS:
                return

            normalized_location = location.strip().lower()
            if normalized_location in {"json", "form"}:
                normalized_location = "body"
            if normalized_location not in {"path", "query", "body"}:
                return

            dedupe_key = f"{normalized_location}:{normalized_name}"
            if dedupe_key in seen:
                return
            seen.add(dedupe_key)

            if normalized_location == "path":
                substitution_targets.append(normalized_name)
            else:
                substitution_targets.append(f"{normalized_location}.{normalized_name}")

        for parameter in endpoint.parameters:
            if not isinstance(parameter, dict):
                continue
            location = str(parameter.get("in") or parameter.get("location") or "").lower()
            if location not in _SUPPORTED_LOCATIONS:
                continue
            raw_name = parameter.get("name")
            if not isinstance(raw_name, str):
                continue
            add(location, raw_name)

        for match in _PATH_PARAM_RE.finditer(endpoint.url_pattern):
            add("path", match.group(1))

        return substitution_targets
