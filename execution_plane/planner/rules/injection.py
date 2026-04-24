from __future__ import annotations

from execution_plane.planner.rules.base import AssetMap, AttackRule, ScanContext
from storage.db.models import AttackTask, Endpoint

_STATE_CHANGING_METHODS: set[str] = {"POST", "PUT", "PATCH", "DELETE"}
_STRING_TYPES: set[str] = {"string", "str", "text"}


class InjectionSql(AttackRule):
    attack_class = "injection"
    name = "InjectionSql"

    def matches(self, endpoint: Endpoint, asset_map: AssetMap) -> bool:
        del asset_map
        return endpoint.method.upper() in _STATE_CHANGING_METHODS and bool(self._string_parameters(endpoint))

    def generate_tasks(self, endpoint: Endpoint, context: ScanContext) -> list[AttackTask]:
        hypothesis_prefix = "Error-based SQL injection probe only"
        tasks: list[AttackTask] = []
        for parameter_name in self._string_parameters(endpoint):
            tasks.append(
                AttackTask(
                    scan_id=context.scan_id,
                    endpoint_id=endpoint.id,
                    attack_class=self.attack_class,
                    target_parameter=parameter_name,
                    hypothesis=(
                        f"{hypothesis_prefix}; parameter={parameter_name}; "
                        "payload='\" OR (SELECT 1/0)--' to trigger SQL parser/DB error signature"
                    ),
                )
            )
        return tasks

    def expected_proof_signal(self) -> str:
        return "Response contains SQL parser/database error signature after malformed input"

    def _string_parameters(self, endpoint: Endpoint) -> list[str]:
        selected: list[str] = []
        seen: set[str] = set()

        for parameter in endpoint.parameters:
            raw_name = parameter.get("name")
            if not isinstance(raw_name, str) or not raw_name.strip():
                continue
            name = raw_name.strip()

            raw_type = str(parameter.get("type") or parameter.get("schema") or "").lower()
            location = str(parameter.get("in") or parameter.get("location") or "").lower()
            if location not in {"query", "path", "body", "form", "json"}:
                continue

            type_is_string = any(token in raw_type for token in _STRING_TYPES)
            if not type_is_string and location in {"query", "path", "form"}:
                type_is_string = True
            if not type_is_string:
                continue

            lowered = name.lower()
            if lowered in seen:
                continue
            seen.add(lowered)
            selected.append(name)

        return selected
