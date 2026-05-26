from __future__ import annotations

import json
import re

from execution_plane.planner.rules.base import AssetMap, AttackRule, ScanContext
from storage.db.models import AttackTask, Endpoint

_PATH_ID_TEMPLATE_RE = re.compile(r"\{([a-zA-Z0-9_]*id[a-zA-Z0-9_]*)\}", re.IGNORECASE)
_NUMERIC_SEGMENT_RE = re.compile(r"/\d+(?=/|$)")
_SUPPORTED_LOCATIONS: set[str] = {"path", "query", "body", "form", "json"}


class BolaBidirectional(AttackRule):
    requires_auth = False
    attack_class = "bola"
    name = "BolaBidirectional"

    def matches(self, endpoint: Endpoint, asset_map: AssetMap) -> bool:
        del asset_map
        return (
            endpoint.method.upper() == "GET"
            and bool(self._id_parameters(endpoint))
        )

    def generate_tasks(
        self,
        endpoint: Endpoint,
        context: ScanContext,
        identity_pairs: list[tuple[str, str]] | None = None,
    ) -> list[AttackTask]:
        hypothesis = "Substitute another users resource ID to confirm unauthorized access"
        tasks: list[AttackTask] = []
        differential_pairs = identity_pairs or []
        for parameter in self._id_parameters(endpoint):
            if differential_pairs:
                for owner_name, attacker_name in differential_pairs:
                    tasks.append(
                        AttackTask(
                            scan_id=context.scan_id,
                            endpoint_id=endpoint.id,
                            attack_class=self.attack_class,
                            target_parameter=parameter,
                            hypothesis=json.dumps(
                                {
                                    "hypothesis": hypothesis,
                                    "identity_selector": attacker_name,
                                    "owner_identity": owner_name,
                                    "differential_probe": True,
                                },
                                sort_keys=True,
                            ),
                        )
                    )
                continue
            tasks.append(
                AttackTask(
                    scan_id=context.scan_id,
                    endpoint_id=endpoint.id,
                    attack_class=self.attack_class,
                    target_parameter=parameter,
                    hypothesis=hypothesis,
                )
            )
        return tasks

    def expected_proof_signal(self) -> str:
        return "Response body contains data not belonging to authenticated user"

    def _id_parameters(self, endpoint: Endpoint) -> list[str]:
        parameter_names: list[str] = []
        seen: set[str] = set()

        def add(location: str, name: str) -> None:
            normalized_name = name.strip()
            if not normalized_name:
                return
            normalized_location = location.strip().lower()
            if normalized_location in {"form", "json"}:
                normalized_location = "body"

            dedupe_key = f"{normalized_location}:{normalized_name.lower()}"
            if dedupe_key in seen:
                return
            seen.add(dedupe_key)

            if normalized_location == "path":
                parameter_names.append(normalized_name)
            elif normalized_location in {"query", "body"}:
                parameter_names.append(f"{normalized_location}.{normalized_name}")

        for parameter in endpoint.parameters:
            if not isinstance(parameter, dict):
                continue
            location = str(parameter.get("in") or parameter.get("location") or "").lower()
            if location not in _SUPPORTED_LOCATIONS:
                continue

            name = str(parameter.get("name") or "").strip()
            if not name:
                continue
            if "id" in name.lower():
                add(location, name)

        for template_name in _PATH_ID_TEMPLATE_RE.findall(endpoint.url_pattern):
            add("path", template_name)

        if _NUMERIC_SEGMENT_RE.search(endpoint.url_pattern):
            add("path", "path_id")

        return parameter_names
