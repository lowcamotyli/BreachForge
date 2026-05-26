from __future__ import annotations

import json
import re

from execution_plane.planner.rules.base import AssetMap, AttackRule, ScanContext
from storage.db.models import AttackTask, Endpoint

_TENANT_IDENTIFIERS: tuple[str, ...] = ("org_id", "tenant_id", "company_id", "account_id")
_PATH_PARAM_RE = re.compile(r"\{([a-zA-Z_][a-zA-Z0-9_]*)\}")


class TenantIsolation(AttackRule):
    requires_auth = False
    attack_class = "tenant_isolation"
    name = "TenantIsolation"

    def matches(self, endpoint: Endpoint, asset_map: AssetMap) -> bool:
        del asset_map
        lower_url = endpoint.url_pattern.lower()
        if any(identifier in lower_url for identifier in _TENANT_IDENTIFIERS):
            return True
        for parameter in endpoint.parameters:
            raw_name = parameter.get("name")
            if isinstance(raw_name, str) and raw_name.lower() in _TENANT_IDENTIFIERS:
                return True
        return False

    def generate_tasks(
        self,
        endpoint: Endpoint,
        context: ScanContext,
        identity_pairs: list[tuple[str, str]] | None = None,
    ) -> list[AttackTask]:
        tenant_params: list[str] = []
        seen: set[str] = set()

        for parameter in endpoint.parameters:
            raw_name = parameter.get("name")
            if not isinstance(raw_name, str):
                continue
            name = raw_name.lower()
            if name in _TENANT_IDENTIFIERS and name not in seen:
                seen.add(name)
                tenant_params.append(name)

        for match in _PATH_PARAM_RE.finditer(endpoint.url_pattern):
            name = match.group(1).lower()
            if name in _TENANT_IDENTIFIERS and name not in seen:
                seen.add(name)
                tenant_params.append(name)

        if not tenant_params:
            tenant_params.append("tenant_id")

        hypothesis = "Substitute tenant identifier to access another tenant data"
        differential_pairs = identity_pairs or []
        tasks: list[AttackTask] = []
        for parameter_name in tenant_params:
            if differential_pairs:
                for owner_name, attacker_name in differential_pairs:
                    tasks.append(
                        AttackTask(
                            scan_id=context.scan_id,
                            endpoint_id=endpoint.id,
                            attack_class=self.attack_class,
                            target_parameter=parameter_name,
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
                    target_parameter=parameter_name,
                    hypothesis=hypothesis,
                )
            )
        return tasks

    def expected_proof_signal(self) -> str:
        return "Response contains tenant-identifying markers from another tenant"
