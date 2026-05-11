from __future__ import annotations

import json

from execution_plane.planner.rules.base import AssetMap, AttackRule, ScanContext
from storage.db.models import AttackTask, Endpoint


class AuthBypass(AttackRule):
    requires_auth = True
    attack_class = "auth_bypass"
    name = "AuthBypass"

    def matches(self, endpoint: Endpoint, asset_map: AssetMap) -> bool:
        del asset_map
        return endpoint.auth_required

    def generate_tasks(self, endpoint: Endpoint, context: ScanContext) -> list[AttackTask]:
        return [
            AttackTask(
                scan_id=context.scan_id,
                endpoint_id=endpoint.id,
                attack_class=self.attack_class,
                target_parameter="Authorization",
                hypothesis=json.dumps(
                    {
                        "probe_type": "remove_authorization_header",
                        "mutation": {
                            "headers": {
                                "Authorization": None,
                            }
                        },
                    },
                    sort_keys=True,
                ),
            ),
            AttackTask(
                scan_id=context.scan_id,
                endpoint_id=endpoint.id,
                attack_class=self.attack_class,
                target_parameter="Authorization",
                hypothesis=json.dumps(
                    {
                        "probe_type": "downgrade_to_lower_privilege_token",
                        "mutation": {
                            "headers": {
                                "X-Downgrade-Auth": "true",
                            }
                        },
                    },
                    sort_keys=True,
                ),
            ),
        ]

    def expected_proof_signal(self) -> str:
        return "Unauthenticated response structurally matches authenticated baseline response"
