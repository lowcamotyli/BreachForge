from __future__ import annotations

import json
from typing import List

from execution_plane.planner.rules.base import AssetMap, AttackRule, ScanContext
from storage.db.models import AttackTask, Endpoint


class SecurityHeadersRule(AttackRule):
    requires_auth = False
    attack_class = "security_headers"
    name = "SecurityHeadersRule"

    def matches(self, endpoint: Endpoint, asset_map: AssetMap) -> bool:
        del asset_map
        return endpoint.url_pattern in ("/", "")

    def generate_tasks(self, endpoint: Endpoint, context: ScanContext) -> List[AttackTask]:
        paths = ("/", "/api", "/login")
        analyze_headers = [
            "strict-transport-security",
            "content-security-policy",
            "x-frame-options",
            "x-content-type-options",
            "permissions-policy",
            "access-control-allow-origin",
            "access-control-allow-credentials",
        ]

        tasks: list[AttackTask] = []
        for path in paths:
            tasks.append(
                AttackTask(
                    scan_id=context.scan_id,
                    endpoint_id=endpoint.id,
                    attack_class=self.attack_class,
                    target_parameter="response_headers",
                    hypothesis=json.dumps(
                        {
                            "probe_type": "header_audit",
                            "params": {
                                "method": "GET",
                                "path": path,
                                "analyze_headers": analyze_headers,
                            },
                        },
                        sort_keys=True,
                    ),
                )
            )
        return tasks

    def expected_proof_signal(self) -> str:
        return "Missing or weak security headers detected"
