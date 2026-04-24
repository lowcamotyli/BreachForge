from __future__ import annotations

import json
from typing import List

from execution_plane.planner.rules.base import AssetMap, AttackRule, ScanContext
from storage.db.models import AttackTask, Endpoint

_METHODS: set[str] = {"GET", "POST"}
_PATH_HINTS: tuple[str, ...] = ("login", "auth", "search", "api")
_HEALTH_HINTS: tuple[str, ...] = ("/health", "/status", "/metrics", "/live", "/ready")


class RateLimitAbuseRule(AttackRule):
    attack_class = "rate_limit_abuse"
    name = "RateLimitAbuseRule"

    def matches(self, endpoint: Endpoint, asset_map: AssetMap) -> bool:
        del asset_map
        method = endpoint.method.upper()
        path = endpoint.url_pattern.lower()
        if any(hint in path for hint in _HEALTH_HINTS):
            return False
        if method in _METHODS and any(hint in path for hint in _PATH_HINTS):
            return True
        return endpoint.auth_required

    def generate_tasks(self, endpoint: Endpoint, context: ScanContext) -> List[AttackTask]:
        base_params = {
            "method": endpoint.method.upper(),
            "path": endpoint.url_pattern,
        }
        return [
            AttackTask(
                scan_id=context.scan_id,
                endpoint_id=endpoint.id,
                attack_class=self.attack_class,
                target_parameter="rate_limit",
                hypothesis=json.dumps(
                    {
                        "probe_type": "burst",
                        "params": {
                            **base_params,
                            "count": 10,
                            "interval_ms": 0,
                        },
                    },
                    sort_keys=True,
                ),
            ),
            AttackTask(
                scan_id=context.scan_id,
                endpoint_id=endpoint.id,
                attack_class=self.attack_class,
                target_parameter="rate_limit",
                hypothesis=json.dumps(
                    {
                        "probe_type": "staircase",
                        "params": {
                            **base_params,
                            "steps": [1, 2, 5, 10],
                            "interval_ms": 500,
                        },
                    },
                    sort_keys=True,
                ),
            ),
            AttackTask(
                scan_id=context.scan_id,
                endpoint_id=endpoint.id,
                attack_class=self.attack_class,
                target_parameter="retry-after",
                hypothesis=json.dumps(
                    {
                        "probe_type": "retry_after",
                        "params": {
                            **base_params,
                            "count": 5,
                        },
                    },
                    sort_keys=True,
                ),
            ),
        ]

    def expected_proof_signal(self) -> str:
        return "Rate limiting is absent, inconsistent, or bypassable under repeated request pressure"
