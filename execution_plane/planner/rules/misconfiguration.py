from __future__ import annotations

import json
from typing import List
from urllib.parse import urlsplit

from execution_plane.planner.rules.base import AssetMap, AttackRule, ScanContext
from storage.db.models import AttackTask, Endpoint

_DEBUG_PATHS: tuple[str, ...] = ("/debug", "/health", "/status", "/actuator")
_UNSAFE_METHODS: tuple[str, ...] = ("TRACE", "OPTIONS")


class MisconfigurationRule(AttackRule):
    requires_auth = False
    attack_class = "misconfiguration"
    name = "MisconfigurationRule"

    def matches(self, endpoint: Endpoint, asset_map: AssetMap) -> bool:
        del endpoint, asset_map
        return True

    def generate_tasks(self, endpoint: Endpoint, context: ScanContext) -> List[AttackTask]:
        if self._is_operational_endpoint(endpoint.url_pattern):
            return []
        base_params = {
            "method": endpoint.method.upper(),
            "path": endpoint.url_pattern,
        }
        debug_targets = self._debug_targets(context.target_url)
        return [
            AttackTask(
                scan_id=context.scan_id,
                endpoint_id=endpoint.id,
                attack_class=self.attack_class,
                target_parameter="Origin",
                hypothesis=json.dumps(
                    {
                        "probe_type": "cors_wildcard",
                        "params": {
                            **base_params,
                            "headers": {"Origin": "https://evil.example.com"},
                        },
                    },
                    sort_keys=True,
                ),
            ),
            AttackTask(
                scan_id=context.scan_id,
                endpoint_id=endpoint.id,
                attack_class=self.attack_class,
                target_parameter="debug_endpoint",
                hypothesis=json.dumps(
                    {
                        "probe_type": "debug_endpoint",
                        "params": {
                            "targets": debug_targets,
                        },
                    },
                    sort_keys=True,
                ),
            ),
            AttackTask(
                scan_id=context.scan_id,
                endpoint_id=endpoint.id,
                attack_class=self.attack_class,
                target_parameter="method",
                hypothesis=json.dumps(
                    {
                        "probe_type": "unsafe_methods",
                        "params": {
                            **base_params,
                            "methods": list(_UNSAFE_METHODS),
                        },
                    },
                    sort_keys=True,
                ),
            ),
            AttackTask(
                scan_id=context.scan_id,
                endpoint_id=endpoint.id,
                attack_class=self.attack_class,
                target_parameter="request_body",
                hypothesis=json.dumps(
                    {
                        "probe_type": "verbose_error",
                        "params": {
                            **base_params,
                            "malformed_body": "{",
                            "content_type": endpoint.observed_content_type or "application/json",
                        },
                    },
                    sort_keys=True,
                ),
            ),
        ]

    def expected_proof_signal(self) -> str:
        return "Configuration weakness exposed via permissive CORS, debug surfaces, unsafe methods, or verbose errors"

    def _debug_targets(self, target_url: str) -> list[str]:
        parsed = urlsplit(target_url)
        origin = f"{parsed.scheme}://{parsed.netloc}" if parsed.scheme and parsed.netloc else target_url.rstrip("/")
        return [f"{origin}{path}" for path in _DEBUG_PATHS]

    def _is_operational_endpoint(self, url_pattern: str) -> bool:
        path = url_pattern.lower()
        return any(path.startswith(prefix) for prefix in ("/health", "/status", "/metrics", "/live", "/ready"))
