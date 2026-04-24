from __future__ import annotations

import json
from typing import List

from execution_plane.planner.rules.base import AssetMap, AttackRule, ScanContext
from storage.db.models import AttackTask, Endpoint

_AUTH_HEADER_NAMES: set[str] = {"authorization", "cookie", "x-api-key", "x-auth-token", "proxy-authorization"}


class SessionMisuseRule(AttackRule):
    attack_class = "session_misuse"
    name = "SessionMisuseRule"

    def matches(self, endpoint: Endpoint, asset_map: AssetMap) -> bool:
        del asset_map
        return endpoint.auth_required or self._has_auth_headers(endpoint)

    def generate_tasks(self, endpoint: Endpoint, context: ScanContext) -> List[AttackTask]:
        token_swap_parameters = self._user_id_parameters(endpoint)
        base_params = {
            "method": endpoint.method.upper(),
            "path": endpoint.url_pattern,
        }
        return [
            AttackTask(
                scan_id=context.scan_id,
                endpoint_id=endpoint.id,
                attack_class=self.attack_class,
                target_parameter="Authorization",
                hypothesis=json.dumps(
                    {
                        "probe_type": "replay",
                        "params": {
                            **base_params,
                            "auth_header_reuse": True,
                            "simulated_delay_seconds": 3600,
                        },
                    },
                    sort_keys=True,
                ),
            ),
            AttackTask(
                scan_id=context.scan_id,
                endpoint_id=endpoint.id,
                attack_class=self.attack_class,
                target_parameter="user_id",
                hypothesis=json.dumps(
                    {
                        "probe_type": "token_swap",
                        "params": {
                            **base_params,
                            "token_source": "context",
                            "swap_user_id_parameters": token_swap_parameters,
                        },
                    },
                    sort_keys=True,
                ),
            ),
            AttackTask(
                scan_id=context.scan_id,
                endpoint_id=endpoint.id,
                attack_class=self.attack_class,
                target_parameter="X-Session-Age",
                hypothesis=json.dumps(
                    {
                        "probe_type": "stale_session",
                        "params": {
                            **base_params,
                            "headers": {"X-Session-Age": "99999"},
                        },
                    },
                    sort_keys=True,
                ),
            ),
        ]

    def expected_proof_signal(self) -> str:
        return "Session replay, token swap, or stale session request succeeds when it should be rejected"

    def _has_auth_headers(self, endpoint: Endpoint) -> bool:
        for parameter in endpoint.parameters:
            if not isinstance(parameter, dict):
                continue
            location = str(parameter.get("in") or parameter.get("location") or "").lower()
            if location != "header":
                continue
            raw_name = parameter.get("name")
            if isinstance(raw_name, str) and raw_name.strip().lower() in _AUTH_HEADER_NAMES:
                return True
        return False

    def _user_id_parameters(self, endpoint: Endpoint) -> list[str]:
        selected: list[str] = []
        seen: set[str] = set()
        for parameter in endpoint.parameters:
            if not isinstance(parameter, dict):
                continue
            location = str(parameter.get("in") or parameter.get("location") or "").lower()
            if location not in {"path", "query"}:
                continue
            raw_name = parameter.get("name")
            if not isinstance(raw_name, str) or not raw_name.strip():
                continue
            lowered = raw_name.strip().lower()
            if "user_id" not in lowered:
                continue
            if lowered in seen:
                continue
            seen.add(lowered)
            selected.append(raw_name.strip())
        return selected
