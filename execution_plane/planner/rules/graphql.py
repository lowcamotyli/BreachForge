from __future__ import annotations

import json
from typing import Any

from execution_plane.planner.rules.base import AssetMap, AttackRule, ScanContext
from execution_plane.crawler.graphql_parser import is_graphql_endpoint
from storage.db.models import AttackTask, Endpoint


class GraphqlRule(AttackRule):
    requires_auth = False
    attack_class = "graphql_introspection"
    name = "GraphqlRule"

    def matches(self, endpoint: Endpoint, asset_map: AssetMap) -> bool:
        if is_graphql_endpoint(endpoint.url_pattern, endpoint.observed_content_type):
            return True

        signals = self._signals(asset_map)
        spec_hints = signals.get("spec_endpoints")
        if not isinstance(spec_hints, list):
            spec_hints = signals.get("openapi_endpoints") if isinstance(signals.get("openapi_endpoints"), list) else []

        endpoint_path = endpoint.url_pattern.lower().rstrip("/")
        for hint in spec_hints:
            if not isinstance(hint, str):
                continue
            normalized_hint = hint.lower().rstrip("/")
            if normalized_hint.endswith("/graphql") and endpoint_path.endswith("/graphql"):
                return True

        return False

    def generate_tasks(self, endpoint: Endpoint, context: ScanContext) -> list[AttackTask]:
        base = {
            "method": endpoint.method.upper(),
            "path": endpoint.url_pattern,
            "graphql": True,
        }

        candidates: list[tuple[str, str, dict[str, Any], float]] = [
            (
                "graphql_introspection",
                "graphql_endpoint",
                {
                    "probe_type": "graphql_introspection",
                    "requires_auth": False,
                    "query": "query IntrospectionProbe { __schema { types { name } } }",
                    "read_only": True,
                    "max_requests": 1,
                    "unauth_first": True,
                    "params": base,
                },
                0.92,
            ),
            (
                "graphql_batch",
                "graphql_endpoint",
                {
                    "probe_type": "graphql_batch",
                    "requires_auth": False,
                    "batch_size": 20,
                    "query": "query BatchProbe { __typename }",
                    "read_only": True,
                    "params": base,
                },
                0.88,
            ),
            (
                "graphql_depth",
                "graphql_endpoint",
                {
                    "probe_type": "graphql_depth",
                    "max_depth": 10,
                    "requires_auth": True,
                    "query": "query DepthProbe { __typename }",
                    "timeout_seconds": 5,
                    "read_only": True,
                    "params": base,
                },
                0.74,
            ),
            (
                "graphql_field_suggestion",
                "graphql_endpoint",
                {
                    "probe_type": "graphql_field_suggestion",
                    "requires_auth": False,
                    "alias_bypass": True,
                    "query": "query SuggestionProbe { __typenam3 }",
                    "read_only": True,
                    "params": base,
                },
                0.84,
            ),
        ]

        tasks: list[AttackTask] = []
        for attack_class, target_parameter, payload, priority in candidates:
            tasks.append(
                AttackTask(
                    scan_id=context.scan_id,
                    endpoint_id=endpoint.id,
                    attack_class=attack_class,
                    target_parameter=target_parameter,
                    hypothesis=json.dumps(payload, sort_keys=True),
                    priority_score=priority,
                )
            )
        return tasks

    def expected_proof_signal(self) -> str:
        return "GraphQL endpoint permits introspection, batch amplification, deep queries, or alias-based bypass"

    def _signals(self, asset_map: AssetMap) -> dict[str, Any]:
        raw_signals = getattr(asset_map, "signals", None)
        if isinstance(raw_signals, dict):
            return raw_signals

        planning_signals = getattr(asset_map, "planning_signals", None)
        if isinstance(planning_signals, dict):
            return planning_signals

        return {}
