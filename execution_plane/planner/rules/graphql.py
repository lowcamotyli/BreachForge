from __future__ import annotations

import json
from typing import Any

from execution_plane.planner.decision_log import FeedbackPayload
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

    def generate_adaptive_followups(
        self, feedback: FeedbackPayload, endpoint: Endpoint, context: ScanContext
    ) -> list[AttackTask]:
        tasks: list[AttackTask] = []
        follow_up_hints = set(feedback.follow_up_hints)
        outcome = getattr(feedback.outcome, "value", feedback.outcome)
        can_probe_schema = outcome in {"needs_followup", "interesting"}

        if can_probe_schema and "schema_driven_field_probe" in follow_up_hints:
            for schema_type in self._schema_type_names(feedback.metadata.get("schema_types", [])):
                task = AttackTask(
                    scan_id=context.scan_id,
                    endpoint_id=endpoint.id,
                    attack_class="graphql_field_probe",
                    target_parameter=schema_type,
                    hypothesis=json.dumps(
                        {
                            "probe_type": "graphql_schema_driven_field_probe",
                            "schema_type": schema_type,
                            "parent_evidence_ref": feedback.parent_evidence_ref,
                            "read_only": True,
                            "params": self._base_params(endpoint),
                        },
                        sort_keys=True,
                    ),
                    priority_score=0.86,
                )
                task.parent_evidence_ref = feedback.parent_evidence_ref
                tasks.append(task)

        if "depth_exhaustion_probe" in follow_up_hints:
            for depth in (3, 5, 10):
                task = AttackTask(
                    scan_id=context.scan_id,
                    endpoint_id=endpoint.id,
                    attack_class="graphql_depth",
                    target_parameter=f"depth_{depth}",
                    hypothesis=json.dumps(
                        {
                            "probe_type": "graphql_depth_exhaustion_probe",
                            "max_depth": depth,
                            "parent_evidence_ref": feedback.parent_evidence_ref,
                            "read_only": True,
                            "timeout_seconds": 5,
                            "params": self._base_params(endpoint),
                        },
                        sort_keys=True,
                    ),
                    priority_score=0.8,
                )
                task.parent_evidence_ref = feedback.parent_evidence_ref
                tasks.append(task)

        return tasks

    def expected_proof_signal(self) -> str:
        return "GraphQL endpoint permits introspection, batch amplification, deep queries, or alias-based bypass"

    def _base_params(self, endpoint: Endpoint) -> dict[str, Any]:
        return {
            "method": endpoint.method.upper(),
            "path": endpoint.url_pattern,
            "graphql": True,
        }

    def _schema_type_names(self, raw_schema_types: Any) -> list[str]:
        if not isinstance(raw_schema_types, list):
            return []

        names: list[str] = []
        seen: set[str] = set()
        for raw_schema_type in raw_schema_types:
            if isinstance(raw_schema_type, str):
                name = raw_schema_type.strip()
            elif isinstance(raw_schema_type, dict) and isinstance(raw_schema_type.get("name"), str):
                name = raw_schema_type["name"].strip()
            else:
                continue

            if not name or name.startswith("__") or name in seen:
                continue
            seen.add(name)
            names.append(name)

        return names

    def _signals(self, asset_map: AssetMap) -> dict[str, Any]:
        raw_signals = getattr(asset_map, "signals", None)
        if isinstance(raw_signals, dict):
            return raw_signals

        planning_signals = getattr(asset_map, "planning_signals", None)
        if isinstance(planning_signals, dict):
            return planning_signals

        return {}
