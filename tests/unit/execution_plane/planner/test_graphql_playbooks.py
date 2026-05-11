from __future__ import annotations

import json
from uuid import uuid4

from execution_plane.planner.planner import AttackPlanner
from execution_plane.planner.playbook_loader import load_builtin_playbooks
from execution_plane.planner.rules.base import ScanContext
from storage.db.models import AssetMap, Endpoint


def _graphql_endpoint() -> Endpoint:
    return Endpoint(
        id=uuid4(),
        asset_map_id=uuid4(),
        url_pattern="/graphql",
        method="POST",
        auth_required=False,
        parameters=[{"name": "graphql", "location": "meta", "type": "boolean", "value": "true"}],
        observed_content_type="application/graphql",
        example_response_code=200,
    )


def _context(endpoint: Endpoint) -> ScanContext:
    asset_map = AssetMap(scan_id=uuid4())
    asset_map.endpoints = [endpoint]
    asset_map.signals = {"attack_playbooks": ["graphql_introspection", "graphql_batch_amplification", "graphql_query_depth"]}
    return ScanContext(scan_id=uuid4(), target_url="https://app.example.test", asset_map=asset_map)


def test_graphql_playbooks_have_read_only_budgets() -> None:
    playbooks = {playbook.id: playbook for playbook in load_builtin_playbooks()}

    introspection = playbooks["graphql_introspection"]
    batch = playbooks["graphql_batch_amplification"]
    depth = playbooks["graphql_query_depth"]

    assert introspection.safety_budget["max_requests"] == 1
    assert introspection.steps[0].probe_template["variables"]["read_only"] is True
    assert batch.steps[1].probe_template["variables"]["max_batch_size"] == 20
    assert batch.steps[1].probe_template["variables"]["query"] == "query BatchProbe { __typename }"
    assert depth.safety_budget["max_requests"] == 1
    assert depth.steps[0].probe_template["variables"]["max_depth"] == 10
    assert depth.steps[0].probe_template["variables"]["retry_on_timeout"] is False


def test_planner_selects_graphql_playbooks_from_asset_map_signal() -> None:
    endpoint = _graphql_endpoint()
    planner = AttackPlanner()

    tasks = planner.plan(_context(endpoint))

    payloads = [json.loads(task.hypothesis) for task in tasks if "playbook_id" in task.hypothesis]
    playbook_ids = {payload["playbook_id"] for payload in payloads}
    assert {"graphql_introspection", "graphql_batch_amplification", "graphql_query_depth"} <= playbook_ids
