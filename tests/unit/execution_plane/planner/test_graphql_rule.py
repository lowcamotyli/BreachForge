from __future__ import annotations

import json
from uuid import uuid4

from execution_plane.planner.rules.base import ScanContext
from execution_plane.planner.rules.graphql import GraphqlRule
from storage.db.models import AssetMap, Endpoint


def _endpoint(url_pattern: str, content_type: str | None = "application/json") -> Endpoint:
    return Endpoint(
        id=uuid4(),
        asset_map_id=uuid4(),
        url_pattern=url_pattern,
        method="POST",
        auth_required=False,
        parameters=[],
        observed_content_type=content_type,
        example_response_code=200,
    )


def _context(endpoint: Endpoint, signals: dict[str, object] | None = None) -> ScanContext:
    asset_map = AssetMap(scan_id=uuid4())
    asset_map.endpoints = [endpoint]
    if signals is not None:
        asset_map.signals = signals
    return ScanContext(scan_id=uuid4(), target_url="https://example.test", asset_map=asset_map)


def test_matches_graphql_endpoint() -> None:
    endpoint = _endpoint("/graphql")
    context = _context(endpoint)

    assert GraphqlRule().matches(endpoint, context.asset_map) is True


def test_matches_openapi_hint_for_graphql_endpoint() -> None:
    endpoint = _endpoint("/graphql", content_type="application/json")
    context = _context(endpoint, signals={"openapi_endpoints": ["/graphql"]})

    assert GraphqlRule().matches(endpoint, context.asset_map) is True


def test_generates_four_graphql_candidates_and_unauth_flags() -> None:
    endpoint = _endpoint("/graphql")
    context = _context(endpoint)

    tasks = GraphqlRule().generate_tasks(endpoint, context)

    assert len(tasks) == 4
    payloads = [json.loads(task.hypothesis) for task in tasks]
    by_probe = {payload["probe_type"]: payload for payload in payloads}
    assert set(by_probe) == {
        "graphql_introspection",
        "graphql_batch",
        "graphql_depth",
        "graphql_field_suggestion",
    }
    assert by_probe["graphql_introspection"]["requires_auth"] is False
    assert by_probe["graphql_batch"]["requires_auth"] is False
    assert by_probe["graphql_field_suggestion"]["requires_auth"] is False
    assert by_probe["graphql_depth"]["requires_auth"] is True
