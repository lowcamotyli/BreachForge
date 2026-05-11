from __future__ import annotations

import json
from uuid import uuid4

from execution_plane.planner.rules.base import ScanContext
from execution_plane.planner.rules.bfla import BflaRule
from storage.db.models import AssetMap, Endpoint


def _endpoint(*, method: str, url_pattern: str) -> Endpoint:
    return Endpoint(
        id=uuid4(),
        asset_map_id=uuid4(),
        url_pattern=url_pattern,
        method=method,
        auth_required=True,
        parameters=[],
        observed_content_type="application/json",
        example_response_code=200,
    )


def _context(endpoint: Endpoint) -> ScanContext:
    asset_map = AssetMap(scan_id=uuid4())
    asset_map.endpoints = [endpoint]
    return ScanContext(scan_id=uuid4(), target_url="https://app.example.test", asset_map=asset_map)


def test_bfla_rule_admin_path_get_is_high_priority_candidate() -> None:
    rule = BflaRule()
    endpoint = _endpoint(method="GET", url_pattern="/api/admin/users")
    context = _context(endpoint)

    assert rule.matches(endpoint, context.asset_map) is True
    tasks = rule.generate_tasks(endpoint, context)

    assert len(tasks) == 1
    assert tasks[0].attack_class == "bfla"
    assert tasks[0].priority_score == 0.96
    payload = json.loads(tasks[0].hypothesis)
    assert payload["required_identities"]["minimum_identities"] == 2
    assert "guest" in payload["required_identities"]["low_privilege"]
    assert "admin" in payload["required_identities"]["elevated"]


def test_bfla_rule_restricted_mutating_verb_requires_safe_fixture_metadata() -> None:
    rule = BflaRule()
    endpoint = _endpoint(method="DELETE", url_pattern="/api/v1/users/{id}")
    context = _context(endpoint)

    assert rule.matches(endpoint, context.asset_map) is True
    tasks = rule.generate_tasks(endpoint, context)

    assert len(tasks) == 1
    payload = json.loads(tasks[0].hypothesis)
    assert payload["requires_safe_fixture_or_allow_mutation"] is True
    assert payload["mutation_allowed"] is False
    candidate = payload["candidates"][0]
    assert candidate["probe_type"] == "bfla_verb_authorization"
    assert candidate["requires_safe_fixture_or_allow_mutation"] is True


def test_bfla_rule_skips_mutating_non_resource_endpoint() -> None:
    endpoint = _endpoint(method="DELETE", url_pattern="/api")

    assert BflaRule().matches(endpoint, AssetMap(scan_id=uuid4())) is False
