from __future__ import annotations

import json
from uuid import uuid4

from execution_plane.planner.rules.base import ScanContext
from execution_plane.planner.rules.mass_assignment import ExcessiveDataExposureRule, MassAssignmentRule
from storage.db.models import AssetMap, Endpoint


def _endpoint(
    *,
    method: str,
    parameters: list[dict[str, object]],
    observed_content_type: str | None = "application/json",
    auth_required: bool = True,
) -> Endpoint:
    return Endpoint(
        id=uuid4(),
        asset_map_id=uuid4(),
        url_pattern="/api/profile",
        method=method,
        auth_required=auth_required,
        parameters=parameters,
        observed_content_type=observed_content_type,
        example_response_code=200,
    )


def _context(endpoint: Endpoint) -> ScanContext:
    asset_map = AssetMap(scan_id=uuid4())
    asset_map.endpoints = [endpoint]
    return ScanContext(scan_id=uuid4(), target_url="https://app.example.test", asset_map=asset_map)


def test_mass_assignment_rule_generates_candidate_for_each_write_endpoint() -> None:
    rule = MassAssignmentRule()
    endpoint = _endpoint(method="PATCH", parameters=[{"name": "profile", "in": "body", "type": "object"}])
    context = _context(endpoint)

    assert rule.matches(endpoint, context.asset_map) is True

    tasks = rule.generate_tasks(endpoint, context)

    assert len(tasks) == 1
    assert tasks[0].attack_class == "mass_assignment"
    payload = json.loads(tasks[0].hypothesis)
    assert payload["requires_safe_fixture_or_allow_mutation"] is True
    assert {"role", "is_admin", "subscription_tier"} <= set(payload["hidden_fields"])


def test_mass_assignment_rule_skips_read_only_endpoint() -> None:
    rule = MassAssignmentRule()
    endpoint = _endpoint(method="GET", parameters=[{"name": "profile", "in": "body", "type": "object"}])

    assert rule.matches(endpoint, AssetMap(scan_id=uuid4())) is False


def test_excessive_exposure_rule_generates_when_response_schema_exceeds_request_by_30_percent() -> None:
    rule = ExcessiveDataExposureRule()
    endpoint = _endpoint(
        method="GET",
        parameters=[
            {
                "name": "schema",
                "request_schema": {"properties": {"id": {}, "email": {}, "name": {}}},
                "response_schema": {
                    "properties": {
                        "id": {},
                        "email": {},
                        "name": {},
                        "internal_id": {},
                        "password_hash": {},
                    }
                },
            }
        ],
    )
    context = _context(endpoint)

    assert rule.matches(endpoint, context.asset_map) is True

    tasks = rule.generate_tasks(endpoint, context)

    assert len(tasks) == 1
    payload = json.loads(tasks[0].hypothesis)
    assert tasks[0].attack_class == "excessive_exposure"
    assert payload["read_only"] is True
    assert payload["extra_field_ratio"] > 0.30
    assert payload["extra_response_fields"] == ["internal_id", "password_hash"]
