from __future__ import annotations

import json
from uuid import uuid4

from execution_plane.planner.rules.base import ScanContext
from execution_plane.planner.rules.ssrf import SsrfRule
from storage.db.models import AssetMap, Endpoint


def _endpoint(parameters: list[dict[str, object]], auth_required: bool = False) -> Endpoint:
    return Endpoint(
        id=uuid4(),
        asset_map_id=uuid4(),
        url_pattern="/api/fetch",
        method="POST",
        auth_required=auth_required,
        parameters=parameters,
        observed_content_type="application/json",
        example_response_code=200,
    )


def _context(endpoint: Endpoint, asset_map: AssetMap | None = None) -> ScanContext:
    active_map = asset_map or AssetMap(scan_id=uuid4())
    active_map.endpoints = [endpoint]
    return ScanContext(scan_id=uuid4(), target_url="https://app.example.test", asset_map=active_map)


def test_url_accepting_params_are_high_risk_and_no_auth_required() -> None:
    rule = SsrfRule()
    endpoint = _endpoint(
        [
            {"name": "url", "in": "query", "type": "string"},
            {"name": "webhook", "in": "body", "type": "string"},
        ]
    )
    context = _context(endpoint)

    assert rule.requires_auth is False
    assert rule.matches(endpoint, context.asset_map) is True

    tasks = rule.generate_tasks(endpoint, context)

    assert len(tasks) == 2
    assert all(task.attack_class == "ssrf" for task in tasks)
    assert all(task.priority_score == 0.85 for task in tasks)
    hypotheses = [json.loads(task.hypothesis) for task in tasks]
    assert {payload["target_parameter"] for payload in hypotheses} == {"url", "webhook"}


def test_har_url_parameter_hints_generate_candidates() -> None:
    rule = SsrfRule()
    endpoint = _endpoint([])
    asset_map = AssetMap(scan_id=uuid4())
    asset_map.signals = {"har_url_params": ["image_url", "ignored"]}
    context = _context(endpoint, asset_map=asset_map)

    tasks = rule.generate_tasks(endpoint, context)

    assert len(tasks) == 1
    assert tasks[0].target_parameter == "image_url"
