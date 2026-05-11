from __future__ import annotations

import json
from uuid import uuid4

from execution_plane.planner.rules.base import ScanContext
from execution_plane.planner.rules.oauth import OauthRule
from storage.db.models import AssetMap, Endpoint


def _endpoint(*, path: str, method: str = "GET", params: list[dict[str, object]] | None = None) -> Endpoint:
    return Endpoint(
        id=uuid4(),
        asset_map_id=uuid4(),
        url_pattern=path,
        method=method,
        auth_required=False,
        parameters=params or [],
        observed_content_type="application/json",
        example_response_code=200,
    )


def _context(endpoint: Endpoint, signals: dict[str, object] | None = None) -> ScanContext:
    asset_map = AssetMap(scan_id=uuid4())
    asset_map.endpoints = [endpoint]
    if signals is not None:
        asset_map.signals = signals
    return ScanContext(scan_id=uuid4(), target_url="https://app.example.test", asset_map=asset_map)


def test_oauth_rule_matches_authorize_endpoint() -> None:
    endpoint = _endpoint(path="/oauth/authorize", params=[{"name": "client_id", "in": "query"}])
    context = _context(endpoint)

    assert OauthRule().matches(endpoint, context.asset_map) is True


def test_oauth_rule_builds_expected_oauth_task_candidates() -> None:
    endpoint = _endpoint(
        path="/oauth/authorize",
        params=[
            {"name": "redirect_uri", "in": "query"},
            {"name": "state", "in": "query"},
            {"name": "response_type", "in": "query"},
        ],
    )
    context = _context(endpoint)

    tasks = OauthRule().generate_tasks(endpoint, context)

    attack_classes = {task.attack_class for task in tasks}
    assert attack_classes == {
        "oauth_redirect",
        "oauth_state_csrf",
        "oauth_error_disclosure",
    }
    redirect_task = next(task for task in tasks if task.attack_class == "oauth_redirect")
    payload = json.loads(redirect_task.hypothesis)
    assert payload["controlled_callback"]["host"] == "callback.scanner.local"
    assert "partial-host-match:example.com.evil.test" in payload["manipulation_patterns"]


def test_oauth_rule_adds_token_reuse_for_token_lifecycle_endpoints() -> None:
    endpoint = _endpoint(path="/oauth/token", method="POST", params=[{"name": "refresh_token", "in": "body"}])
    context = _context(endpoint)

    tasks = OauthRule().generate_tasks(endpoint, context)

    assert "oauth_token_reuse" in {task.attack_class for task in tasks}


def test_oauth_rule_can_match_signals_when_endpoint_is_ambiguous() -> None:
    endpoint = _endpoint(path="/api/login", params=[])
    context = _context(endpoint, signals={"openapi_endpoints": ["/oauth/authorize"]})

    assert OauthRule().matches(endpoint, context.asset_map) is True
