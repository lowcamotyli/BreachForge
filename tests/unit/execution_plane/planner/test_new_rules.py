from __future__ import annotations

import json
from pathlib import Path
import sys
from uuid import uuid4

PROJECT_ROOT = Path(__file__).resolve().parents[4]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


def _extend_execution_plane_package_paths() -> None:
    execution_plane_path = PROJECT_ROOT / "execution_plane"
    planner_path = execution_plane_path / "planner"
    execution_plane_package = sys.modules.get("execution_plane")
    if execution_plane_package is not None and hasattr(execution_plane_package, "__path__"):
        execution_plane_locations = list(execution_plane_package.__path__)
        if str(execution_plane_path) not in execution_plane_locations:
            execution_plane_package.__path__.append(str(execution_plane_path))
    planner_package = sys.modules.get("execution_plane.planner")
    if planner_package is not None and hasattr(planner_package, "__path__"):
        planner_locations = list(planner_package.__path__)
        if str(planner_path) not in planner_locations:
            planner_package.__path__.append(str(planner_path))


_extend_execution_plane_package_paths()

from execution_plane.planner.rules.base import ScanContext
from execution_plane.planner.rules.misconfiguration import MisconfigurationRule
from execution_plane.planner.rules.rate_limit_abuse import RateLimitAbuseRule
from execution_plane.planner.rules.session_misuse import SessionMisuseRule
from storage.db.models import AssetMap, Endpoint


def _build_context(endpoint: Endpoint) -> ScanContext:
    asset_map = AssetMap(scan_id=uuid4())
    asset_map.endpoints = [endpoint]
    return ScanContext(scan_id=uuid4(), target_url="https://app.example.com", asset_map=asset_map)


def _build_endpoint(
    *,
    method: str,
    auth_required: bool,
    url_pattern: str,
    parameters: list[dict[str, object]],
    observed_content_type: str | None = "application/json",
    example_response_code: int = 200,
) -> Endpoint:
    return Endpoint(
        id=uuid4(),
        asset_map_id=uuid4(),
        url_pattern=url_pattern,
        method=method,
        auth_required=auth_required,
        parameters=parameters,
        observed_content_type=observed_content_type,
        example_response_code=example_response_code,
    )


def _task_by_probe_type(tasks: list[object], probe_type: str) -> object:
    for task in tasks:
        parsed = json.loads(task.hypothesis)
        if parsed.get("probe_type") == probe_type:
            return task
    raise AssertionError(f"No task found for probe_type={probe_type}")


# SessionMisuseRule

def test_session_misuse_generates_replay_task() -> None:
    rule = SessionMisuseRule()
    endpoint = _build_endpoint(
        method="GET",
        auth_required=False,
        url_pattern="/api/me",
        parameters=[{"name": "Authorization", "in": "header"}],
    )
    context = _build_context(endpoint)

    tasks = rule.generate_tasks(endpoint, context)

    replay_task = _task_by_probe_type(tasks, "replay")
    replay_payload = json.loads(replay_task.hypothesis)
    assert replay_payload["probe_type"] == "replay"


def test_session_misuse_generates_token_swap_task() -> None:
    rule = SessionMisuseRule()
    endpoint = _build_endpoint(
        method="GET",
        auth_required=True,
        url_pattern="/api/users/{user_id}",
        parameters=[{"name": "user_id", "in": "path"}],
    )
    context = _build_context(endpoint)

    tasks = rule.generate_tasks(endpoint, context)

    token_swap_task = _task_by_probe_type(tasks, "token_swap")
    token_swap_payload = json.loads(token_swap_task.hypothesis)
    assert token_swap_payload["probe_type"] == "token_swap"


def test_session_misuse_generates_stale_session_task() -> None:
    rule = SessionMisuseRule()
    endpoint = _build_endpoint(
        method="POST",
        auth_required=True,
        url_pattern="/api/orders",
        parameters=[{"name": "Authorization", "in": "header"}],
    )
    context = _build_context(endpoint)

    tasks = rule.generate_tasks(endpoint, context)

    stale_task = _task_by_probe_type(tasks, "stale_session")
    stale_payload = json.loads(stale_task.hypothesis)
    assert stale_payload["probe_type"] == "stale_session"


def test_session_misuse_attack_class_is_canonical() -> None:
    rule = SessionMisuseRule()
    endpoint = _build_endpoint(
        method="GET",
        auth_required=True,
        url_pattern="/api/users/{user_id}",
        parameters=[{"name": "user_id", "in": "path"}],
    )
    context = _build_context(endpoint)

    tasks = rule.generate_tasks(endpoint, context)

    assert tasks
    assert all(task.attack_class == "session_misuse" for task in tasks)


# RateLimitAbuseRule

def test_rate_limit_generates_burst_task() -> None:
    rule = RateLimitAbuseRule()
    endpoint = _build_endpoint(
        method="POST",
        auth_required=False,
        url_pattern="/api/login",
        parameters=[],
    )
    context = _build_context(endpoint)

    tasks = rule.generate_tasks(endpoint, context)

    burst_task = _task_by_probe_type(tasks, "burst")
    burst_payload = json.loads(burst_task.hypothesis)
    assert burst_payload["probe_type"] == "burst"
    assert burst_payload["params"]["count"] == 10


def test_rate_limit_generates_staircase_task() -> None:
    rule = RateLimitAbuseRule()
    endpoint = _build_endpoint(
        method="GET",
        auth_required=True,
        url_pattern="/api/search",
        parameters=[{"name": "q", "in": "query"}],
    )
    context = _build_context(endpoint)

    tasks = rule.generate_tasks(endpoint, context)

    staircase_task = _task_by_probe_type(tasks, "staircase")
    staircase_payload = json.loads(staircase_task.hypothesis)
    assert staircase_payload["probe_type"] == "staircase"


def test_rate_limit_attack_class_canonical() -> None:
    rule = RateLimitAbuseRule()
    endpoint = _build_endpoint(
        method="POST",
        auth_required=True,
        url_pattern="/api/auth/token",
        parameters=[],
    )
    context = _build_context(endpoint)

    tasks = rule.generate_tasks(endpoint, context)

    assert tasks
    assert all(task.attack_class == "rate_limit_abuse" for task in tasks)


# MisconfigurationRule

def test_misconfiguration_generates_cors_task() -> None:
    rule = MisconfigurationRule()
    endpoint = _build_endpoint(
        method="GET",
        auth_required=False,
        url_pattern="/api/profile",
        parameters=[],
    )
    context = _build_context(endpoint)

    tasks = rule.generate_tasks(endpoint, context)

    cors_task = _task_by_probe_type(tasks, "cors_wildcard")
    cors_payload = json.loads(cors_task.hypothesis)
    assert cors_payload["probe_type"] == "cors_wildcard"


def test_misconfiguration_generates_debug_task() -> None:
    rule = MisconfigurationRule()
    endpoint = _build_endpoint(
        method="GET",
        auth_required=False,
        url_pattern="/api/users",
        parameters=[],
    )
    context = _build_context(endpoint)

    tasks = rule.generate_tasks(endpoint, context)

    debug_task = _task_by_probe_type(tasks, "debug_endpoint")
    debug_payload = json.loads(debug_task.hypothesis)
    assert debug_payload["probe_type"] == "debug_endpoint"


def test_misconfiguration_applies_to_all_endpoints() -> None:
    rule = MisconfigurationRule()
    endpoint = _build_endpoint(
        method="GET",
        auth_required=False,
        url_pattern="/v1/generic",
        parameters=[{"name": "x", "in": "query"}],
    )

    if hasattr(rule, "applies_to"):
        assert rule.applies_to(endpoint) is True
    else:
        assert rule.matches(endpoint, AssetMap(scan_id=uuid4())) is True


def test_misconfiguration_attack_class_canonical() -> None:
    rule = MisconfigurationRule()
    endpoint = _build_endpoint(
        method="POST",
        auth_required=True,
        url_pattern="/api/orders",
        parameters=[{"name": "request", "in": "body", "type": "object"}],
    )
    context = _build_context(endpoint)

    tasks = rule.generate_tasks(endpoint, context)

    assert tasks
    assert all(task.attack_class == "misconfiguration" for task in tasks)
