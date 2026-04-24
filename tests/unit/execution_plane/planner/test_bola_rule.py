from __future__ import annotations

from pathlib import Path
import sys
from uuid import uuid4

import pytest

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
from execution_plane.planner.rules.bola import BolaBidirectional
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
) -> Endpoint:
    return Endpoint(
        id=uuid4(),
        asset_map_id=uuid4(),
        url_pattern=url_pattern,
        method=method,
        auth_required=auth_required,
        parameters=parameters,
        observed_content_type="application/json",
        example_response_code=200,
    )


@pytest.mark.parametrize("path_parameter", ["id", "user_id"])
def test_matches_true_for_authenticated_get_with_path_id(path_parameter: str) -> None:
    rule = BolaBidirectional()
    endpoint = _build_endpoint(
        method="GET",
        auth_required=True,
        url_pattern=f"/api/users/{{{path_parameter}}}",
        parameters=[{"name": path_parameter, "in": "path"}],
    )

    assert rule.matches(endpoint, AssetMap(scan_id=uuid4())) is True


def test_matches_false_for_post_endpoint() -> None:
    rule = BolaBidirectional()
    endpoint = _build_endpoint(
        method="POST",
        auth_required=True,
        url_pattern="/api/users/{id}",
        parameters=[{"name": "id", "in": "path"}],
    )

    assert rule.matches(endpoint, AssetMap(scan_id=uuid4())) is False


def test_matches_false_for_get_without_auth_required() -> None:
    rule = BolaBidirectional()
    endpoint = _build_endpoint(
        method="GET",
        auth_required=False,
        url_pattern="/api/users/{id}",
        parameters=[{"name": "id", "in": "path"}],
    )

    assert rule.matches(endpoint, AssetMap(scan_id=uuid4())) is False


def test_matches_false_for_get_without_path_params() -> None:
    rule = BolaBidirectional()
    endpoint = _build_endpoint(
        method="GET",
        auth_required=True,
        url_pattern="/api/profile",
        parameters=[{"name": "expand", "in": "query"}],
    )

    assert rule.matches(endpoint, AssetMap(scan_id=uuid4())) is False


def test_generate_tasks_returns_attack_tasks_with_expected_hypothesis() -> None:
    rule = BolaBidirectional()
    endpoint = _build_endpoint(
        method="GET",
        auth_required=True,
        url_pattern="/api/users/{user_id}",
        parameters=[{"name": "user_id", "in": "path"}],
    )
    context = _build_context(endpoint)

    tasks = rule.generate_tasks(endpoint, context)

    assert len(tasks) == 1
    task = tasks[0]
    assert task.scan_id == context.scan_id
    assert task.endpoint_id == endpoint.id
    assert task.attack_class == "bola"
    assert task.target_parameter == "user_id"
    assert task.hypothesis == "Substitute another users resource ID to confirm unauthorized access"
