from __future__ import annotations

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

from api.models.requests import ScanPolicy
from execution_plane.planner.planner import AttackPlanner, filter_tasks_by_policy
from execution_plane.planner.rules.base import ScanContext
from storage.db.models import AssetMap, AttackTask, Endpoint


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


def _build_context(endpoints: list[Endpoint]) -> ScanContext:
    asset_map = AssetMap(scan_id=uuid4())
    asset_map.endpoints = endpoints
    return ScanContext(scan_id=uuid4(), target_url="https://app.example.com", asset_map=asset_map)


def test_plan_returns_tasks_sorted_by_priority_desc_and_scores_bola_at_least_expected() -> None:
    planner = AttackPlanner()
    bola_endpoint = _build_endpoint(
        method="GET",
        auth_required=True,
        url_pattern="/api/users/{id}",
        parameters=[{"name": "id", "in": "path"}],
    )
    tenant_endpoint = _build_endpoint(
        method="GET",
        auth_required=False,
        url_pattern="/api/tenants/{tenant_id}/users",
        parameters=[{"name": "tenant_id", "in": "path"}],
    )
    context = _build_context([tenant_endpoint, bola_endpoint])

    tasks = planner.plan(context)

    assert len(tasks) >= 2
    assert tasks == sorted(tasks, key=lambda task: task.priority_score, reverse=True)

    bola_tasks = [task for task in tasks if task.endpoint_id == bola_endpoint.id and task.attack_class == "bola"]
    assert bola_tasks
    assert max(task.priority_score for task in bola_tasks) >= 0.60


def test_plan_returns_empty_list_when_no_rules_match() -> None:
    planner = AttackPlanner()
    endpoint = _build_endpoint(
        method="GET",
        auth_required=False,
        url_pattern="/health",
        parameters=[{"name": "verbose", "in": "query"}],
        observed_content_type=None,
    )
    context = _build_context([endpoint])

    tasks = planner.plan(context)

    assert tasks == []


def test_plan_respects_max_50_tasks_per_endpoint() -> None:
    planner = AttackPlanner(max_tasks_per_endpoint=50)
    endpoint = _build_endpoint(
        method="GET",
        auth_required=True,
        url_pattern="/api/users",
        parameters=[{"name": f"user_id_{index}", "in": "path"} for index in range(55)],
    )
    context = _build_context([endpoint])

    tasks = planner.plan(context)

    assert len(tasks) == 50
    assert all(task.attack_class == "bola" for task in tasks)
    assert all(task.endpoint_id == endpoint.id for task in tasks)


def test_filter_tasks_blocks_mutating() -> None:
    endpoint = _build_endpoint(
        method="POST",
        auth_required=True,
        url_pattern="https://app.example.com/api/users",
        parameters=[],
    )
    task = AttackTask(
        scan_id=uuid4(),
        endpoint_id=endpoint.id,
        attack_class="mass_assignment",
        target_parameter=None,
        hypothesis="probe mutation",
    )
    task.endpoint = endpoint

    allowed, skipped = filter_tasks_by_policy([task], ScanPolicy(mutating_allowed=False))

    assert allowed == []
    assert skipped == [
        {
            "task_id": str(task.id),
            "reason": "mutating method POST blocked by policy",
            "attack_class": "mass_assignment",
        }
    ]


def test_filter_tasks_allows_get() -> None:
    endpoint = _build_endpoint(
        method="GET",
        auth_required=True,
        url_pattern="https://app.example.com/api/users/{id}",
        parameters=[],
    )
    task = AttackTask(
        scan_id=uuid4(),
        endpoint_id=endpoint.id,
        attack_class="bola",
        target_parameter=None,
        hypothesis="probe read",
    )
    task.endpoint = endpoint

    allowed, skipped = filter_tasks_by_policy([task], ScanPolicy(mutating_allowed=False))

    assert allowed == [task]
    assert skipped == []
