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

from execution_plane.planner.planner import AttackPlanner
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


def _task_signature(task: AttackTask) -> tuple[object, ...]:
    return (
        task.scan_id,
        task.endpoint_id,
        task.attack_class,
        task.target_parameter,
        task.hypothesis,
        task.priority_score,
    )


def test_replan_with_empty_prior_findings_returns_same_tasks_as_plan() -> None:
    planner = AttackPlanner()
    endpoint = _build_endpoint(
        method="GET",
        auth_required=True,
        url_pattern="/api/users/{id}",
        parameters=[{"name": "id", "in": "path"}],
    )
    context = _build_context([endpoint])

    planned_tasks = planner.plan(context)
    replanned_tasks = planner.replan(context)

    assert context.prior_findings == []
    assert [_task_signature(task) for task in replanned_tasks] == [
        _task_signature(task) for task in planned_tasks
    ]


def test_replan_deduplicates_tasks_already_completed() -> None:
    planner = AttackPlanner()
    endpoint = _build_endpoint(
        method="GET",
        auth_required=True,
        url_pattern="/api/users/{id}",
        parameters=[{"name": "id", "in": "path"}],
    )
    context = _build_context([endpoint])
    candidate_tasks = planner.plan(context)
    assert candidate_tasks
    for task in candidate_tasks:
        task.id = uuid4()

    completed_task = candidate_tasks[0]
    context.completed_task_ids = {completed_task.id}

    planner.plan = lambda _: candidate_tasks  # type: ignore[method-assign]
    replanned_tasks = planner.replan(context)

    assert completed_task.id not in {task.id for task in replanned_tasks}
    assert len(replanned_tasks) == len(candidate_tasks) - 1


def test_scan_context_prior_findings_defaults_to_empty_list() -> None:
    endpoint = _build_endpoint(
        method="GET",
        auth_required=True,
        url_pattern="/api/users/{id}",
        parameters=[{"name": "id", "in": "path"}],
    )
    asset_map = AssetMap(scan_id=uuid4())
    asset_map.endpoints = [endpoint]

    context = ScanContext(scan_id=uuid4(), target_url="https://app.example.com", asset_map=asset_map)

    assert context.prior_findings == []


def test_scan_context_completed_task_ids_defaults_to_empty_set() -> None:
    endpoint = _build_endpoint(
        method="GET",
        auth_required=True,
        url_pattern="/api/users/{id}",
        parameters=[{"name": "id", "in": "path"}],
    )
    asset_map = AssetMap(scan_id=uuid4())
    asset_map.endpoints = [endpoint]

    context = ScanContext(scan_id=uuid4(), target_url="https://app.example.com", asset_map=asset_map)

    assert context.completed_task_ids == set()


def test_replan_budget_stops_after_max_rounds() -> None:
    planner = AttackPlanner()
    endpoint = _build_endpoint(
        method="GET",
        auth_required=True,
        url_pattern="/api/users/{id}",
        parameters=[{"name": "id", "in": "path"}],
    )
    context = _build_context([endpoint])

    for _ in range(3):
        planner.replan(context)

    result = planner.replan(context)
    assert result == []


def test_replan_budget_tracks_rounds() -> None:
    planner = AttackPlanner()
    endpoint = _build_endpoint(
        method="GET",
        auth_required=True,
        url_pattern="/api/orders",
        parameters=[],
    )
    context = _build_context([endpoint])

    planner.replan(context)
    planner.replan(context)

    assert context.replan_budget is not None
    assert context.replan_budget.rounds_used == 2
