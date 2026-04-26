from __future__ import annotations

import json
from pathlib import Path
import sys
from uuid import uuid4

PROJECT_ROOT = Path(__file__).resolve().parents[4]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from execution_plane.planner.planner import AttackPlanner
from execution_plane.planner.rules.base import ScanContext
from storage.db.models import AssetMap, Endpoint


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


def _build_context(endpoints: list[Endpoint], signals: dict[str, object]) -> ScanContext:
    asset_map = AssetMap(scan_id=uuid4())
    asset_map.endpoints = endpoints
    asset_map.signals = signals
    return ScanContext(scan_id=uuid4(), target_url="https://app.example.com", asset_map=asset_map)


def _hypothesis_value(hypothesis: str, key: str) -> object:
    try:
        parsed = json.loads(hypothesis)
    except json.JSONDecodeError:
        return None
    if not isinstance(parsed, dict):
        return None
    return parsed.get(key)


def test_planner_selects_bola_playbook_from_endpoint_heuristic_without_signal() -> None:
    endpoint = _build_endpoint(
        method="GET",
        auth_required=True,
        url_pattern="/api/users/{user_id}",
        parameters=[{"name": "user_id", "in": "path"}],
    )
    context = _build_context([endpoint], {})
    planner = AttackPlanner()

    tasks = planner.plan(context)

    playbook_tasks = [
        task
        for task in tasks
        if _hypothesis_value(task.hypothesis, "playbook_id") == "bola_idor"
    ]
    assert len(playbook_tasks) == 3
    assert [task.step_order for task in playbook_tasks] == [1, 2, 3]
    assert playbook_tasks[0].prerequisites is None
    assert playbook_tasks[1].prerequisites == ["bola_idor:1:discover_ids"]


def test_planner_hypothesis_contains_deterministic_playbook_step_payload() -> None:
    endpoint = _build_endpoint(
        method="GET",
        auth_required=True,
        url_pattern="/api/users/{user_id}",
        parameters=[{"name": "user_id", "in": "path"}],
    )
    context = _build_context([endpoint], {"attack_playbooks": ["bola_idor"]})
    planner = AttackPlanner()

    tasks = planner.plan(context)

    playbook_tasks = [
        task
        for task in tasks
        if _hypothesis_value(task.hypothesis, "playbook_id") == "bola_idor"
    ]
    assert playbook_tasks
    payload = json.loads(playbook_tasks[0].hypothesis)
    assert set(payload) >= {
        "action",
        "expected_signal",
        "identity_selector",
        "observe_only",
        "playbook_id",
        "probe_template",
        "safety_budget",
        "step_id",
        "validator",
    }
    assert payload["playbook_id"] == "bola_idor"


def test_planner_decision_log_records_selection_and_step_progress_reason() -> None:
    endpoint = _build_endpoint(
        method="GET",
        auth_required=True,
        url_pattern="/api/users/{user_id}",
        parameters=[{"name": "user_id", "in": "path"}],
    )
    context = _build_context([endpoint], {"attack_playbooks": ["bola_idor"]})
    planner = AttackPlanner()

    planner.plan(context)

    logs = planner.decision_logger.get_log(str(context.scan_id))
    selection = [log for log in logs if log.step_id == "playbook:bola_idor:selected"]
    progress = [log for log in logs if log.step_id.startswith("bola_idor:")]

    assert selection
    assert selection[0].status == "selected"
    assert "reasons=" in selection[0].rationale
    assert selection[0].reason is not None
    assert len(progress) == 3
    assert all(log.status == "planned" for log in progress)


def test_planner_generates_secret_to_impact_playbook_without_secret_value_false_positive() -> None:
    endpoint = _build_endpoint(
        method="GET",
        auth_required=True,
        url_pattern="/api/reports/{id}",
        parameters=[{"name": "id", "in": "path"}],
        observed_content_type="application/json",
    )
    context = _build_context([endpoint], {"attack_playbooks": ["secret_to_impact"]})
    planner = AttackPlanner()

    tasks = planner.plan(context)

    secret_tasks = [
        task
        for task in tasks
        if _hypothesis_value(task.hypothesis, "playbook_id") == "secret_to_impact"
    ]
    assert len(secret_tasks) == 3
    assert all(_hypothesis_value(task.hypothesis, "safety_budget") for task in secret_tasks)
