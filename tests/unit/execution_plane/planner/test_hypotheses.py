from __future__ import annotations

from pathlib import Path
import sys
from uuid import uuid4

PROJECT_ROOT = Path(__file__).resolve().parents[4]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from execution_plane.planner.hypotheses import (
    AttackHypothesis,
    AttackSignal,
    extract_flow_hints_from_asset_map,
    extract_flow_hints_from_endpoint,
    extract_high_risk_parameters,
)
from storage.db.models import AssetMap, Endpoint


def _build_endpoint(
    *,
    method: str,
    url_pattern: str,
    parameters: list[dict[str, object]],
    auth_required: bool = True,
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


def test_attack_signal_normalizes_and_serializes_deterministically() -> None:
    signal = AttackSignal(
        kind=" Param ",
        key=" High_Risk_Param ",
        value=" USER_ID ",
        endpoint=" /API/Users/{ID} ",
        method=" get ",
        location="JSON",
        strength=1.123456789,
        tags=("BOLA", " param ", "BOLA"),
    )

    assert signal.kind == "param"
    assert signal.key == "high_risk_param"
    assert signal.value == "user_id"
    assert signal.endpoint == "/api/users/{id}"
    assert signal.method == "GET"
    assert signal.location == "body"
    assert signal.strength == 1.123457
    assert signal.tags == ("bola", "param")
    assert signal.to_json() == signal.to_json()


def test_attack_hypothesis_normalizes_identity_playbook_and_signal_order() -> None:
    first = AttackSignal(kind="param", key="x", value="role")
    second = AttackSignal(kind="endpoint", key="x", value="get /api/admin")
    hypothesis = AttackHypothesis(
        type=" Workflow_Privilege ",
        target=" POST /API/Approve ",
        rationale="  State   transition  might skip authz  ",
        required_identities=(" Admin ", "user", "admin"),
        candidate_playbooks=("workflow_abuse", "Privilege_Drift", "workflow_abuse"),
        confidence=1.2,
        signals=(first, second),
    )

    assert hypothesis.type == "workflow_privilege"
    assert hypothesis.target == "post /api/approve"
    assert hypothesis.rationale == "State transition might skip authz"
    assert hypothesis.required_identities == ("admin", "user")
    assert hypothesis.candidate_playbooks == ("privilege_drift", "workflow_abuse")
    assert hypothesis.confidence == 1.0
    assert hypothesis.signals == tuple(sorted((first, second), key=lambda signal: signal.to_json()))
    assert hypothesis.to_json() == hypothesis.to_json()


def test_extract_high_risk_parameters_is_ranked_and_deduplicated() -> None:
    endpoint = _build_endpoint(
        method="PATCH",
        url_pattern="/api/orgs/{org_id}/users/{id}",
        parameters=[
            {"name": "callback", "in": "query"},
            {"name": "role", "in": "body"},
            {"name": "user_id", "in": "body"},
            {"name": "status", "in": "body"},
            {"name": "role", "in": "query"},
            {"name": "random", "in": "query"},
        ],
    )

    assert extract_high_risk_parameters(endpoint) == ("id", "user_id", "org_id", "role", "status", "callback")


def test_extract_flow_hints_from_endpoint_and_asset_map_is_deterministic() -> None:
    endpoint_a = _build_endpoint(
        method="POST",
        url_pattern="/api/orders/create",
        parameters=[{"name": "status", "in": "body"}],
    )
    endpoint_b = _build_endpoint(
        method="POST",
        url_pattern="/api/reports/export",
        parameters=[{"name": "format", "in": "query"}],
    )
    endpoint_c = _build_endpoint(
        method="GET",
        url_pattern="/api/profile",
        parameters=[{"name": "expand", "in": "query"}],
    )
    asset_map = AssetMap(scan_id=uuid4())
    asset_map.endpoints = [endpoint_c, endpoint_b, endpoint_a]

    assert extract_flow_hints_from_endpoint(endpoint_a) == ("create", "status")
    hints_map = extract_flow_hints_from_asset_map(asset_map)
    assert list(hints_map.keys()) == ["POST /api/orders/create", "POST /api/reports/export"]
    assert hints_map["POST /api/orders/create"] == ("create", "status")
    assert hints_map["POST /api/reports/export"] == ("export",)
