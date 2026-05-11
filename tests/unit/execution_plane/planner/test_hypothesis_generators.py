from __future__ import annotations

from pathlib import Path
import sys
from uuid import uuid4

PROJECT_ROOT = Path(__file__).resolve().parents[4]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from execution_plane.planner.hypothesis_generators.bola import generate_bola_hypotheses
from execution_plane.planner.hypothesis_generators.secrets import generate_secret_impact_hypotheses
from execution_plane.planner.hypothesis_generators.workflow import generate_workflow_hypotheses
from storage.db.models import AssetMap, Endpoint


def _build_endpoint(
    *,
    method: str,
    url_pattern: str,
    auth_required: bool,
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


def test_bola_generator_produces_cross_identity_hypotheses() -> None:
    asset_map = AssetMap(scan_id=uuid4())
    asset_map.endpoints = [
        _build_endpoint(
            method="GET",
            url_pattern="/api/users/{user_id}",
            auth_required=True,
            parameters=[{"name": "user_id", "in": "path"}],
        ),
        _build_endpoint(
            method="POST",
            url_pattern="/api/login",
            auth_required=False,
            parameters=[{"name": "email", "in": "body"}],
        ),
    ]

    hypotheses = generate_bola_hypotheses(asset_map)

    assert len(hypotheses) == 1
    hypothesis = hypotheses[0]
    assert hypothesis.type == "bola_idor"
    assert hypothesis.required_identities == ("attacker_identity", "foreign_identity")
    assert hypothesis.candidate_playbooks == ("bola_idor",)
    assert any(signal.kind == "identity" and signal.value == "user_id" for signal in hypothesis.signals)


def test_workflow_generator_produces_privilege_hypotheses() -> None:
    asset_map = AssetMap(scan_id=uuid4())
    asset_map.endpoints = [
        _build_endpoint(
            method="POST",
            url_pattern="/api/orders/approve",
            auth_required=True,
            parameters=[{"name": "status", "in": "body"}],
        ),
        _build_endpoint(
            method="PATCH",
            url_pattern="/api/admin/users/update",
            auth_required=True,
            parameters=[{"name": "role", "in": "body"}],
        ),
        _build_endpoint(
            method="PATCH",
            url_pattern="/api/orders/state",
            auth_required=True,
            parameters=[{"name": "status", "in": "body"}],
        ),
    ]

    hypotheses = generate_workflow_hypotheses(asset_map)

    assert len(hypotheses) == 3
    assert all(hypothesis.type == "workflow_privilege" for hypothesis in hypotheses)
    assert all("workflow_abuse" in hypothesis.candidate_playbooks for hypothesis in hypotheses)
    assert any("privilege_drift" in hypothesis.candidate_playbooks for hypothesis in hypotheses)
    status_hypothesis = next(
        hypothesis for hypothesis in hypotheses if hypothesis.target == "patch /api/orders/state"
    )
    assert "privilege_drift" in status_hypothesis.candidate_playbooks
    assert status_hypothesis.required_identities == ("elevated_user", "standard_user")
    assert any(
        signal.key == "workflow_hint" and signal.value == "status"
        for signal in status_hypothesis.signals
    )


def test_secret_impact_generator_uses_blast_radius_candidates() -> None:
    asset_map = AssetMap(scan_id=uuid4())
    asset_map.endpoints = [
        _build_endpoint(
            method="POST",
            url_pattern="/api/auth/token",
            auth_required=False,
            parameters=[{"name": "username", "in": "body"}],
        ),
        _build_endpoint(
            method="GET",
            url_pattern="/api/me",
            auth_required=True,
            parameters=[],
        ),
        _build_endpoint(
            method="GET",
            url_pattern="/api/admin/audit",
            auth_required=True,
            parameters=[],
        ),
    ]

    hypotheses = generate_secret_impact_hypotheses(asset_map)

    assert len(hypotheses) == 1
    hypothesis = hypotheses[0]
    assert hypothesis.type == "secret_impact"
    assert hypothesis.candidate_playbooks == ("secret_to_impact",)
    assert any(signal.key == "blast_radius_endpoint" for signal in hypothesis.signals)
