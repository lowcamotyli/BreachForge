from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

from execution_plane.validator.strategies.bfla import BflaStrategy
from storage.db.models import RawProbe


def _probe(
    *,
    request: dict[str, object],
    response: dict[str, object],
    attack_task_id=None,
    control_probe_id=None,
) -> RawProbe:
    return RawProbe(
        id=uuid4(),
        attack_task_id=attack_task_id or uuid4(),
        worker_id="worker-test",
        timestamp=datetime.now(UTC),
        request=request,
        response=response,
        control_probe_id=control_probe_id,
    )


def test_bfla_admin_path_low_priv_200_with_body_returns_092() -> None:
    strategy = BflaStrategy()
    task_id = uuid4()
    control_probe = _probe(
        attack_task_id=task_id,
        request={"method": "GET", "identity_role": "admin"},
        response={"status": 200, "json": {"id": "admin-view"}},
    )
    attack_probe = _probe(
        attack_task_id=task_id,
        control_probe_id=control_probe.id,
        request={
            "method": "GET",
            "identity_role": "viewer",
            "hypothesis": '{"expected_low_priv_status":[403,404]}',
        },
        response={"status": 200, "json": {"users": [{"id": "u-1"}]}},
    )

    artifact = strategy.validate(attack_probe=attack_probe, control_probe=control_probe)

    assert artifact is not None
    assert artifact.confidence_score == 0.92
    assert "invoked_role=viewer" in artifact.evidence_notes
    assert "expected_status=403|404" in artifact.evidence_notes
    assert "received_status=200" in artifact.evidence_notes
    assert "body_evidence=json_keys=users" in artifact.evidence_notes


def test_bfla_delete_200_without_admin_token_returns_095() -> None:
    strategy = BflaStrategy()
    attack_probe = _probe(
        request={
            "method": "DELETE",
            "identity_role": "user",
            "headers": {"authorization": "Bearer user-token"},
        },
        response={"status": 200, "body": "deleted"},
    )

    artifact = strategy.validate(attack_probe=attack_probe, control_probe=None)

    assert artifact is not None
    assert artifact.confidence_score == 0.95
    assert "method=DELETE" in artifact.evidence_notes


def test_bfla_404_for_both_roles_is_not_bfla() -> None:
    strategy = BflaStrategy()
    task_id = uuid4()
    control_probe = _probe(
        attack_task_id=task_id,
        request={"method": "GET", "identity_role": "admin"},
        response={"status": 404},
    )
    attack_probe = _probe(
        attack_task_id=task_id,
        control_probe_id=control_probe.id,
        request={"method": "GET", "identity_role": "guest"},
        response={"status": 404},
    )

    artifact = strategy.validate(attack_probe=attack_probe, control_probe=control_probe)

    assert artifact is None


def test_bfla_filters_login_redirect_and_method_not_allowed() -> None:
    strategy = BflaStrategy()

    redirect_probe = _probe(
        request={"method": "GET", "identity_role": "user"},
        response={"status": 401, "headers": {"Location": "/login"}},
    )
    method_not_allowed_probe = _probe(
        request={"method": "DELETE", "identity_role": "user"},
        response={"status": 405, "body": "method not allowed"},
    )

    assert strategy.validate(attack_probe=redirect_probe, control_probe=None) is None
    assert strategy.validate(attack_probe=method_not_allowed_probe, control_probe=None) is None


def test_bfla_admin_forbidden_control_is_not_bfla() -> None:
    strategy = BflaStrategy()
    task_id = uuid4()
    control_probe = _probe(
        attack_task_id=task_id,
        request={"method": "GET", "identity_role": "admin"},
        response={"status": 403},
    )
    attack_probe = _probe(
        attack_task_id=task_id,
        control_probe_id=control_probe.id,
        request={"method": "GET", "identity_role": "user"},
        response={"status": 200, "json": {"users": [{"id": "u-1"}]}},
    )

    artifact = strategy.validate(attack_probe=attack_probe, control_probe=control_probe)

    assert artifact is None


def test_bfla_rejects_restricted_verb_with_elevated_identity() -> None:
    strategy = BflaStrategy()
    attack_probe = _probe(
        request={
            "method": "DELETE",
            "identity_role": "admin",
            "headers": {"X-Role": "admin"},
        },
        response={"status": 200, "body": "deleted"},
    )

    artifact = strategy.validate(attack_probe=attack_probe, control_probe=None)

    assert artifact is None
