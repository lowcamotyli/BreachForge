from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

from execution_plane.validator.strategies.mass_assignment import ExcessiveExposureStrategy, MassAssignmentStrategy
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


def test_mass_assignment_hidden_field_accepted_returns_differential_confidence_092() -> None:
    task_id = uuid4()
    control_probe = _probe(
        attack_task_id=task_id,
        request={"method": "GET", "url": "https://app.example.test/profile"},
        response={"json": {"id": "u-1", "email": "user@example.test", "is_admin": False}},
    )
    attack_probe = _probe(
        attack_task_id=task_id,
        control_probe_id=control_probe.id,
        request={
            "method": "PATCH",
            "url": "https://app.example.test/profile",
            "body": {"is_admin": True},
            "safe_fixture": True,
            "rollback": {"is_admin": False},
        },
        response={"json": {"id": "u-1", "email": "user@example.test", "is_admin": True}},
    )

    artifact = MassAssignmentStrategy().validate(attack_probe=attack_probe, control_probe=control_probe)

    assert artifact is not None
    assert artifact.proof_type == "differential"
    assert artifact.confidence_score == 0.92
    assert "changed_fields=is_admin" in artifact.evidence_notes
    assert "rollback_guard=performed" in artifact.evidence_notes
    assert "True" not in artifact.evidence_notes


def test_mass_assignment_ignores_hidden_field_when_post_write_state_does_not_change() -> None:
    task_id = uuid4()
    control_probe = _probe(
        attack_task_id=task_id,
        request={"method": "GET"},
        response={"json": {"is_admin": False}},
    )
    attack_probe = _probe(
        attack_task_id=task_id,
        request={"method": "PATCH", "body": {"is_admin": True}},
        response={"json": {"is_admin": False}},
    )

    artifact = MassAssignmentStrategy().validate(attack_probe=attack_probe, control_probe=control_probe)

    assert artifact is None


def test_mass_assignment_safe_fixture_without_rollback_marks_rollback_required() -> None:
    task_id = uuid4()
    control_probe = _probe(
        attack_task_id=task_id,
        request={"method": "GET"},
        response={"json": {"role": "user"}},
    )
    attack_probe = _probe(
        attack_task_id=task_id,
        request={"method": "PATCH", "body": {"role": "admin"}, "safe_fixture": True},
        response={"json": {"role": "admin"}},
    )

    artifact = MassAssignmentStrategy().validate(attack_probe=attack_probe, control_probe=control_probe)

    assert artifact is not None
    assert "rollback_guard=required" in artifact.evidence_notes
    assert "rollback_fields=role" in artifact.evidence_notes


def test_excessive_exposure_sensitive_field_returns_absolute_confidence_087_without_values() -> None:
    attack_probe = _probe(
        request={"method": "GET", "url": "https://app.example.test/profile"},
        response={
            "json": {
                "id": "u-1",
                "email": "user@example.test",
                "password_hash": "do-not-log-this",
                "profile": {"internal_id": "int-1"},
            }
        },
    )

    artifact = ExcessiveExposureStrategy().validate(attack_probe=attack_probe, control_probe=None)

    assert artifact is not None
    assert artifact.proof_type == "absolute"
    assert artifact.confidence_score == 0.87
    assert "internal_id,password_hash" in artifact.evidence_notes
    assert "do-not-log-this" not in artifact.evidence_notes


def test_excessive_exposure_ignores_non_sensitive_response_fields() -> None:
    attack_probe = _probe(
        request={"method": "GET"},
        response={"json": {"id": "u-1", "email": "user@example.test"}},
    )

    artifact = ExcessiveExposureStrategy().validate(attack_probe=attack_probe, control_probe=None)

    assert artifact is None
