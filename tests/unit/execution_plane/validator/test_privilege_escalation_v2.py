from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

from execution_plane.validator.differential import DifferentialProbeResult
from execution_plane.validator.strategies.privilege_escalation import PrivilegeEscalationStrategy
from storage.db.models import RawProbe


def _probe(*, status: int, body: object, attack_task_id=None) -> RawProbe:
    task_id = attack_task_id or uuid4()
    return RawProbe(
        id=uuid4(),
        attack_task_id=task_id,
        worker_id="worker-test",
        timestamp=datetime.now(UTC),
        request={"method": "GET", "url": "https://example.test/api/admin/me"},
        response={"status": status, "body": body},
        control_probe_id=None,
    )


def _differential_result(*, baseline_status: int, challenger_status: int, status_differs: bool) -> DifferentialProbeResult:
    return DifferentialProbeResult(
        baseline_identity="admin",
        challenger_identity="low-privilege",
        baseline_status=baseline_status,
        challenger_status=challenger_status,
        status_differs=status_differs,
        shape_differs=False,
        ownership_markers_differ=False,
        content_length_bucket_baseline="1-100",
        content_length_bucket_challenger="1-100",
    )


def test_privilege_collapse_confirmed_with_differential_result() -> None:
    strategy = PrivilegeEscalationStrategy()
    task_id = uuid4()
    control_probe = _probe(status=200, body={"role": "viewer"}, attack_task_id=task_id)
    attack_probe = _probe(status=200, body={"role": "admin"}, attack_task_id=task_id)

    artifact = strategy.validate(
        attack_probe=attack_probe,
        control_probe=control_probe,
        differential_result=_differential_result(baseline_status=200, challenger_status=200, status_differs=False),
    )

    assert artifact is not None
    assert artifact.confidence_score == 1.0
    assert "privilege boundary collapse" in artifact.evidence_notes


def test_observed_access_separated_from_inferred_role() -> None:
    strategy = PrivilegeEscalationStrategy()
    task_id = uuid4()
    control_probe = _probe(status=200, body={"role": "viewer"}, attack_task_id=task_id)
    attack_probe = _probe(status=200, body={"ok": True}, attack_task_id=task_id)

    artifact = strategy.validate(
        attack_probe=attack_probe,
        control_probe=control_probe,
        differential_result=_differential_result(baseline_status=200, challenger_status=200, status_differs=False),
    )

    assert artifact is None


def test_single_identity_fallback_without_differential_result() -> None:
    strategy = PrivilegeEscalationStrategy()
    task_id = uuid4()
    control_probe = _probe(status=200, body={"role": "viewer"}, attack_task_id=task_id)
    attack_probe = _probe(status=200, body={"role": "admin"}, attack_task_id=task_id)

    artifact = strategy.validate(attack_probe=attack_probe, control_probe=control_probe)

    assert artifact is not None
    assert artifact.confidence_score == 0.95
