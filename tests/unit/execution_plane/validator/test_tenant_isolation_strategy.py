from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

from execution_plane.validator.strategies.tenant_isolation import TenantIsolationStrategy
from storage.db.models import RawProbe


def _probe(*, status: int, body: object, attack_task_id=None) -> RawProbe:
    task_id = attack_task_id or uuid4()
    return RawProbe(
        id=uuid4(),
        attack_task_id=task_id,
        worker_id="worker-test",
        timestamp=datetime.now(UTC),
        request={"method": "GET", "url": "https://example.test/api/tenants/tenant-a/users/1"},
        response={"status": status, "body": body},
        control_probe_id=None,
    )


def test_tenant_isolation_returns_none_when_only_status_differs_confidence_070() -> None:
    strategy = TenantIsolationStrategy()
    task_id = uuid4()
    control_probe = _probe(status=200, body={"tenant_id": "tenant-a", "users": [1]}, attack_task_id=task_id)
    attack_probe = _probe(status=403, body={"tenant_id": "tenant-a", "users": [1]}, attack_task_id=task_id)

    artifact = strategy.validate(attack_probe=attack_probe, control_probe=control_probe)

    assert artifact is None


def test_tenant_isolation_returns_artifact_when_bodies_semantically_differ_confidence_090() -> None:
    strategy = TenantIsolationStrategy()
    task_id = uuid4()
    control_probe = _probe(
        status=200,
        body='{"tenant_id":"tenant-a","users":[{"id":1,"name":"alice"}]}',
        attack_task_id=task_id,
    )
    attack_probe = _probe(
        status=200,
        body={"tenant_id": "tenant-b", "users": [{"id": 1, "name": "alice"}]},
        attack_task_id=task_id,
    )

    artifact = strategy.validate(attack_probe=attack_probe, control_probe=control_probe)

    assert artifact is not None
    assert artifact.proof_type == "differential"
    assert artifact.confidence_score == 0.90
    assert artifact.attack_probe_id == attack_probe.id
    assert artifact.control_probe_id == control_probe.id


def test_tenant_isolation_proof_gate_at_threshold_085_and_below_084() -> None:
    strategy = TenantIsolationStrategy()
    task_id = uuid4()
    control_probe = _probe(status=200, body={"tenant_id": "tenant-a"}, attack_task_id=task_id)
    attack_probe = _probe(status=200, body={"tenant_id": "tenant-b"}, attack_task_id=task_id)

    strategy._DIFFERENTIAL_BODY_CONFIDENCE = 0.85
    at_threshold_artifact = strategy.validate(attack_probe=attack_probe, control_probe=control_probe)
    assert at_threshold_artifact is not None
    assert at_threshold_artifact.confidence_score == 0.85

    strategy._DIFFERENTIAL_BODY_CONFIDENCE = 0.84
    below_threshold_artifact = strategy.validate(attack_probe=attack_probe, control_probe=control_probe)
    assert below_threshold_artifact is None
