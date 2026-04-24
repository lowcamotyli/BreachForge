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
        worker_id="worker-corpus",
        timestamp=datetime.now(UTC),
        request={"method": "GET", "url": "https://example.test/api/tenant/items/1"},
        response={"status": status, "body": body},
        control_probe_id=None,
    )


def test_confidence_score_below_085_is_rejected() -> None:
    strategy = TenantIsolationStrategy()
    strategy._DIFFERENTIAL_BODY_CONFIDENCE = 0.84
    task_id = uuid4()

    control_probe = _probe(status=200, body={"tenant_id": "tenant-a", "items": [1]}, attack_task_id=task_id)
    attack_probe = _probe(status=200, body={"tenant_id": "tenant-b", "items": [1]}, attack_task_id=task_id)

    artifact = strategy.validate(attack_probe=attack_probe, control_probe=control_probe)

    assert artifact is None


def test_confidence_score_at_or_above_085_passes_gate() -> None:
    strategy = TenantIsolationStrategy()
    strategy._DIFFERENTIAL_BODY_CONFIDENCE = 0.85
    task_id = uuid4()

    control_probe = _probe(status=200, body={"tenant_id": "tenant-a", "items": [1]}, attack_task_id=task_id)
    attack_probe = _probe(status=200, body={"tenant_id": "tenant-b", "items": [1]}, attack_task_id=task_id)

    artifact = strategy.validate(attack_probe=attack_probe, control_probe=control_probe)

    assert artifact is not None
    assert artifact.confidence_score >= 0.85
