from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest

from execution_plane.validator.differential import DifferentialProbeResult
from execution_plane.validator.strategies.bola import BolaStrategy
from storage.db.models import RawProbe


def _probe(*, status: int, body: object, attack_task_id=None) -> RawProbe:
    task_id = attack_task_id or uuid4()
    return RawProbe(
        id=uuid4(),
        attack_task_id=task_id,
        worker_id="worker-test",
        timestamp=datetime.now(UTC),
        request={"method": "GET", "url": "https://example.test/api/users/1"},
        response={"status": status, "body": body},
        control_probe_id=None,
    )


def test_differential_bola_confirmed() -> None:
    strategy = BolaStrategy()
    task_id = uuid4()
    control_probe = _probe(status=200, body={"user": {"id": 1}}, attack_task_id=task_id)
    attack_probe = _probe(status=200, body={"user": {"id": 1}}, attack_task_id=task_id)

    differential_result = DifferentialProbeResult(
        baseline_identity="owner",
        challenger_identity="attacker",
        baseline_status=200,
        challenger_status=200,
        status_differs=False,
        shape_differs=False,
        ownership_markers_differ=False,
        content_length_bucket_baseline="1-100",
        content_length_bucket_challenger="1-100",
    )

    artifact = strategy.validate(
        attack_probe=attack_probe,
        control_probe=control_probe,
        differential_result=differential_result,
    )

    assert artifact is not None
    assert artifact.confidence_score == pytest.approx(0.90)
    assert "ownership_markers_differ=false" in artifact.evidence_notes


def test_single_identity_path_unchanged(monkeypatch) -> None:
    strategy = BolaStrategy()
    task_id = uuid4()
    control_probe = _probe(status=200, body={"ok": True}, attack_task_id=task_id)
    attack_probe = _probe(status=403, body={"ok": True}, attack_task_id=task_id)

    called = {"value": False}

    def _fallback(attack_probe: RawProbe, control_probe: RawProbe | None):
        called["value"] = True
        return None

    monkeypatch.setattr(strategy, "_validate_single_identity", _fallback)

    artifact = strategy.validate(attack_probe=attack_probe, control_probe=control_probe)

    assert artifact is None
    assert called["value"] is True


def test_anon_blocked_does_not_confirm_bola() -> None:
    strategy = BolaStrategy()
    task_id = uuid4()
    control_probe = _probe(status=200, body={"user": {"id": 1}}, attack_task_id=task_id)
    attack_probe = _probe(status=200, body={"user": {"id": 1}}, attack_task_id=task_id)

    differential_result = DifferentialProbeResult(
        baseline_identity="owner",
        challenger_identity="anon",
        baseline_status=200,
        challenger_status=403,
        status_differs=True,
        shape_differs=False,
        ownership_markers_differ=True,
        content_length_bucket_baseline="1-100",
        content_length_bucket_challenger="1-100",
    )

    artifact = strategy.validate(
        attack_probe=attack_probe,
        control_probe=control_probe,
        differential_result=differential_result,
    )

    assert artifact is None
