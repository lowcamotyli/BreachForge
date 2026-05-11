from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

from execution_plane.validator.strategies.behavioral import StateDeltaStrategy
from execution_plane.validator.strategies.race_condition import RaceConditionStrategy
from storage.db.models import ProofArtifact, RawProbe


def make_probe(request: dict[str, object] | None = None, response: dict[str, object] | None = None) -> RawProbe:
    return RawProbe(
        id=uuid4(),
        attack_task_id=uuid4(),
        worker_id="worker-test",
        timestamp=datetime.now(UTC),
        request=request or {"method": "POST", "url": "https://example.test/api/workflow"},
        response=response or {"status": 200, "body": {"ok": True}},
        control_probe_id=None,
    )


def test_state_delta_no_finding_when_no_pre_state() -> None:
    strategy = StateDeltaStrategy()
    probe = make_probe(response={"post_state": {"status": "approved"}})

    artifact = strategy.validate(attack_probe=probe, control_probe=None)

    assert artifact is None


def test_state_delta_no_finding_when_identical_states() -> None:
    strategy = StateDeltaStrategy()
    state = {"status": "pending", "total": 10}
    probe = make_probe(request={"pre_state": state}, response={"post_state": state})

    artifact = strategy.validate(attack_probe=probe, control_probe=None)

    assert artifact is None


def test_state_delta_finding_when_states_differ() -> None:
    strategy = StateDeltaStrategy()
    probe = make_probe(
        request={"pre_state": {"status": "pending"}},
        response={"post_state": {"status": "approved"}},
    )

    artifact = strategy.validate(attack_probe=probe, control_probe=None)

    assert isinstance(artifact, ProofArtifact)
    assert artifact.confidence_score >= 0.85


def test_state_delta_higher_confidence_when_keys_added() -> None:
    strategy = StateDeltaStrategy()
    probe = make_probe(
        request={"pre_state": {"status": "pending"}},
        response={"post_state": {"status": "pending", "approved_at": "2026-04-26T00:00:00Z"}},
    )

    artifact = strategy.validate(attack_probe=probe, control_probe=None)

    assert artifact is not None
    assert artifact.confidence_score >= 0.90


def test_race_no_finding_without_reproduction() -> None:
    strategy = RaceConditionStrategy()
    probe = make_probe()

    artifact = strategy.validate(attack_probe=probe, control_probe=None)

    assert artifact is None


def test_race_finding_with_reproduced_true() -> None:
    strategy = RaceConditionStrategy()
    probe = make_probe(request={"reproduced": True})

    artifact = strategy.validate(attack_probe=probe, control_probe=None)

    assert isinstance(artifact, ProofArtifact)


def test_race_finding_with_reproduction_count() -> None:
    strategy = RaceConditionStrategy()
    probe = make_probe(request={"reproduction_count": 3})

    artifact = strategy.validate(attack_probe=probe, control_probe=None)

    assert isinstance(artifact, ProofArtifact)


def test_race_finding_with_race_winner() -> None:
    strategy = RaceConditionStrategy()
    probe = make_probe(response={"race_winner": "thread_1"})

    artifact = strategy.validate(attack_probe=probe, control_probe=None)

    assert isinstance(artifact, ProofArtifact)
    assert artifact.confidence_score >= 0.90
