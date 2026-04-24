from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

from control_plane.auth_manager import IdentityContext, IdentityRole
from execution_plane.validator.state_diff import compute_diff
from execution_plane.validator.validator import ExploitValidator
from execution_plane.validator.strategies.base import ValidationStrategy
from storage.db.models import ProofArtifact, RawProbe
from storage.evidence.state_store import StateSnapshot


class _StubStrategy(ValidationStrategy):
    def validate(self, attack_probe: RawProbe, control_probe: RawProbe | None) -> ProofArtifact | None:
        return ProofArtifact(
            id=uuid4(),
            attack_task_id=attack_probe.attack_task_id,
            proof_type="differential",
            confidence_score=0.95,
            attack_probe_id=attack_probe.id,
            control_probe_id=control_probe.id if control_probe is not None else None,
            summary="stub proof",
            evidence_notes="stub notes",
        )

    def expected_proof_type(self) -> str:
        return "differential"

    def expected_attack_class(self) -> str:
        return "bola"


def _probe() -> RawProbe:
    return RawProbe(
        id=uuid4(),
        attack_task_id=uuid4(),
        worker_id="worker",
        timestamp=datetime.now(UTC),
        request={"method": "GET", "url": "https://example.test/api/v1/users/1"},
        response={"status": 200, "body": {"id": 1}},
        control_probe_id=None,
    )


def test_validate_attaches_identity_role_and_state_diff() -> None:
    validator = ExploitValidator.__new__(ExploitValidator)
    strategy = _StubStrategy()
    attack_probe = _probe()
    control_probe = _probe()
    identity_context = IdentityContext(
        scan_id=uuid4(),
        role=IdentityRole.admin,
        cookies=[],
        auth_headers={"authorization": "Bearer token"},
        csrf_tokens={},
        captured_at=datetime.now(UTC),
    )
    before_snapshot = StateSnapshot(
        scan_id=str(uuid4()),
        step_id="pre",
        timestamp=datetime.now(UTC),
        state_dict={"resource_count": 1, "owner_id": 100},
        version=1,
    )
    after_snapshot = StateSnapshot(
        scan_id=before_snapshot.scan_id,
        step_id="post",
        timestamp=datetime.now(UTC),
        state_dict={"resource_count": 2, "owner_id": 200, "new_key": "value"},
        version=2,
    )

    artifact = validator.validate(
        strategy=strategy,
        attack_probe=attack_probe,
        control_probe=control_probe,
        identity_context=identity_context,
        before_snapshot=before_snapshot,
        after_snapshot=after_snapshot,
    )

    assert artifact is not None
    assert artifact.identity_role == "admin"
    expected_diff = compute_diff(before=before_snapshot, after=after_snapshot)
    assert artifact.state_diff == {
        "added": expected_diff.added,
        "removed": expected_diff.removed,
        "changed": {key: [value[0], value[1]] for key, value in expected_diff.changed.items()},
    }


def test_validate_defaults_identity_role_to_none() -> None:
    validator = ExploitValidator.__new__(ExploitValidator)
    strategy = _StubStrategy()
    attack_probe = _probe()

    artifact = validator.validate(strategy=strategy, attack_probe=attack_probe, control_probe=None)

    assert artifact is not None
    assert artifact.identity_role is None
    assert artifact.state_diff is None
