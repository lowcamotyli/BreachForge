from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

from execution_plane.validator.strategies.mass_assignment import MassAssignmentStrategy
from storage.db.models import RawProbe


class MassAssignmentCorpus:
    def __init__(self) -> None:
        self.profile = {"id": "u-1", "email": "user@example.test", "is_admin": False}

    def patch_profile(self, payload: dict[str, object]) -> dict[str, object]:
        self.profile.update(payload)
        return {"status": 200, "body": dict(self.profile)}

    def get_profile(self) -> dict[str, object]:
        return {"status": 200, "body": dict(self.profile)}


def _probe(*, request: dict[str, object], response: dict[str, object], attack_task_id) -> RawProbe:
    return RawProbe(
        id=uuid4(),
        attack_task_id=attack_task_id,
        worker_id="corpus-mass-assignment",
        timestamp=datetime.now(UTC),
        request=request,
        response=response,
    )


def test_mock_profile_api_accepts_is_admin_mass_assignment_and_confirms_finding() -> None:
    corpus = MassAssignmentCorpus()
    task_id = uuid4()
    baseline = _probe(
        attack_task_id=task_id,
        request={"method": "GET", "url": "https://app.example.test/profile"},
        response=corpus.get_profile(),
    )

    corpus.patch_profile({"is_admin": True})
    verified = _probe(
        attack_task_id=task_id,
        request={
            "method": "PATCH",
            "url": "https://app.example.test/profile",
            "body": {"is_admin": True},
            "safe_fixture": True,
            "rollback": {"is_admin": False},
        },
        response=corpus.get_profile(),
    )

    artifact = MassAssignmentStrategy().validate(attack_probe=verified, control_probe=baseline)

    assert artifact is not None
    assert artifact.confidence_score == 0.92
    assert "changed_fields=is_admin" in artifact.evidence_notes
