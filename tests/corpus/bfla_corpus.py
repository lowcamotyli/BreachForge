from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

from execution_plane.validator.strategies.bfla import BflaStrategy
from storage.db.models import RawProbe


class BflaCorpus:
    def __init__(self) -> None:
        self.users = [{"id": "u-1", "role": "user"}, {"id": "u-2", "role": "viewer"}]
        self.fixture_exists = True

    def get_admin_users(self, *, role: str) -> dict[str, object]:
        if role == "admin":
            return {"status": 200, "json": {"users": self.users, "source": "admin"}}
        return {"status": 200, "json": {"users": self.users, "source": "low_privilege"}}

    def delete_safe_fixture(self, *, role: str) -> dict[str, object]:
        if role in {"admin", "manager", "user"} and self.fixture_exists:
            return {"status": 200, "body": "bounded delete accepted; fixture retained"}
        return {"status": 403, "body": "forbidden"}

    def verify_fixture(self) -> dict[str, object]:
        return {"status": 200, "json": {"exists": self.fixture_exists}}


def _probe(
    *,
    request: dict[str, object],
    response: dict[str, object],
    attack_task_id,
    control_probe_id=None,
) -> RawProbe:
    return RawProbe(
        id=uuid4(),
        attack_task_id=attack_task_id,
        worker_id="corpus-bfla",
        timestamp=datetime.now(UTC),
        request=request,
        response=response,
        control_probe_id=control_probe_id,
    )


def test_mock_api_user_can_access_admin_users_and_confirms_bfla() -> None:
    corpus = BflaCorpus()
    task_id = uuid4()
    control_probe = _probe(
        attack_task_id=task_id,
        request={"method": "GET", "url": "https://app.example.test/admin/users", "identity_role": "admin"},
        response=corpus.get_admin_users(role="admin"),
    )
    attack_probe = _probe(
        attack_task_id=task_id,
        control_probe_id=control_probe.id,
        request={
            "method": "GET",
            "url": "https://app.example.test/admin/users",
            "identity_role": "user",
            "expected_statuses": [403, 404],
        },
        response=corpus.get_admin_users(role="user"),
    )

    artifact = BflaStrategy().validate(attack_probe=attack_probe, control_probe=control_probe)

    assert artifact is not None
    assert artifact.confidence_score == 0.92
    assert "invoked_role=user" in artifact.evidence_notes
    assert "body_evidence=json_keys=source,users" in artifact.evidence_notes


def test_mock_api_delete_safe_fixture_without_admin_confirms_bfla_and_preserves_fixture() -> None:
    corpus = BflaCorpus()
    task_id = uuid4()
    attack_probe = _probe(
        attack_task_id=task_id,
        request={
            "method": "DELETE",
            "url": "https://app.example.test/admin/fixtures/bfla-temp",
            "identity_role": "user",
            "safe_fixture": True,
            "mutation_allowed": True,
        },
        response=corpus.delete_safe_fixture(role="user"),
    )

    artifact = BflaStrategy().validate(attack_probe=attack_probe, control_probe=None)

    assert corpus.verify_fixture()["json"] == {"exists": True}
    assert artifact is not None
    assert artifact.confidence_score == 0.95
    assert "method=DELETE" in artifact.evidence_notes
