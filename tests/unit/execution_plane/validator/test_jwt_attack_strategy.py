from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

from execution_plane.validator.strategies.jwt_attack import JwtAttackStrategy
from storage.db.models import RawProbe


def _probe(*, probe_type: str, status: int, body: object, attack_task_id=None) -> RawProbe:
    task_id = attack_task_id or uuid4()
    return RawProbe(
        id=uuid4(),
        attack_task_id=task_id,
        worker_id="worker-test",
        timestamp=datetime.now(UTC),
        request={
            "probe_type": probe_type,
            "method": "GET",
            "url": "https://example.test/api/data",
        },
        response={"status": status, "body": body},
        control_probe_id=None,
    )


def test_alg_none_accepted_returns_artifact_092() -> None:
    strategy = JwtAttackStrategy()
    task_id = uuid4()
    body = {"user": {"id": 1, "role": "user"}, "data": [1, 2, 3]}
    control_probe = _probe(probe_type="control", status=200, body=body, attack_task_id=task_id)
    attack_probe = _probe(probe_type="alg_none", status=200, body=body, attack_task_id=task_id)

    artifact = strategy.validate(attack_probe=attack_probe, control_probe=control_probe)

    assert artifact is not None
    assert artifact.proof_type == "differential"
    assert artifact.confidence_score == 0.92


def test_alg_none_no_control_probe_returns_none() -> None:
    strategy = JwtAttackStrategy()
    attack_probe = _probe(probe_type="alg_none", status=200, body={"data": [1, 2, 3]})

    artifact = strategy.validate(attack_probe=attack_probe, control_probe=None)

    assert artifact is None


def test_alg_none_body_match_below_threshold_returns_none() -> None:
    strategy = JwtAttackStrategy()
    task_id = uuid4()
    control_probe = _probe(
        probe_type="control",
        status=200,
        body={"user": {"id": 1, "role": "user"}, "data": [1, 2, 3]},
        attack_task_id=task_id,
    )
    attack_probe = _probe(
        probe_type="alg_none",
        status=200,
        body={"warehouse": ["alpha", "bravo"], "metrics": {"blocked": 19}},
        attack_task_id=task_id,
    )

    artifact = strategy.validate(attack_probe=attack_probe, control_probe=control_probe)

    assert artifact is None


def test_claim_escalation_role_accepted_returns_artifact() -> None:
    strategy = JwtAttackStrategy()
    task_id = uuid4()
    body = {"user": {"id": 1, "role": "admin"}, "data": [1, 2, 3]}
    control_probe = _probe(probe_type="control", status=200, body=body, attack_task_id=task_id)
    attack_probe = _probe(
        probe_type="claim_escalation_role",
        status=200,
        body=body,
        attack_task_id=task_id,
    )

    artifact = strategy.validate(attack_probe=attack_probe, control_probe=control_probe)

    assert artifact is not None
    assert artifact.confidence_score == 0.92


def test_claim_escalation_scope_accepted_returns_artifact() -> None:
    strategy = JwtAttackStrategy()
    task_id = uuid4()
    control_body = {"scope": ["read", "write"], "data": {"items": [1, 2, 3]}}
    attack_body = {"scope": ["read", "write"], "data": {"items": [1, 2, 3]}}
    control_probe = _probe(probe_type="control", status=200, body=control_body, attack_task_id=task_id)
    attack_probe = _probe(
        probe_type="claim_escalation_scope",
        status=200,
        body=attack_body,
        attack_task_id=task_id,
    )

    artifact = strategy.validate(attack_probe=attack_probe, control_probe=control_probe)

    assert artifact is not None
    assert artifact.confidence_score == 0.92


def test_expired_token_acceptance_server_returns_200() -> None:
    strategy = JwtAttackStrategy()
    attack_probe = _probe(
        probe_type="expired_token_acceptance",
        status=200,
        body={"data": "ok"},
    )

    artifact = strategy.validate(attack_probe=attack_probe, control_probe=None)

    assert artifact is not None
    assert artifact.confidence_score == 0.88


def test_expired_token_acceptance_server_rejects_401_returns_none() -> None:
    strategy = JwtAttackStrategy()
    attack_probe = _probe(
        probe_type="expired_token_acceptance",
        status=401,
        body={"error": "expired"},
    )

    artifact = strategy.validate(attack_probe=attack_probe, control_probe=None)

    assert artifact is None


def test_kid_path_traversal_accepted_returns_artifact_090() -> None:
    strategy = JwtAttackStrategy()
    task_id = uuid4()
    body = {"user": {"id": 1}, "data": [1, 2, 3]}
    control_probe = _probe(probe_type="control", status=200, body=body, attack_task_id=task_id)
    attack_probe = _probe(
        probe_type="kid_path_traversal",
        status=200,
        body=body,
        attack_task_id=task_id,
    )

    artifact = strategy.validate(attack_probe=attack_probe, control_probe=control_probe)

    assert artifact is not None
    assert artifact.confidence_score == 0.90


def test_kid_sql_injection_accepted_returns_artifact_090() -> None:
    strategy = JwtAttackStrategy()
    task_id = uuid4()
    body = {"user": {"id": 1}, "data": [1, 2, 3]}
    control_probe = _probe(probe_type="control", status=200, body=body, attack_task_id=task_id)
    attack_probe = _probe(
        probe_type="kid_sql_injection",
        status=200,
        body=body,
        attack_task_id=task_id,
    )

    artifact = strategy.validate(attack_probe=attack_probe, control_probe=control_probe)

    assert artifact is not None
    assert artifact.confidence_score == 0.90


def test_evidence_notes_contain_no_token_values() -> None:
    strategy = JwtAttackStrategy()
    task_id = uuid4()
    body = {"user": {"id": 1, "role": "user"}, "data": [1, 2, 3]}
    control_probe = _probe(probe_type="control", status=200, body=body, attack_task_id=task_id)
    attack_probe = _probe(probe_type="alg_none", status=200, body=body, attack_task_id=task_id)

    artifact = strategy.validate(attack_probe=attack_probe, control_probe=control_probe)

    assert artifact is not None
    assert "Bearer" not in artifact.evidence_notes
    assert "eyJ" not in artifact.evidence_notes


def test_unknown_probe_type_returns_none() -> None:
    strategy = JwtAttackStrategy()
    attack_probe = _probe(probe_type="unknown_probe", status=200, body={"data": "ok"})

    artifact = strategy.validate(attack_probe=attack_probe, control_probe=None)

    assert artifact is None


def test_expected_proof_type_is_differential() -> None:
    assert JwtAttackStrategy().expected_proof_type() == "differential"


def test_expected_attack_class_is_jwt_attack() -> None:
    assert JwtAttackStrategy().expected_attack_class() == "jwt_attack"
