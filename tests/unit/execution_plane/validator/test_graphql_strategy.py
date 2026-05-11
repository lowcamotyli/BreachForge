from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

from execution_plane.validator.strategies.graphql import (
    GraphqlBatchStrategy,
    GraphqlDepthStrategy,
    GraphqlFieldSuggestionStrategy,
    GraphqlIntrospectionStrategy,
)
from storage.db.models import RawProbe


def _probe(
    *,
    request: dict[str, object] | None = None,
    response: dict[str, object] | None = None,
    attack_task_id=None,
) -> RawProbe:
    task_id = attack_task_id or uuid4()
    return RawProbe(
        id=uuid4(),
        attack_task_id=task_id,
        worker_id="worker-test",
        timestamp=datetime.now(UTC),
        request=request or {},
        response=response or {},
        control_probe_id=None,
    )


def test_introspection_enabled_returns_absolute_high_confidence() -> None:
    strategy = GraphqlIntrospectionStrategy()
    probe = _probe(response={"json": {"__schema": {"types": []}}})

    artifact = strategy.validate(probe, None)

    assert artifact is not None
    assert artifact.proof_type == "absolute"
    assert artifact.confidence_score == 0.95


def test_introspection_disabled_returns_none() -> None:
    strategy = GraphqlIntrospectionStrategy()
    probe = _probe(response={"body": "Introspection is disabled"})

    artifact = strategy.validate(probe, None)

    assert artifact is None


def test_introspection_prefers_unauth_probe_first() -> None:
    strategy = GraphqlIntrospectionStrategy()
    task_id = uuid4()
    auth_probe = _probe(
        attack_task_id=task_id,
        request={"headers": {"Authorization": "Bearer token"}},
        response={"body": "{}"},
    )
    unauth_probe = _probe(
        attack_task_id=task_id,
        request={},
        response={"json": {"__type": {"name": "Query"}}},
    )

    artifact = strategy.validate(auth_probe, unauth_probe)

    assert artifact is not None
    assert "probe_auth=False" in artifact.evidence_notes


def test_batch_returns_differential_when_20_without_throttle() -> None:
    strategy = GraphqlBatchStrategy()
    batch_probe = _probe(response={"responses": [{"status": 200} for _ in range(20)]})
    control_probe = _probe(response={"status": 200}, attack_task_id=batch_probe.attack_task_id)

    artifact = strategy.validate(batch_probe, control_probe)

    assert artifact is not None
    assert artifact.proof_type == "differential"
    assert artifact.confidence_score == 0.88


def test_field_suggestion_redacts_field_names_and_requires_out_of_spec_field() -> None:
    strategy = GraphqlFieldSuggestionStrategy()
    probe = _probe(
        request={"invalid_field": "adminPassword", "schema_fields": ["id", "name"]},
        response={"body": 'Cannot query field "adminPassword" on type "Query". Did you mean "password"?'},
    )

    artifact = strategy.validate(probe, None)

    assert artifact is not None
    assert artifact.confidence_score == 0.85
    assert "adminPassword" not in artifact.evidence_notes
    assert "password" not in artifact.evidence_notes
    assert "<redacted>" in artifact.evidence_notes


def test_depth_timeout_signal_returns_absolute_without_retry() -> None:
    strategy = GraphqlDepthStrategy()
    probe = _probe(
        request={"probe_type": "graphql_depth", "max_depth": 10, "retry_count": 0},
        response={"status": 504, "timeout": True, "body": "query timed out"},
    )

    artifact = strategy.validate(probe, None)

    assert artifact is not None
    assert artifact.proof_type == "absolute"
    assert artifact.confidence_score == 0.86
    assert "retries=0" in artifact.evidence_notes
