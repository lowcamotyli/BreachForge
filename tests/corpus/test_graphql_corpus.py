from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

from execution_plane.validator.strategies.graphql import GraphqlBatchStrategy, GraphqlIntrospectionStrategy
from storage.db.models import RawProbe
from tests.corpus.graphql_corpus import GraphqlCorpus


def _probe(*, request: dict[str, object], response: dict[str, object], attack_task_id) -> RawProbe:
    return RawProbe(
        id=uuid4(),
        attack_task_id=attack_task_id,
        worker_id="corpus-graphql",
        timestamp=datetime.now(UTC),
        request=request,
        response=response,
    )


def test_mock_graphql_server_with_introspection_confirms_critical_signal() -> None:
    corpus = GraphqlCorpus()
    task_id = uuid4()
    probe = _probe(
        attack_task_id=task_id,
        request={"method": "POST", "url": "https://app.example.test/graphql", "query": "{__schema{types{name}}}"},
        response=corpus.introspection_enabled_response(),
    )

    artifact = GraphqlIntrospectionStrategy().validate(attack_probe=probe, control_probe=None)

    assert artifact is not None
    assert artifact.confidence_score == 0.95
    assert artifact.proof_type == "absolute"


def test_mock_graphql_batch_without_rate_limit_reports_amplification_count() -> None:
    corpus = GraphqlCorpus()
    task_id = uuid4()
    control_probe = _probe(
        attack_task_id=task_id,
        request={"method": "POST", "url": "https://app.example.test/graphql", "query": "{__typename}"},
        response={"status": 200, "body": {"data": {"__typename": "Query"}}},
    )
    attack_probe = _probe(
        attack_task_id=task_id,
        request={"method": "POST", "url": "https://app.example.test/graphql", "batch_size": 20},
        response=corpus.batch_without_rate_limit_response(batch_size=20),
    )

    artifact = GraphqlBatchStrategy().validate(attack_probe=attack_probe, control_probe=control_probe)

    assert artifact is not None
    assert artifact.confidence_score == 0.88
    assert "batch_size=20" in artifact.evidence_notes
