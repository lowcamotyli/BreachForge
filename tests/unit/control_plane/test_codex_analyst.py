from __future__ import annotations

from control_plane.codex_analyst import CodexAnalyst
from execution_plane.planner.hypothesis_ranker import HypothesisFeedbackState
from execution_plane.planner.hypotheses import AttackHypothesis, AttackSignal


def _hypothesis(type_name: str, target: str, confidence: float) -> AttackHypothesis:
    return AttackHypothesis(
        type=type_name,
        target=target,
        rationale=f"rationale:{target}",
        required_identities=("user",),
        candidate_playbooks=("workflow_abuse",),
        confidence=confidence,
        signals=(AttackSignal(kind="endpoint", key="endpoint", value=target),),
    )


def test_rank_hypotheses_advisory_returns_sorted_advisory_payload() -> None:
    analyst = CodexAnalyst()
    hypotheses = [
        _hypothesis("workflow_privilege", "POST /api/orders/approve", 0.55),
        _hypothesis("bola_idor", "GET /api/users/{id}", 0.75),
    ]

    ranked = analyst.rank_hypotheses_advisory(hypotheses, top_k=2)

    assert len(ranked) == 2
    assert ranked[0]["priority"] >= ranked[1]["priority"]
    assert ranked[0]["type"] in {"workflow_privilege", "bola_idor"}
    assert all("validator_proof_gate_required=true" in item["rationale"] for item in ranked)


def test_rank_hypotheses_advisory_applies_outcomes_to_feedback_state() -> None:
    analyst = CodexAnalyst()
    state = HypothesisFeedbackState()
    high = _hypothesis("workflow_privilege", "POST /api/orders/approve", 0.75)
    low = _hypothesis("secret_impact", "POST /api/auth/token", 0.50)

    initial = analyst.rank_hypotheses_advisory([high, low], top_k=2, feedback_state=state)
    assert initial[0]["hypothesis_key"] == high.key()

    reranked = analyst.rank_hypotheses_advisory(
        [high, low],
        outcomes=[
            {"hypothesis_key": high.key(), "status": "no_signal"},
            {"hypothesis_key": low.key(), "status": "confirmed"},
        ],
        top_k=2,
        feedback_state=state,
    )

    assert reranked[0]["hypothesis_key"] == low.key()
