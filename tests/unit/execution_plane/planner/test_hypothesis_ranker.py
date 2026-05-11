from __future__ import annotations

from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[4]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from execution_plane.planner.hypothesis_ranker import (
    HypothesisFeedbackState,
    apply_probe_outcomes,
    rank_hypotheses,
)
from execution_plane.planner.hypotheses import AttackHypothesis, AttackSignal


def _make_hypothesis(*, type_name: str, target: str, confidence: float, signal_count: int) -> AttackHypothesis:
    signals = tuple(
        AttackSignal(kind="endpoint", key=f"k{index}", value=f"signal_{index}") for index in range(signal_count)
    )
    return AttackHypothesis(
        type=type_name,
        target=target,
        rationale=f"rationale for {target}",
        required_identities=("user",),
        candidate_playbooks=("bola_idor",),
        confidence=confidence,
        signals=signals,
    )


def test_rank_hypotheses_is_stable_for_identical_input_and_top_k() -> None:
    hypotheses = [
        _make_hypothesis(type_name="bola_idor", target="GET /api/users/{id}", confidence=0.60, signal_count=3),
        _make_hypothesis(type_name="workflow_privilege", target="POST /api/orders/approve", confidence=0.60, signal_count=3),
        _make_hypothesis(type_name="secret_impact", target="POST /api/auth/token", confidence=0.60, signal_count=3),
    ]

    first = rank_hypotheses(hypotheses, top_k=2)
    second = rank_hypotheses(hypotheses, top_k=2)

    assert [item.hypothesis.key() for item in first] == [item.hypothesis.key() for item in second]
    assert [item.score for item in first] == [item.score for item in second]


def test_feedback_state_updates_confidence_without_restart() -> None:
    high = _make_hypothesis(type_name="bola_idor", target="GET /api/users/{id}", confidence=0.75, signal_count=4)
    low = _make_hypothesis(type_name="workflow_privilege", target="POST /api/orders/approve", confidence=0.55, signal_count=2)
    state = HypothesisFeedbackState()

    initial = rank_hypotheses([high, low], feedback_state=state)
    assert initial[0].hypothesis.key() == high.key()

    apply_probe_outcomes(
        state,
        {high.key(): high, low.key(): low},
        [
            {"hypothesis_key": high.key(), "status": "no_signal"},
            {"hypothesis_key": low.key(), "status": "confirmed"},
        ],
    )

    reranked = rank_hypotheses([high, low], feedback_state=state)
    assert reranked[0].hypothesis.key() == low.key()
    assert state.adjusted_confidence(low) > low.confidence
    assert state.adjusted_confidence(high) < high.confidence
