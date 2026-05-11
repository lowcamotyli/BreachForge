from __future__ import annotations

from dataclasses import dataclass, field

from execution_plane.planner.hypotheses import AttackHypothesis

_SCORE_WEIGHTS: dict[str, float] = {
    "impact": 0.32,
    "likelihood": 0.24,
    "reachability": 0.18,
    "cost": 0.14,
    "safety": 0.12,
}
_OUTCOME_DELTAS: dict[str, float] = {
    "confirmed": 0.25,
    "supported": 0.12,
    "no_signal": -0.16,
    "blocked": -0.10,
    "invalid": -0.22,
}


@dataclass(frozen=True, slots=True)
class HypothesisScore:
    impact: float
    likelihood: float
    reachability: float
    cost: float
    safety: float

    def normalized(self) -> HypothesisScore:
        return HypothesisScore(
            impact=_clamp(self.impact),
            likelihood=_clamp(self.likelihood),
            reachability=_clamp(self.reachability),
            cost=_clamp(self.cost),
            safety=_clamp(self.safety),
        )

    def composite(self) -> float:
        normalized = self.normalized()
        score = (
            normalized.impact * _SCORE_WEIGHTS["impact"]
            + normalized.likelihood * _SCORE_WEIGHTS["likelihood"]
            + normalized.reachability * _SCORE_WEIGHTS["reachability"]
            + (1.0 - normalized.cost) * _SCORE_WEIGHTS["cost"]
            + normalized.safety * _SCORE_WEIGHTS["safety"]
        )
        return round(score, 6)


@dataclass(frozen=True, slots=True)
class RankedHypothesis:
    hypothesis: AttackHypothesis
    score: float
    confidence: float
    rationale: str


@dataclass(slots=True)
class HypothesisFeedbackState:
    confidence_by_key: dict[str, float] = field(default_factory=dict)
    outcome_history: dict[str, list[str]] = field(default_factory=dict)

    def observe(self, hypothesis: AttackHypothesis, outcome: str) -> None:
        key = hypothesis.key()
        normalized_outcome = outcome.strip().lower()
        if normalized_outcome not in _OUTCOME_DELTAS:
            return

        existing_confidence = self.confidence_by_key.get(key, hypothesis.confidence)
        delta = _OUTCOME_DELTAS[normalized_outcome]
        updated_confidence = _clamp(round(existing_confidence + delta, 6))
        self.confidence_by_key[key] = updated_confidence
        self.outcome_history.setdefault(key, []).append(normalized_outcome)

    def adjusted_confidence(self, hypothesis: AttackHypothesis) -> float:
        return self.confidence_by_key.get(hypothesis.key(), hypothesis.confidence)


def rank_hypotheses(
    hypotheses: list[AttackHypothesis],
    *,
    top_k: int | None = None,
    feedback_state: HypothesisFeedbackState | None = None,
) -> list[RankedHypothesis]:
    ranked: list[RankedHypothesis] = []
    for hypothesis in hypotheses:
        adjusted_confidence = hypothesis.confidence
        if feedback_state is not None:
            adjusted_confidence = feedback_state.adjusted_confidence(hypothesis)

        score_breakdown = _score_hypothesis(hypothesis, adjusted_confidence)
        score = round(score_breakdown.composite() * (0.55 + (0.45 * adjusted_confidence)), 6)
        ranked.append(
            RankedHypothesis(
                hypothesis=hypothesis,
                score=score,
                confidence=adjusted_confidence,
                rationale=_ranking_rationale(hypothesis=hypothesis, score=score_breakdown, confidence=adjusted_confidence),
            )
        )

    ranked.sort(
        key=lambda item: (
            -item.score,
            -item.confidence,
            item.hypothesis.type,
            item.hypothesis.target,
            item.hypothesis.rationale,
        )
    )
    if top_k is None:
        return ranked
    return ranked[: max(0, top_k)]


def apply_probe_outcomes(
    feedback_state: HypothesisFeedbackState,
    hypotheses_by_key: dict[str, AttackHypothesis],
    outcomes: list[dict[str, str]],
) -> None:
    for outcome in outcomes:
        key = str(outcome.get("hypothesis_key") or "").strip().lower()
        status = str(outcome.get("status") or "").strip().lower()
        if not key or status not in _OUTCOME_DELTAS:
            continue
        hypothesis = hypotheses_by_key.get(key)
        if hypothesis is None:
            continue
        feedback_state.observe(hypothesis, status)


def _score_hypothesis(hypothesis: AttackHypothesis, confidence: float) -> HypothesisScore:
    signal_count = len(hypothesis.signals)
    impact = min(1.0, 0.45 + (0.08 * len(hypothesis.required_identities)) + (0.05 * len(hypothesis.candidate_playbooks)))
    likelihood = min(1.0, (confidence * 0.75) + min(signal_count, 6) * 0.04)
    reachability = min(1.0, 0.4 + (0.06 * signal_count))
    cost = max(0.0, 0.75 - (0.1 * len(hypothesis.candidate_playbooks)) - (0.05 * len(hypothesis.required_identities)))
    safety = min(1.0, 0.65 + (0.05 * len(hypothesis.candidate_playbooks)))
    return HypothesisScore(
        impact=impact,
        likelihood=likelihood,
        reachability=reachability,
        cost=cost,
        safety=safety,
    )


def _ranking_rationale(*, hypothesis: AttackHypothesis, score: HypothesisScore, confidence: float) -> str:
    normalized = score.normalized()
    return (
        f"advisory_hypothesis={hypothesis.type};"
        f" impact={normalized.impact:.3f};"
        f" likelihood={normalized.likelihood:.3f};"
        f" reachability={normalized.reachability:.3f};"
        f" cost={normalized.cost:.3f};"
        f" safety={normalized.safety:.3f};"
        f" confidence={confidence:.3f};"
        " validator_proof_gate_required=true"
    )


def _clamp(value: float) -> float:
    return min(1.0, max(0.0, round(float(value), 6)))
