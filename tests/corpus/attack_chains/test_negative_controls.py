"""Corpus C5: negative controls - chains with weak confidence must not pass proof gate."""

from __future__ import annotations

import pytest

from control_plane.attack_chain_builder import adjust_chain_severity, compute_chain_confidence

PROOF_GATE = 0.85


def _rank(s: str) -> int:
    return {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}[s]


def test_single_weak_step_fails_gate() -> None:
    result = compute_chain_confidence(
        [("entry", 0.70)],
        has_differential=False,
        has_reproducible=False,
    )

    assert result.chain_confidence < PROOF_GATE


def test_chain_with_weak_link_fails_gate() -> None:
    result = compute_chain_confidence(
        [("entry", 0.90), ("pivot", 0.60), ("impact", 0.92)],
        has_differential=False,
        has_reproducible=False,
    )

    assert result.chain_confidence < PROOF_GATE


def test_differential_boost_cannot_exceed_1() -> None:
    result = compute_chain_confidence(
        [("entry", 1.0)],
        has_differential=True,
        has_reproducible=True,
    )

    assert result.chain_confidence <= 1.0


def test_no_severity_upgrade_without_impact_evidence() -> None:
    result = adjust_chain_severity("high", 0.90, False, 5)

    assert result.adjusted != "critical"


def test_low_confidence_never_upgrades() -> None:
    result = adjust_chain_severity("high", 0.65, True, 3)

    assert _rank(result.adjusted) <= _rank("high")


def test_critical_without_evidence_downgrades() -> None:
    result = adjust_chain_severity("critical", 0.90, False, 2)

    assert result.adjusted == "high"
