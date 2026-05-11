"""Corpus C3: secret exposure -> accepted token -> privilege fingerprint -> remediation."""

from __future__ import annotations

import pytest

from control_plane.attack_chain_builder import (
    adjust_chain_severity,
    build_remediation,
    compute_chain_confidence,
    compute_chain_score,
)


def test_secret_exposure_chain_confidence() -> None:
    result = compute_chain_confidence(
        [("entry", 0.95), ("pivot", 0.89), ("exploit", 0.91), ("impact", 0.90)],
        has_differential=True,
        has_reproducible=True,
    )

    assert result.chain_confidence >= 0.85


def test_secret_exposure_weak_link_lowers_chain() -> None:
    result = compute_chain_confidence(
        [("entry", 0.95), ("pivot", 0.60), ("exploit", 0.91)],
        has_differential=False,
        has_reproducible=False,
    )

    assert result.chain_confidence == pytest.approx(0.60)
    assert result.weakest_step == "pivot"


def test_secret_exposure_low_confidence_downgrade() -> None:
    result = adjust_chain_severity("high", 0.65, True, 3)

    assert result.adjusted in ("medium", "low")
    assert "0.65" in result.explanation


def test_secret_exposure_remediation_rotate() -> None:
    result = build_remediation("sensitive_exposure", "/api/config", 4, ["attacker"])

    assert "rotate" in result.lower() or "secret" in result.lower()


def test_secret_exposure_chain_score_bounded() -> None:
    result = compute_chain_score(0.95, 0.80, 0.70, 0.90, 0.65, 0.91)

    assert 0 <= result["total"] <= 1
