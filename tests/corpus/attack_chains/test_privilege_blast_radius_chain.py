"""Corpus C2: low privilege -> admin read -> blast radius chain."""

from __future__ import annotations

import pytest

from control_plane.attack_chain_builder import (
    adjust_chain_severity,
    build_remediation,
    compute_chain_confidence,
    compute_chain_score,
)


def test_privilege_escalation_chain_confidence() -> None:
    result = compute_chain_confidence(
        [("entry", 0.88), ("pivot", 0.91), ("exploit", 0.87), ("impact", 0.93)],
        has_differential=True,
        has_reproducible=True,
    )

    assert result.chain_confidence >= 0.85
    assert result.weakest_step in ("entry", "exploit")


def test_privilege_chain_differential_boost() -> None:
    boosted = compute_chain_confidence(
        [("entry", 0.86)],
        has_differential=True,
        has_reproducible=True,
    )
    unboosted = compute_chain_confidence(
        [("entry", 0.86)],
        has_differential=False,
        has_reproducible=False,
    )

    assert boosted.chain_confidence > unboosted.chain_confidence


def test_privilege_chain_severity_no_impact_downgrade() -> None:
    result = adjust_chain_severity("critical", 0.88, False, 4)

    assert result.adjusted == "high"
    assert "downgraded" in result.explanation


def test_privilege_chain_score_has_all_factors() -> None:
    result = compute_chain_score(0.85, 0.75, 0.5, 0.9, 0.7, 0.88)

    assert set(result) == {
        "impact",
        "reachability",
        "privilege",
        "repeatability",
        "blast_radius",
        "safety_confidence",
        "total",
    }


def test_privilege_chain_remediation_authz() -> None:
    result = build_remediation("privilege_escalation", "/api/admin/users", 4, ["user_low"])

    assert "authentication" in result or "role" in result
    assert "4-step" in result

