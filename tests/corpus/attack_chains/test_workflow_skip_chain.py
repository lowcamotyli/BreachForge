"""Corpus C4: workflow skip -> state delta -> reproducible impact chain."""

from __future__ import annotations

import pytest

from control_plane.attack_chain_builder import (
    adjust_chain_severity,
    build_remediation,
    compute_chain_confidence,
    compute_chain_score,
)


def test_workflow_skip_chain_confidence() -> None:
    result = compute_chain_confidence(
        [("entry", 0.87), ("exploit", 0.91), ("impact", 0.88)],
        has_differential=True,
        has_reproducible=True,
    )

    assert result.chain_confidence >= 0.87


def test_workflow_skip_reproducible_required() -> None:
    supported = compute_chain_confidence(
        [("entry", 0.87), ("impact", 0.88)],
        has_differential=True,
        has_reproducible=True,
    )
    unsupported = compute_chain_confidence(
        [("entry", 0.87), ("impact", 0.88)],
        has_differential=False,
        has_reproducible=False,
    )

    assert supported.chain_confidence >= unsupported.chain_confidence


def test_workflow_skip_severity_medium_to_critical_requires_steps() -> None:
    two_step = adjust_chain_severity("high", 0.90, True, 2)
    three_step = adjust_chain_severity("high", 0.90, True, 3)

    assert two_step.adjusted == "high"
    assert three_step.adjusted == "critical"


def test_workflow_skip_default_remediation() -> None:
    result = build_remediation("workflow_skip", "/api/checkout/step2", 3, ["user_a"])

    assert "/api/checkout/step2" in result
    assert "3-step" in result
