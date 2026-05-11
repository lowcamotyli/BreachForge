"""Corpus C1: BOLA read -> write candidate -> tenant impact chain."""

from __future__ import annotations

import pytest

from api.models.responses import AttackChain, AttackChainScoreFactors, AttackChainStep
from control_plane.attack_chain_builder import (
    adjust_chain_severity,
    build_remediation,
    compute_chain_confidence,
    compute_chain_score,
)


def test_bola_tenant_chain_confidence() -> None:
    result = compute_chain_confidence(
        [("entry", 0.92), ("pivot", 0.88), ("impact", 0.90)],
        has_differential=True,
        has_reproducible=True,
    )

    assert result.chain_confidence >= 0.85
    assert result.weakest_step == "pivot"
    assert result.has_differential_support is True


def test_bola_chain_severity_upgrade() -> None:
    result = adjust_chain_severity("high", 0.90, True, 3)

    assert result.adjusted == "critical"
    assert "upgraded" in result.explanation


def test_bola_chain_score_factors() -> None:
    result = compute_chain_score(0.9, 0.8, 0.7, 0.85, 0.6, 0.9)

    assert "total" in result
    assert 0 < result["total"] <= 1


def test_bola_chain_remediation() -> None:
    result = build_remediation("bola", "/api/resources/{id}", 3, ["user_a", "user_b"])

    assert "object-level authorization" in result
    assert "Affected identities: 2" in result


def test_bola_chain_model_serializable() -> None:
    score = compute_chain_score(0.9, 0.8, 0.7, 0.85, 0.6, 0.9)
    chain = AttackChain(
        id="chain_bola_tenant",
        root_cause_id="finding_bola_read",
        steps=[
            AttackChainStep(
                phase="entry",
                description="Read another tenant resource by changing object id.",
                endpoint="/api/resources/{id}",
                evidence_ref="evidence_entry",
                confidence=0.92,
            ),
            AttackChainStep(
                phase="pivot",
                description="Identify write candidate exposed by the same object scope.",
                endpoint="/api/resources/{id}",
                evidence_ref="evidence_pivot",
                confidence=0.88,
            ),
            AttackChainStep(
                phase="impact",
                description="Confirm tenant impact using differential identities.",
                endpoint="/api/resources/{id}",
                evidence_ref="evidence_impact",
                confidence=0.90,
            ),
        ],
        identities=["user_a", "user_b"],
        evidence_refs=["evidence_entry", "evidence_pivot", "evidence_impact"],
        chain_confidence=0.90,
        severity="critical",
        severity_explanation="upgraded to critical: multi-step chain with proven impact evidence",
        score_factors=AttackChainScoreFactors(**score),
        remediation=build_remediation("bola", "/api/resources/{id}", 3, ["user_a", "user_b"]),
    )

    dumped = chain.model_dump()

    assert dumped["severity"] == "critical"

