#!/usr/bin/env python3
"""Red-team simulation harness — runs curated attack chain scenarios for CI smoke testing."""
from __future__ import annotations

import sys
from dataclasses import dataclass

from control_plane.attack_chain_builder import (
    ChainConfidenceResult,
    SeverityAdjustment,
    adjust_chain_severity,
    build_remediation,
    compute_chain_confidence,
    compute_chain_score,
)

PROOF_GATE = 0.85


@dataclass
class Scenario:
    name: str
    attack_class: str
    steps: list[tuple[str, float]]
    has_differential: bool
    has_reproducible: bool
    base_severity: str
    has_impact_evidence: bool
    root_endpoint: str
    identities: list[str]
    expect_pass: bool


SCENARIOS: list[Scenario] = [
    Scenario(
        name="C1_bola_tenant_chain",
        attack_class="bola",
        steps=[("entry", 0.92), ("pivot", 0.88), ("impact", 0.90)],
        has_differential=True,
        has_reproducible=True,
        base_severity="high",
        has_impact_evidence=True,
        root_endpoint="/api/resources/{id}",
        identities=["user_a", "user_b"],
        expect_pass=True,
    ),
    Scenario(
        name="C2_privilege_blast_radius",
        attack_class="privilege_escalation",
        steps=[("entry", 0.88), ("pivot", 0.91), ("exploit", 0.87), ("impact", 0.93)],
        has_differential=True,
        has_reproducible=True,
        base_severity="high",
        has_impact_evidence=True,
        root_endpoint="/api/admin/users",
        identities=["user_low"],
        expect_pass=True,
    ),
    Scenario(
        name="C3_secret_exposure_chain",
        attack_class="sensitive_exposure",
        steps=[("entry", 0.95), ("pivot", 0.89), ("exploit", 0.91), ("impact", 0.90)],
        has_differential=True,
        has_reproducible=True,
        base_severity="high",
        has_impact_evidence=True,
        root_endpoint="/api/config",
        identities=["attacker"],
        expect_pass=True,
    ),
    Scenario(
        name="C4_workflow_skip_chain",
        attack_class="workflow_skip",
        steps=[("entry", 0.87), ("exploit", 0.91), ("impact", 0.88)],
        has_differential=True,
        has_reproducible=True,
        base_severity="high",
        has_impact_evidence=True,
        root_endpoint="/api/checkout/step2",
        identities=["user_a"],
        expect_pass=True,
    ),
    Scenario(
        name="C5_negative_weak_link",
        attack_class="bola",
        steps=[("entry", 0.90), ("pivot", 0.60), ("impact", 0.92)],
        has_differential=False,
        has_reproducible=False,
        base_severity="high",
        has_impact_evidence=True,
        root_endpoint="/api/items/{id}",
        identities=["user_x"],
        expect_pass=False,
    ),
]


def run_scenario(s: Scenario) -> tuple[bool, str]:
    conf_result = compute_chain_confidence(s.steps, s.has_differential, s.has_reproducible)
    passed_gate = conf_result.chain_confidence >= PROOF_GATE
    if s.expect_pass and not passed_gate:
        return False, f"FAIL {s.name}: expected chain to pass gate, got {conf_result.chain_confidence:.3f}"
    if not s.expect_pass and passed_gate:
        return False, f"FAIL {s.name}: expected chain to fail gate, got {conf_result.chain_confidence:.3f}"

    adj = adjust_chain_severity(s.base_severity, conf_result.chain_confidence, s.has_impact_evidence, len(s.steps))
    score = compute_chain_score(0.8, 0.7, 0.6, 0.8, 0.5, conf_result.chain_confidence)
    rem = build_remediation(s.attack_class, s.root_endpoint, len(s.steps), s.identities)

    return True, (
        f"PASS {s.name}: conf={conf_result.chain_confidence:.3f} "
        f"sev={adj.adjusted} score={score['total']:.4f} weakest={conf_result.weakest_step}"
    )


def main() -> int:
    results = [run_scenario(s) for s in SCENARIOS]
    for ok, msg in results:
        print(msg)
    failures = sum(1 for ok, _ in results if not ok)
    if failures:
        print(f"\n{failures}/{len(SCENARIOS)} scenarios FAILED")
        return 1
    print(f"\nAll {len(SCENARIOS)} scenarios PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
