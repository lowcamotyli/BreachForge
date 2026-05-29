from __future__ import annotations

from dataclasses import dataclass

import yaml


@dataclass
class GatePolicy:
    max_new_critical: int = 0
    max_new_high: int = 5
    no_auth_failure: bool = True
    discovery_regression: bool = False
    no_new_fp_budget: bool = False


@dataclass
class GateViolation:
    rule: str
    actual: int
    limit: int


EXIT_PASS = 0
EXIT_GATE_FAIL = 1
EXIT_SCAN_ERROR = 2


@dataclass
class GateResult:
    passed: bool
    violations: list[GateViolation]
    exit_code: int


def evaluate_gates(policy: GatePolicy, summary: dict[str, int]) -> GateResult:
    violations: list[GateViolation] = []
    new_critical = summary.get("new_critical", 0)
    new_high = summary.get("new_high", 0)
    auth_failures = summary.get("auth_failures", 0)
    discovery_failures = summary.get("discovery_failures", 0)
    fp_added = summary.get("fp_added", 0)

    if new_critical > policy.max_new_critical:
        violations.append(
            GateViolation("max_new_critical", new_critical, policy.max_new_critical)
        )
    if new_high > policy.max_new_high:
        violations.append(GateViolation("max_new_high", new_high, policy.max_new_high))
    if policy.no_auth_failure and auth_failures > 0:
        violations.append(GateViolation("no_auth_failure", auth_failures, 0))
    if policy.discovery_regression and discovery_failures > 0:
        violations.append(GateViolation("discovery_regression", discovery_failures, 0))
    if policy.no_new_fp_budget and fp_added > 0:
        violations.append(GateViolation("no_new_fp_budget", fp_added, 0))

    passed = len(violations) == 0
    return GateResult(
        passed=passed,
        violations=violations,
        exit_code=EXIT_PASS if passed else EXIT_GATE_FAIL,
    )


def load_gate_policy(path: str) -> GatePolicy:
    try:
        with open(path) as f:
            data = yaml.safe_load(f) or {}
    except FileNotFoundError:
        return GatePolicy()

    known = {k: v for k, v in data.items() if k in GatePolicy.__dataclass_fields__}
    return GatePolicy(**known)
