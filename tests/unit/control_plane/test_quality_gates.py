from __future__ import annotations

import yaml

from control_plane.quality_gates import (
    EXIT_GATE_FAIL,
    EXIT_PASS,
    GatePolicy,
    evaluate_gates,
    load_gate_policy,
)


def test_gate_pass() -> None:
    summary = {
        "new_critical": 0,
        "new_high": 0,
        "auth_failures": 0,
        "discovery_failures": 0,
        "fp_added": 0,
    }

    result = evaluate_gates(GatePolicy(), summary)

    assert result.passed is True
    assert result.exit_code == EXIT_PASS
    assert result.violations == []


def test_gate_fail_critical() -> None:
    result = evaluate_gates(GatePolicy(), {"new_critical": 1})

    assert result.passed is False
    assert result.exit_code == EXIT_GATE_FAIL
    assert result.violations[0].rule == "max_new_critical"


def test_gate_fail_high() -> None:
    result = evaluate_gates(GatePolicy(), {"new_high": 6})

    assert result.passed is False
    assert result.exit_code == EXIT_GATE_FAIL
    assert result.violations[0].rule == "max_new_high"


def test_no_auth_failure_triggered() -> None:
    result = evaluate_gates(
        GatePolicy(no_auth_failure=True),
        {"auth_failures": 2},
    )

    assert result.passed is False
    assert result.exit_code == EXIT_GATE_FAIL
    assert result.violations[0].rule == "no_auth_failure"


def test_auth_failure_not_enforced() -> None:
    result = evaluate_gates(
        GatePolicy(no_auth_failure=False),
        {"auth_failures": 2},
    )

    assert result.passed is True
    assert result.exit_code == EXIT_PASS


def test_load_policy_defaults_on_missing() -> None:
    assert load_gate_policy("/nonexistent") == GatePolicy()


def test_load_policy_from_yaml(tmp_path) -> None:
    policy_path = tmp_path / "quality-gates.yaml"
    policy_path.write_text(
        yaml.safe_dump({"max_new_critical": 2, "max_new_high": 10}),
        encoding="utf-8",
    )

    assert load_gate_policy(str(policy_path)) == GatePolicy(
        max_new_critical=2,
        max_new_high=10,
    )


def test_deterministic_exit_code() -> None:
    policy = GatePolicy()
    summary = {"new_critical": 1, "new_high": 6, "auth_failures": 1}

    first = evaluate_gates(policy, summary)
    second = evaluate_gates(policy, summary)

    assert first.exit_code == second.exit_code
