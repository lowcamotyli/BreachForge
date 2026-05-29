from __future__ import annotations

import pytest

from execution_plane.planner.scan_budget import (
    FAST_SCAN_BUDGET,
    FULL_SCAN_BUDGET,
    filter_attack_classes,
    get_budget,
)


def test_fast_budget_filters() -> None:
    available = [
        "bola",
        "auth_bypass",
        "tenant_isolation",
        "jwt_attack",
        "privilege_escalation",
        "idor",
        "ssrf",
        "sensitive_exposure",
        "csrf",
        "graphql",
    ]

    filtered = filter_attack_classes(FAST_SCAN_BUDGET, available)

    assert filtered == [
        "bola",
        "auth_bypass",
        "tenant_isolation",
        "jwt_attack",
        "privilege_escalation",
        "idor",
        "ssrf",
        "sensitive_exposure",
    ]


def test_full_budget_allows_all() -> None:
    available = ["bola", "csrf", "graphql", "ssrf"]

    filtered = filter_attack_classes(FULL_SCAN_BUDGET, available)

    assert filtered == available
    assert filtered is not available


def test_get_budget_fast() -> None:
    assert get_budget("fast") is FAST_SCAN_BUDGET


def test_get_budget_invalid() -> None:
    with pytest.raises(ValueError, match="Unknown budget"):
        get_budget("unknown")


def test_fast_budget_flags() -> None:
    assert FAST_SCAN_BUDGET.auth_gate_enforced is True
    assert FAST_SCAN_BUDGET.discovery_gate_enforced is True
