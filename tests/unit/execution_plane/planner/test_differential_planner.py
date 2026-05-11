from __future__ import annotations

import pytest

from control_plane.auth_manager import IdentityMatrix, IdentityProfile
from execution_plane.planner.differential import build_differential_plans


def test_plan_specifies_baseline_and_challengers_correctly() -> None:
    matrix = _identity_matrix("owner", "attacker", "anon")

    plans = build_differential_plans(matrix=matrix, target_url="https://example.test/resource")

    assert len(plans) == 1
    plan = plans[0]
    assert plan.baseline_identity == "owner"
    assert plan.challenger_identities == ["attacker", "anon"]
    assert plan.target_url == "https://example.test/resource"
    assert plan.method == "GET"


def test_empty_matrix_with_less_than_two_identities_raises_value_error() -> None:
    matrix = _identity_matrix("owner")

    with pytest.raises(ValueError):
        build_differential_plans(matrix=matrix, target_url="https://example.test/resource")


def test_build_with_explicit_baseline_uses_it() -> None:
    matrix = _identity_matrix("owner", "attacker", "anon")

    plans = build_differential_plans(
        matrix=matrix,
        target_url="https://example.test/resource",
        method="POST",
        baseline="attacker",
        payload={"id": "123"},
    )

    assert len(plans) == 1
    plan = plans[0]
    assert plan.baseline_identity == "attacker"
    assert plan.challenger_identities == ["owner", "anon"]
    assert plan.method == "POST"
    assert plan.payload == {"id": "123"}


def _identity_matrix(*names: str) -> IdentityMatrix:
    return {
        name: IdentityProfile(
            name=name,
            role=None,
            tenant=None,
            auth_state="active",
            privilege_hint=None,
            session_ref=None,
        )
        for name in names
    }
