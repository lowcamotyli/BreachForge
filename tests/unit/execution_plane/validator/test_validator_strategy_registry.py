from __future__ import annotations

import pytest

from execution_plane.validator.strategies.bola import BolaStrategy

pytest.importorskip("redis")
pytest.importorskip("rq")

from execution_plane.validator.validator import ExploitValidator


def test_validator_default_registry_includes_planner_supported_attack_classes() -> None:
    validator = ExploitValidator()

    registered_attack_classes = set(validator._strategies.keys())

    assert {
        "bfla",
        "bola",
        "tenant_isolation",
        "auth_bypass",
        "privilege_escalation",
        "sensitive_exposure",
        "workflow_abuse",
        "mass_assignment",
        "excessive_exposure",
        "graphql_introspection",
        "graphql_batch",
        "graphql_field_suggestion",
        "graphql_depth",
        "oauth_redirect",
        "oauth_state_csrf",
        "oauth_token_reuse",
        "oauth_error_disclosure",
    } <= registered_attack_classes
    for attack_class, strategy in validator._strategies.items():
        assert strategy.expected_attack_class() == attack_class


def test_validator_raises_on_registry_strategy_mismatch() -> None:
    with pytest.raises(ValueError, match="Validator strategy registry mismatch"):
        ExploitValidator(strategies={"tenant_isolation": BolaStrategy()})
