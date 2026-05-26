from __future__ import annotations

from pathlib import Path
import sys

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[4]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from execution_plane.planner.playbook_loader import load_builtin_playbooks
from execution_plane.planner.playbooks import AttackPlaybook, PlaybookValidationError


def _minimal_step() -> dict[str, object]:
    return {
        "id": "step_a",
        "action": "read_boundary_probe",
        "identity_selector": "current_user",
        "probe_template": {"mode": "observe", "variables": {"path_hint": "user_id"}},
        "expected_signal": "boundary observed",
        "validator": "boundary_validator",
        "max_attempts": 1,
    }


def _minimal_playbook() -> dict[str, object]:
    return {
        "id": "sample",
        "attack_class": "bola",
        "preconditions": {"methods": ["GET"]},
        "steps": [_minimal_step()],
        "validators": {"boundary_validator": {"signal": "ok"}},
        "safety_budget": {
            "max_requests": 1,
            "max_attempts_per_step": 1,
            "rate_limit_rps": 1.0,
            "scope": "current_endpoint",
            "proof_gate": "default",
        },
    }


def test_builtin_playbooks_load_validate_and_serialize_deterministically() -> None:
    playbooks = load_builtin_playbooks()

    assert [playbook.id for playbook in playbooks] == [
        "account_enumeration_timing",
        "admin_endpoint_fuzz",
        "api_doc_exposure",
        "bfla_admin_function",
        "bfla_http_verb",
        "bola_idor",
        "cache_auth_drift",
        "cache_poisoning",
        "cookie_flags_audit",
        "cors_deep_analysis",
        "coupon_stacking",
        "csrf_state_change",
        "csrf_weak_token",
        "deprecated_version_probe",
        "deserialization_probe",
        "double_spend",
        "excessive_data_exposure",
        "forced_browsing",
        "graphql_batch_amplification",
        "graphql_introspection",
        "graphql_query_depth",
        "header_injection",
        "http_method_override",
        "http_request_smuggling",
        "idempotency_bypass",
        "inventory_reservation",
        "inventory_reservation_abuse",
        "jwt_alg_none",
        "jwt_claim_escalation",
        "jwt_kid_injection",
        "ldap_injection",
        "limit_override_race",
        "mass_assignment_probe",
        "negative_value_attack",
        "nosql_injection",
        "oauth_redirect_manipulation",
        "oauth_state_csrf",
        "oauth_token_reuse",
        "price_manipulation",
        "privilege_drift",
        "public_baseline_differential",
        "race_conditions",
        "replay_state_change",
        "secret_to_impact",
        "security_headers_audit",
        "sensitive_exposure_adaptive_followup",
        "ssrf_cloud_metadata",
        "ssrf_internal_discovery",
        "ssrf_protocol_abuse",
        "ssti",
        "step_skipping",
        "tls_analysis",
        "unauth_graphql_recon",
        "unauth_injection_public_forms",
        "unauth_misconfiguration_full",
        "unauth_rate_limit_public",
        "unauth_secret_replay",
        "unauth_sensitive_exposure",
        "web_cache_deception",
        "wordlist_forced_browsing",
        "workflow_abuse",
        "xxe_classic",
    ]
    assert [playbook.to_json() for playbook in playbooks] == [playbook.to_json() for playbook in playbooks]


def test_step_requires_validator_or_observe_only() -> None:
    raw = _minimal_playbook()
    step = dict(_minimal_step())
    step.pop("validator")
    raw["steps"] = [step]

    with pytest.raises(PlaybookValidationError, match="validator or observe_only"):
        AttackPlaybook.from_dict(raw)


def test_safety_budget_rejects_scope_expansion_and_high_rate() -> None:
    raw = _minimal_playbook()
    raw["safety_budget"] = {
        "max_requests": 1,
        "rate_limit_rps": 2.0,
        "scope": "cross_endpoint",
        "proof_gate": "default",
    }

    with pytest.raises(PlaybookValidationError):
        AttackPlaybook.from_dict(raw)


def test_safety_budget_limits_total_step_attempts() -> None:
    raw = _minimal_playbook()
    step = dict(_minimal_step())
    step["max_attempts"] = 2
    raw["steps"] = [step]

    with pytest.raises(PlaybookValidationError, match="exceed safety_budget.max_requests"):
        AttackPlaybook.from_dict(raw)


def test_secret_bearing_values_are_rejected_in_probe_template() -> None:
    raw = _minimal_playbook()
    step = dict(_minimal_step())
    step["probe_template"] = {"variables": {"auth_header": "Bearer token"}}
    raw["steps"] = [step]

    with pytest.raises(PlaybookValidationError, match="secret-bearing"):
        AttackPlaybook.from_dict(raw)


def test_category_names_are_allowed_without_raw_secret_material() -> None:
    raw = _minimal_playbook()
    raw["id"] = "secret_to_impact"
    raw["attack_class"] = "sensitive_exposure"
    raw["validators"] = {"exposure_classification_validator": {"signal": "credential_class_fingerprint_only"}}
    step = dict(_minimal_step())
    step["expected_signal"] = "credential-like class metadata without storing raw value"
    raw["steps"] = [step]

    playbook = AttackPlaybook.from_dict(raw)

    assert playbook.id == "secret_to_impact"


def test_mutation_step_requires_observe_only_or_safe_fixture() -> None:
    raw = _minimal_playbook()
    step = dict(_minimal_step())
    step["action"] = "approve_payment"
    step["observe_only"] = False
    raw["steps"] = [step]

    with pytest.raises(PlaybookValidationError, match="mutating"):
        AttackPlaybook.from_dict(raw)
