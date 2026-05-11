from __future__ import annotations

from pathlib import Path
import sys
from uuid import uuid4

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


def _extend_execution_plane_package_paths() -> None:
    execution_plane_path = PROJECT_ROOT / "execution_plane"
    planner_path = execution_plane_path / "planner"
    validator_path = execution_plane_path / "validator"

    execution_plane_package = sys.modules.get("execution_plane")
    if execution_plane_package is not None and hasattr(execution_plane_package, "__path__"):
        execution_plane_locations = list(execution_plane_package.__path__)
        if str(execution_plane_path) not in execution_plane_locations:
            execution_plane_package.__path__.append(str(execution_plane_path))

    planner_package = sys.modules.get("execution_plane.planner")
    if planner_package is not None and hasattr(planner_package, "__path__"):
        planner_locations = list(planner_package.__path__)
        if str(planner_path) not in planner_locations:
            planner_package.__path__.append(str(planner_path))

    validator_package = sys.modules.get("execution_plane.validator")
    if validator_package is not None and hasattr(validator_package, "__path__"):
        validator_locations = list(validator_package.__path__)
        if str(validator_path) not in validator_locations:
            validator_package.__path__.append(str(validator_path))


_extend_execution_plane_package_paths()

from execution_plane.planner.rules.auth_bypass import AuthBypass
from execution_plane.planner.rules.base import AttackRule, ScanContext
from execution_plane.planner.rules.bfla import BflaRule
from execution_plane.planner.rules.bola import BolaBidirectional
from execution_plane.planner.rules.injection import InjectionSql
from execution_plane.planner.rules.misconfiguration import MisconfigurationRule
from execution_plane.planner.rules.privilege_escalation import PrivilegeEscalation
from execution_plane.planner.rules.rate_limit_abuse import RateLimitAbuseRule
from execution_plane.planner.rules.sensitive_exposure import SensitiveExposure
from execution_plane.planner.rules.session_misuse import SessionMisuseRule
from execution_plane.planner.rules.tenant_isolation import TenantIsolation
from execution_plane.planner.rules.workflow_abuse import WorkflowAbuse
from execution_plane.validator.strategies.auth_bypass import AuthBypassStrategy
from execution_plane.validator.strategies.bfla import BflaStrategy
from execution_plane.validator.strategies.bola import BolaStrategy
from execution_plane.validator.strategies.injection import InjectionStrategy
from execution_plane.validator.strategies.misconfiguration import MisconfigurationStrategy
from execution_plane.validator.strategies.privilege_escalation import PrivilegeEscalationStrategy
from execution_plane.validator.strategies.rate_limit_abuse import RateLimitAbuseStrategy
from execution_plane.validator.strategies.sensitive_exposure import SensitiveExposureStrategy
from execution_plane.validator.strategies.session_misuse import SessionMisuseStrategy
from execution_plane.validator.strategies.tenant_isolation import TenantIsolationStrategy
from execution_plane.validator.strategies.workflow_abuse import WorkflowAbuseStrategy
from storage.db.models import AssetMap, Endpoint


def _build_endpoint(
    *,
    method: str,
    auth_required: bool,
    url_pattern: str,
    parameters: list[dict[str, object]],
    observed_content_type: str | None = "application/json",
    example_response_code: int = 200,
) -> Endpoint:
    return Endpoint(
        id=uuid4(),
        asset_map_id=uuid4(),
        url_pattern=url_pattern,
        method=method,
        auth_required=auth_required,
        parameters=parameters,
        observed_content_type=observed_content_type,
        example_response_code=example_response_code,
    )


def _build_context(endpoints: list[Endpoint]) -> ScanContext:
    asset_map = AssetMap(scan_id=uuid4())
    asset_map.endpoints = endpoints
    return ScanContext(scan_id=uuid4(), target_url="https://app.example.com", asset_map=asset_map)


def _rule_case(rule: AttackRule) -> tuple[Endpoint, list[Endpoint]]:
    if isinstance(rule, BflaRule):
        endpoint = _build_endpoint(
            method="GET",
            auth_required=True,
            url_pattern="/api/admin/users",
            parameters=[],
        )
        return endpoint, [endpoint]

    if isinstance(rule, BolaBidirectional):
        endpoint = _build_endpoint(
            method="GET",
            auth_required=True,
            url_pattern="/api/users/{user_id}",
            parameters=[{"name": "user_id", "in": "path"}],
        )
        return endpoint, [endpoint]

    if isinstance(rule, TenantIsolation):
        endpoint = _build_endpoint(
            method="GET",
            auth_required=False,
            url_pattern="/api/tenants/{tenant_id}/users",
            parameters=[{"name": "tenant_id", "in": "path"}],
        )
        return endpoint, [endpoint]

    if isinstance(rule, AuthBypass):
        endpoint = _build_endpoint(
            method="GET",
            auth_required=True,
            url_pattern="/api/me",
            parameters=[],
        )
        return endpoint, [endpoint]

    if isinstance(rule, PrivilegeEscalation):
        endpoint = _build_endpoint(
            method="PATCH",
            auth_required=True,
            url_pattern="/api/users/{user_id}",
            parameters=[{"name": "role", "in": "body", "type": "string"}],
        )
        return endpoint, [endpoint]

    if isinstance(rule, SensitiveExposure):
        endpoint = _build_endpoint(
            method="GET",
            auth_required=True,
            url_pattern="/api/profile",
            parameters=[],
            observed_content_type="application/json",
        )
        return endpoint, [endpoint]

    if isinstance(rule, WorkflowAbuse):
        prereq = _build_endpoint(
            method="POST",
            auth_required=True,
            url_pattern="/orders/checkout/start",
            parameters=[{"name": "cart_id", "in": "body", "type": "string"}],
        )
        endpoint = _build_endpoint(
            method="POST",
            auth_required=True,
            url_pattern="/orders/checkout/confirm",
            parameters=[{"name": "order_id", "in": "body", "type": "string"}],
        )
        return endpoint, [prereq, endpoint]

    if isinstance(rule, InjectionSql):
        endpoint = _build_endpoint(
            method="POST",
            auth_required=True,
            url_pattern="/api/search",
            parameters=[{"name": "q", "in": "query", "type": "string"}],
        )
        return endpoint, [endpoint]

    if isinstance(rule, SessionMisuseRule):
        endpoint = _build_endpoint(
            method="GET",
            auth_required=True,
            url_pattern="/api/users/{user_id}",
            parameters=[{"name": "Authorization", "in": "header"}, {"name": "user_id", "in": "path"}],
        )
        return endpoint, [endpoint]

    if isinstance(rule, RateLimitAbuseRule):
        endpoint = _build_endpoint(
            method="POST",
            auth_required=False,
            url_pattern="/api/login",
            parameters=[],
        )
        return endpoint, [endpoint]

    if isinstance(rule, MisconfigurationRule):
        endpoint = _build_endpoint(
            method="GET",
            auth_required=False,
            url_pattern="/api/catalog",
            parameters=[],
        )
        return endpoint, [endpoint]

    raise AssertionError(f"Unhandled rule type: {type(rule).__name__}")


def test_all_attack_classes_have_rules() -> None:
    rules: list[AttackRule] = [
        BflaRule(),
        BolaBidirectional(),
        TenantIsolation(),
        AuthBypass(),
        PrivilegeEscalation(),
        SensitiveExposure(),
        WorkflowAbuse(),
        InjectionSql(),
        SessionMisuseRule(),
        RateLimitAbuseRule(),
        MisconfigurationRule(),
    ]

    for rule in rules:
        endpoint, endpoints = _rule_case(rule)
        context = _build_context(endpoints)

        assert isinstance(rule.attack_class, str)
        assert rule.attack_class
        assert rule.matches(endpoint, context.asset_map) is True

        tasks = rule.generate_tasks(endpoint, context)

        assert tasks
        assert all(task.attack_class == rule.attack_class for task in tasks)


def test_all_attack_classes_have_strategies() -> None:
    strategy_cases = [
        (BflaStrategy(), "bfla"),
        (BolaStrategy(), "bola"),
        (TenantIsolationStrategy(), "tenant_isolation"),
        (AuthBypassStrategy(), "auth_bypass"),
        (PrivilegeEscalationStrategy(), "privilege_escalation"),
        (SensitiveExposureStrategy(), "sensitive_exposure"),
        (WorkflowAbuseStrategy(), "workflow_abuse"),
        (InjectionStrategy(), "injection"),
        (SessionMisuseStrategy(), "session_misuse"),
        (RateLimitAbuseStrategy(), "rate_limit_abuse"),
        (MisconfigurationStrategy(), "misconfiguration"),
    ]

    for strategy, expected_attack_class in strategy_cases:
        assert strategy.expected_attack_class() == expected_attack_class
