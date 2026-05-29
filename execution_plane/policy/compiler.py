from __future__ import annotations

from dataclasses import dataclass, field

from api.models.requests import ScanPolicyV2
from execution_plane.policy.action_classifier import ActionClass


@dataclass
class PlannerCaps:
    allowed_action_classes: list[str] = field(default_factory=list)  # ActionClass.value strings
    max_tasks: int = 500
    allowed_domains: list[str] = field(default_factory=list)
    denied_patterns: list[str] = field(default_factory=list)


@dataclass
class WorkerCaps:
    allowed_methods: list[str] = field(default_factory=list)  # ["GET", "HEAD", "OPTIONS"]
    max_requests_per_domain: int = 100
    destructive_allowed: bool = False
    credential_allowed: bool = False


@dataclass
class ProviderCaps:
    destructive_budget: int = 0
    rollback_required: bool = True
    time_windows: list[dict] = field(default_factory=list)  # [{start_hour, end_hour, weekdays}]


@dataclass
class RateLimiterCaps:
    requests_per_second: float = 5.0
    requests_per_domain_per_minute: int = 60
    max_concurrent: int = 3


class PolicyCompiler:
    def compile(self, policy: ScanPolicyV2) -> tuple[PlannerCaps, WorkerCaps, ProviderCaps, RateLimiterCaps]:
        mc = policy.method_classes
        scope = policy.scope
        budget = policy.destructive_budget

        # Build allowed action classes
        allowed_actions = []
        if mc.allow_read:
            allowed_actions.append(ActionClass.READ.value)
        if mc.allow_write_safe:
            allowed_actions.append(ActionClass.WRITE_SAFE.value)
        if mc.allow_write_reversible:
            allowed_actions.append(ActionClass.WRITE_REVERSIBLE.value)
        if mc.allow_destructive:
            allowed_actions.append(ActionClass.DESTRUCTIVE.value)
        if mc.allow_credential_sensitive:
            allowed_actions.append(ActionClass.CREDENTIAL_SENSITIVE.value)

        # Build allowed HTTP methods from action classes
        allowed_methods = ["GET", "HEAD", "OPTIONS"]  # always read
        if mc.allow_write_safe:
            allowed_methods.extend(["POST"])
        if mc.allow_write_reversible:
            allowed_methods.extend(["PUT", "PATCH"])
        if mc.allow_destructive:
            allowed_methods.extend(["DELETE"])

        planner = PlannerCaps(
            allowed_action_classes=allowed_actions,
            allowed_domains=list(scope.allowed_domains),
            denied_patterns=list(scope.denied_path_patterns),
        )
        worker = WorkerCaps(
            allowed_methods=allowed_methods,
            destructive_allowed=mc.allow_destructive,
            credential_allowed=mc.allow_credential_sensitive,
        )
        provider = ProviderCaps(
            destructive_budget=budget.max_destructive_probes,
            rollback_required=mc.allow_destructive,
            time_windows=[
                {
                    "start_hour": tw.start_hour,
                    "end_hour": tw.end_hour,
                    "weekdays": tw.weekdays,
                }
                for tw in policy.time_windows
            ],
        )
        rate = RateLimiterCaps()  # defaults
        return planner, worker, provider, rate

    @staticmethod
    def conservative_defaults() -> ScanPolicyV2:
        return ScanPolicyV2()  # all defaults = conservative
