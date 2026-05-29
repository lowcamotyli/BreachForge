from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class ScanBudget:
    name: str
    max_attack_classes: int
    high_signal_only: bool
    auth_gate_enforced: bool
    discovery_gate_enforced: bool
    allowed_classes: tuple[str, ...] = field(default_factory=tuple)


FAST_SCAN_BUDGET = ScanBudget(
    name="fast",
    max_attack_classes=8,
    high_signal_only=True,
    auth_gate_enforced=True,
    discovery_gate_enforced=True,
    allowed_classes=(
        "bola",
        "auth_bypass",
        "tenant_isolation",
        "jwt_attack",
        "privilege_escalation",
        "idor",
        "ssrf",
        "sensitive_exposure",
    ),
)

FULL_SCAN_BUDGET = ScanBudget(
    name="full",
    max_attack_classes=999,
    high_signal_only=False,
    auth_gate_enforced=True,
    discovery_gate_enforced=False,
    allowed_classes=(),
)


def get_budget(name: str) -> ScanBudget:
    budgets = {"fast": FAST_SCAN_BUDGET, "full": FULL_SCAN_BUDGET}
    if name not in budgets:
        raise ValueError(f"Unknown budget: {name!r}. Valid: {list(budgets)}")
    return budgets[name]


def filter_attack_classes(budget: ScanBudget, available: list[str]) -> list[str]:
    if not budget.allowed_classes:
        return list(available)
    allowed = set(budget.allowed_classes)
    return [attack_class for attack_class in available if attack_class in allowed]
