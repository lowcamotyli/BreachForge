from __future__ import annotations

import sys
from pathlib import Path
from uuid import uuid4

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
_shadowed_pkg = sys.modules.get("execution_plane")
if _shadowed_pkg is not None and str(getattr(_shadowed_pkg, "__file__", "")).endswith(
    "tests/unit/execution_plane/__init__.py"
):
    del sys.modules["execution_plane"]

from execution_plane.planner.planner import AttackPlanner, ScanBudget
from execution_plane.workers.dispatcher import ScanBudgetExceeded, _enforce_dispatch_budget
from storage.db.models import AttackTask, AttackTaskStatus


def _task(attack_class: str) -> AttackTask:
    return AttackTask(
        id=uuid4(),
        scan_id=uuid4(),
        endpoint_id=uuid4(),
        attack_class=attack_class,
        target_parameter="id",
        hypothesis="{}",
        priority_score=1.0,
        status=AttackTaskStatus.pending,
    )


class _RedisCounter:
    def __init__(self) -> None:
        self.values: dict[str, int] = {}

    def incr(self, key: str) -> int:
        value = self.values.get(key, 0) + 1
        self.values[key] = value
        return value

    def expire(self, key: str, ttl: int) -> None:
        del ttl
        return None


def test_scan_budget_enforcement_skips_low_priority_after_max_requests() -> None:
    planner = AttackPlanner()
    budget = ScanBudget(
        max_requests=1,
        max_runtime_seconds=60,
        per_class_cap={},
        priority_classes=["bola"],
    )
    tasks = [_task("tenant_isolation"), _task("bola"), _task("mass_assignment")]

    selected = planner._apply_scan_budget(tasks, scan_budget=budget)

    assert [task.attack_class for task in selected] == ["tenant_isolation", "bola"]
    assert budget.requests_dispatched == 2
    assert budget.remaining_requests == 0


def test_dispatch_budget_enforces_max_requests_and_priority_bypass() -> None:
    redis_conn = _RedisCounter()
    scan_id = str(uuid4())
    budget = {
        "max_requests": 1,
        "max_runtime_seconds": 120,
        "per_class_cap": {},
        "priority_classes": ["bola"],
    }

    _enforce_dispatch_budget(
        connection=redis_conn,
        scan_id=scan_id,
        attack_class="tenant_isolation",
        scan_budget=budget,
    )

    try:
        _enforce_dispatch_budget(
            connection=redis_conn,
            scan_id=scan_id,
            attack_class="mass_assignment",
            scan_budget=budget,
        )
        assert False, "expected ScanBudgetExceeded"
    except ScanBudgetExceeded:
        pass

    _enforce_dispatch_budget(
        connection=redis_conn,
        scan_id=scan_id,
        attack_class="bola",
        scan_budget=budget,
    )


def test_dispatch_budget_enforces_per_class_cap() -> None:
    redis_conn = _RedisCounter()
    scan_id = str(uuid4())
    budget = {
        "max_requests": 10,
        "max_runtime_seconds": 120,
        "per_class_cap": {"tenant_isolation": 1},
        "priority_classes": [],
    }

    _enforce_dispatch_budget(
        connection=redis_conn,
        scan_id=scan_id,
        attack_class="tenant_isolation",
        scan_budget=budget,
    )

    try:
        _enforce_dispatch_budget(
            connection=redis_conn,
            scan_id=scan_id,
            attack_class="tenant_isolation",
            scan_budget=budget,
        )
        assert False, "expected ScanBudgetExceeded"
    except ScanBudgetExceeded:
        pass
