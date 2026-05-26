from __future__ import annotations

from copy import deepcopy
from datetime import UTC, datetime
from typing import Any

from execution_plane.validator.state_diff import StateDiff, compute_diff
from storage.evidence.state_store import StateSnapshot, StateStore


def _snapshot(
    state_dict: dict[str, Any],
    *,
    scan_id: str = "scan-1",
    step_id: str = "step-1",
    version: int = 1,
) -> StateSnapshot:
    return StateSnapshot(
        scan_id=scan_id,
        step_id=step_id,
        timestamp=datetime.now(UTC),
        state_dict=state_dict,
        version=version,
    )


def test_compute_diff_ignores_volatile_fields_without_mutating_inputs() -> None:
    before_state = {
        "id": "order-1",
        "updated_at": "2026-01-01T00:00:00Z",
        "headers": {"timestamp": "before", "X-Request-ID": "req-before"},
    }
    after_state = {
        "id": "order-1",
        "updated_at": "2026-01-02T00:00:00Z",
        "headers": {"timestamp": "after", "X-Request-ID": "req-after"},
    }
    original_before = deepcopy(before_state)
    original_after = deepcopy(after_state)

    diff = compute_diff(
        before=_snapshot(before_state),
        after=_snapshot(after_state, version=2),
    )

    assert diff.changed == {}
    assert before_state == original_before
    assert after_state == original_after


def test_compute_diff_detects_real_changed_fields() -> None:
    diff = compute_diff(
        before=_snapshot({"status": "pending", "amount": 100}),
        after=_snapshot({"status": "paid", "amount": 150}, version=2),
    )

    assert diff.changed == {"amount": (100, 150), "status": ("pending", "paid")}


def test_compute_diff_detects_added_and_removed_keys() -> None:
    diff = compute_diff(
        before=_snapshot({"status": "pending", "old_key": "removed"}),
        after=_snapshot({"status": "pending", "new_key": "added"}, version=2),
    )

    assert diff.added == {"new_key": "added"}
    assert diff.removed == {"old_key": "removed"}
    assert diff.changed == {}


def test_state_diff_is_empty_true_when_no_changes() -> None:
    diff = StateDiff(added={}, removed={}, changed={})

    assert diff.is_empty() is True


def test_state_diff_is_empty_false_when_has_changes() -> None:
    diff = StateDiff(added={}, removed={}, changed={"status": ("pending", "paid")})

    assert diff.is_empty() is False


def test_state_store_get_before_after_returns_pre_and_post_snapshots() -> None:
    store = StateStore()
    pre_snap = _snapshot({"status": "pending"}, version=1)
    post_snap = _snapshot({"status": "paid"}, version=2)
    store.save_snapshot(pre_snap)
    store.save_snapshot(post_snap)

    before, after = store.get_before_after(scan_id="scan-1", step_id="step-1")

    assert before == pre_snap
    assert after == post_snap


def test_state_store_get_before_after_returns_same_snapshot_for_single_version() -> None:
    store = StateStore()
    snap = _snapshot({"status": "pending"}, version=1)
    store.save_snapshot(snap)

    before, after = store.get_before_after(scan_id="scan-1", step_id="step-1")

    assert before == snap
    assert after == snap
