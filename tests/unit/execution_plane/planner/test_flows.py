from __future__ import annotations

from datetime import UTC, datetime

import pytest

from execution_plane.planner.flows import (
    FLOW_TYPES,
    FlowMutationPolicy,
    FlowMutationPolicyError,
    FlowStep,
    FlowTrace,
)
from storage.evidence.state_store import StateSnapshot


def _snapshot(step_id: str = "step") -> StateSnapshot:
    return StateSnapshot(
        scan_id="scan-1",
        step_id=step_id,
        timestamp=datetime.now(UTC),
        state_dict={"status": "ok"},
        version=1,
    )


def _step(
    *,
    step_id: str = "step-1",
    action: str = "observe_profile",
    identity_context: str = "current_user",
    pre_snapshot: StateSnapshot | None = None,
    post_snapshot: StateSnapshot | None = None,
    observe_only: bool = False,
    safe_fixture: bool = False,
) -> FlowStep:
    return FlowStep(
        step_id=step_id,
        action=action,
        identity_context=identity_context,
        pre_snapshot=pre_snapshot,
        post_snapshot=post_snapshot,
        timestamp=datetime.now(UTC),
        observe_only=observe_only,
        safe_fixture=safe_fixture,
    )


def _trace(steps: list[FlowStep]) -> FlowTrace:
    return FlowTrace(
        flow_id="flow-1",
        scan_id="scan-1",
        flow_type="checkout",
        steps=steps,
        created_at=datetime.now(UTC),
    )


def test_flow_trace_is_reproducible_true() -> None:
    trace = _trace(
        [
            _step(step_id="step-1", pre_snapshot=_snapshot("step-1-pre"), post_snapshot=_snapshot("step-1-post")),
            _step(step_id="step-2", pre_snapshot=_snapshot("step-2-pre"), post_snapshot=_snapshot("step-2-post")),
        ]
    )

    assert trace.is_reproducible() is True


def test_flow_trace_is_reproducible_false() -> None:
    trace = _trace(
        [
            _step(step_id="step-1", pre_snapshot=_snapshot("step-1-pre"), post_snapshot=_snapshot("step-1-post")),
            _step(step_id="step-2", pre_snapshot=_snapshot("step-2-pre"), post_snapshot=None),
        ]
    )

    assert trace.is_reproducible() is False


def test_flow_trace_identity_contexts() -> None:
    trace = _trace(
        [
            _step(step_id="step-1", identity_context="current_user"),
            _step(step_id="step-2", identity_context="alternate_user"),
            _step(step_id="step-3", identity_context="current_user"),
            _step(step_id="step-4", identity_context="anonymous_user"),
        ]
    )

    assert trace.identity_contexts() == ["current_user", "alternate_user", "anonymous_user"]


def test_mutation_policy_allows_observe_only() -> None:
    FlowMutationPolicy.check_step(_step(action="submit_order", observe_only=True))


def test_mutation_policy_allows_safe_fixture() -> None:
    FlowMutationPolicy.check_step(_step(action="delete_order", safe_fixture=True))


def test_mutation_policy_blocks_unguarded_mutation() -> None:
    with pytest.raises(FlowMutationPolicyError):
        FlowMutationPolicy.check_step(_step(action="approve_order"))


def test_mutation_policy_allows_non_mutating() -> None:
    FlowMutationPolicy.check_step(_step(action="observe_order", observe_only=False, safe_fixture=False))


def test_flow_types_contains_expected() -> None:
    assert {"create", "edit", "approve", "delete", "checkout", "replay", "race"} <= FLOW_TYPES
