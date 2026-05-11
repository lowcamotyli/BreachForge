from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from storage.evidence.state_store import StateSnapshot


FLOW_TYPES = frozenset({"create", "edit", "approve", "export", "delete", "checkout", "replay", "race"})


class FlowMutationPolicyError(ValueError):
    """Raised when a flow step fails closed during mutation policy validation."""


@dataclass(frozen=True)
class FlowStep:
    step_id: str
    action: str
    identity_context: str
    pre_snapshot: StateSnapshot | None
    post_snapshot: StateSnapshot | None
    timestamp: datetime
    observe_only: bool = False
    safe_fixture: bool = False


@dataclass(frozen=True)
class FlowTrace:
    flow_id: str
    scan_id: str
    flow_type: str
    steps: list[FlowStep]
    created_at: datetime

    def is_reproducible(self) -> bool:
        return all(step.pre_snapshot is not None and step.post_snapshot is not None for step in self.steps)

    def identity_contexts(self) -> list[str]:
        contexts: list[str] = []
        seen: set[str] = set()
        for step in self.steps:
            if step.identity_context in seen:
                continue
            seen.add(step.identity_context)
            contexts.append(step.identity_context)
        return contexts


class FlowMutationPolicy:
    MUTATING_ACTIONS = frozenset(
        {"write", "create", "update", "delete", "finalize", "replay", "approve", "pay", "submit", "activate"}
    )

    @classmethod
    def is_mutating(cls, action: str) -> bool:
        normalized = action.casefold()
        return any(keyword in normalized for keyword in cls.MUTATING_ACTIONS)

    @classmethod
    def check_step(cls, step: FlowStep) -> None:
        if not cls.is_mutating(step.action):
            return
        if step.observe_only or step.safe_fixture:
            return
        raise FlowMutationPolicyError(
            "mutating flow steps require observe_only=True or safe_fixture=True"
        )
