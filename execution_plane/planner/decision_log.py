from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from threading import Lock
from typing import Any


class TaskOutcome(str, Enum):
    success = "success"
    interesting = "interesting"
    needs_followup = "needs_followup"
    blocked = "blocked"
    no_signal = "no_signal"
    unsafe_blocked = "unsafe_blocked"


class FeedbackReason(str, Enum):
    no_signal = "no_signal"
    auth_drift = "auth_drift"
    interesting_diff = "interesting_diff"
    state_changed = "state_changed"
    needs_identity = "needs_identity"
    unsafe_blocked = "unsafe_blocked"


@dataclass
class FeedbackPayload:
    outcome: TaskOutcome
    scan_id: str
    task_id: str
    endpoint: str
    finding_class: str
    confidence: float
    reason: FeedbackReason | None = None
    follow_up_hints: list[str] = field(default_factory=list)
    parent_evidence_ref: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class DecisionLog:
    scan_id: str
    timestamp: datetime
    step_id: str
    chosen_action: str
    rationale: str
    alternatives: list[str] = field(default_factory=list)
    status: str | None = None
    reason: str | None = None


class DecisionLogger:
    def __init__(self) -> None:
        self._logs: dict[str, list[DecisionLog]] = {}
        self._lock = Lock()

    def log(self, decision: DecisionLog) -> None:
        if decision.timestamp.tzinfo is None:
            decision.timestamp = decision.timestamp.replace(tzinfo=timezone.utc)
        with self._lock:
            self._logs.setdefault(decision.scan_id, []).append(decision)

    def get_log(self, scan_id: str) -> list[DecisionLog]:
        with self._lock:
            return list(self._logs.get(scan_id, []))
