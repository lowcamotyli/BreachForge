from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from threading import Lock


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
