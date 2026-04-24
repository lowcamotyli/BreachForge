from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any


@dataclass(frozen=True)
class StateSnapshot:
    scan_id: str
    step_id: str
    timestamp: datetime
    state_dict: dict[str, Any]
    version: int


class StateStore:
    def __init__(self) -> None:
        self._snapshots: dict[str, dict[str, dict[int, StateSnapshot]]] = {}

    def save_snapshot(self, snap: StateSnapshot) -> None:
        scan_snapshots = self._snapshots.setdefault(snap.scan_id, {})
        step_snapshots = scan_snapshots.setdefault(snap.step_id, {})
        step_snapshots[snap.version] = snap

    def get_snapshot(self, scan_id: str, step_id: str) -> StateSnapshot | None:
        scan_snapshots = self._snapshots.get(scan_id)
        if scan_snapshots is None:
            return None

        step_snapshots = scan_snapshots.get(step_id)
        if not step_snapshots:
            return None

        latest_version = max(step_snapshots)
        return step_snapshots[latest_version]

    def list_versions(self, scan_id: str) -> list[int]:
        scan_snapshots = self._snapshots.get(scan_id)
        if scan_snapshots is None:
            return []

        versions: set[int] = set()
        for step_snapshots in scan_snapshots.values():
            versions.update(step_snapshots.keys())

        return sorted(versions)
