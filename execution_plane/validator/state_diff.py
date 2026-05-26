from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from storage.evidence.state_store import StateSnapshot


VOLATILE_KEYS = frozenset(
    {
        "timestamp",
        "request_id",
        "trace_id",
        "x_request_id",
        "date",
        "last_modified",
        "updated_at",
        "created_at",
        "server_time",
        "response_time",
        "nonce",
        "etag",
    }
)


@dataclass(frozen=True)
class StateDiff:
    added: dict[str, Any]
    removed: dict[str, Any]
    changed: dict[str, tuple[Any, Any]]

    def is_empty(self) -> bool:
        return not self.added and not self.removed and not self.changed


def normalize_for_diff(state: dict[str, Any]) -> dict[str, Any]:
    return {
        key: _normalize_value(value)
        for key, value in state.items()
        if key.lower().replace("-", "_") not in VOLATILE_KEYS
    }


def _normalize_value(value: Any) -> Any:
    if isinstance(value, dict):
        return normalize_for_diff(value)

    if isinstance(value, list):
        return [_normalize_value(item) for item in value]

    return value


def compute_diff(before: StateSnapshot, after: StateSnapshot) -> StateDiff:
    before_state = normalize_for_diff(before.state_dict)
    after_state = normalize_for_diff(after.state_dict)

    before_keys = set(before_state)
    after_keys = set(after_state)

    added_keys = after_keys - before_keys
    removed_keys = before_keys - after_keys
    common_keys = before_keys & after_keys

    added = {key: after_state[key] for key in added_keys}
    removed = {key: before_state[key] for key in removed_keys}
    changed = {
        key: (before_state[key], after_state[key])
        for key in common_keys
        if before_state[key] != after_state[key]
    }

    return StateDiff(added=added, removed=removed, changed=changed)
