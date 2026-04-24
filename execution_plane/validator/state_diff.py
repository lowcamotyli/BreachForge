from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from storage.evidence.state_store import StateSnapshot


@dataclass(frozen=True)
class StateDiff:
    added: dict[str, Any]
    removed: dict[str, Any]
    changed: dict[str, tuple[Any, Any]]


def compute_diff(before: StateSnapshot, after: StateSnapshot) -> StateDiff:
    before_state = before.state_dict
    after_state = after.state_dict

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
