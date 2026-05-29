from __future__ import annotations

from dataclasses import dataclass, field
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


@dataclass(frozen=True)
class VerificationResult:
    is_proof: bool
    is_destructive: bool
    proof_fields: frozenset[str]
    side_effect_fields: frozenset[str]
    summary: str


class ReadAfterWriteVerifier:
    """Verifies state change is a proof of attack effect, not a destructive side mutation."""

    def verify(
        self,
        before: StateSnapshot,
        after: StateSnapshot,
        expected_mutations: set[str],
    ) -> VerificationResult:
        diff = compute_diff(before, after)
        all_changed = set(diff.changed) | set(diff.added) | set(diff.removed)
        proof_fields = frozenset(all_changed & expected_mutations)
        side_effect_fields = frozenset(
            f for f in (all_changed - expected_mutations)
            if f.lower().replace("-", "_") not in VOLATILE_KEYS
        )
        is_proof = bool(proof_fields)
        is_destructive = bool(side_effect_fields)
        summary = f"proof={sorted(proof_fields)}, side_effects={sorted(side_effect_fields)}"
        return VerificationResult(
            is_proof=is_proof,
            is_destructive=is_destructive,
            proof_fields=proof_fields,
            side_effect_fields=side_effect_fields,
            summary=summary,
        )


@dataclass
class RollbackProtocol:
    """Cleanup protocol for a probe that made a state change."""

    pre_state_snapshot: dict[str, Any] = field(default_factory=dict)
    cleanup_requests: list[dict[str, Any]] = field(default_factory=list)
    is_synthetic_account: bool = False


@dataclass
class RollbackableProbe:
    """Wraps a probe with optional rollback metadata."""

    probe_id: str
    rollback: RollbackProtocol | None = None
    synthetic_identity_id: str | None = None


def is_rollback_safe(state_before: dict[str, Any], state_after: dict[str, Any]) -> bool:
    """Returns True if state change appears reversible (no permanent net-new records, no auth changes)."""
    if set(state_after.keys()) < set(state_before.keys()):
        return False
    auth_keys = {"session", "token", "password", "role", "permissions"}
    for key in auth_keys:
        if state_before.get(key) != state_after.get(key):
            return False
    return True


def mark_synthetic_identity(
    identity_id: str,
    scan_id: str,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Returns a metadata dict tagging an identity as synthetic for cleanup tracking."""
    return {
        "identity_id": identity_id,
        "scan_id": scan_id,
        "synthetic": True,
        **(metadata or {}),
    }
