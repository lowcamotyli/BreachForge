from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from execution_plane.validator.state_diff import compute_diff
from execution_plane.validator.strategies.base import ValidationStrategy
from storage.db.models import ProofArtifact, RawProbe
from storage.evidence.state_store import StateSnapshot


class StateDeltaStrategy(ValidationStrategy):
    _MIN_PROOF_CONFIDENCE_THRESHOLD = 0.85

    def expected_attack_class(self) -> str:
        return "workflow_abuse"

    def expected_proof_type(self) -> str:
        return "state_delta"

    def validate(self, attack_probe: RawProbe, control_probe: RawProbe | None) -> ProofArtifact | None:
        del control_probe

        pre_state = self._extract_state(
            attack_probe.request,
            ("pre_state", "state_before", "before_state", "before"),
        )
        post_state = self._extract_state(
            attack_probe.response,
            ("post_state", "state_after", "after_state", "final_state", "after"),
        )

        if pre_state is None or post_state is None:
            return None

        now = datetime.now(timezone.utc)
        before_snapshot = StateSnapshot(
            scan_id="probe",
            step_id="step",
            timestamp=now,
            state_dict=pre_state,
            version=1,
        )
        after_snapshot = StateSnapshot(
            scan_id="probe",
            step_id="step",
            timestamp=now,
            state_dict=post_state,
            version=1,
        )
        diff = compute_diff(before_snapshot, after_snapshot)

        if not diff.added and not diff.removed and not diff.changed:
            return None

        confidence = 0.93 if diff.added or diff.removed else 0.90
        if confidence < self._MIN_PROOF_CONFIDENCE_THRESHOLD:
            return None

        return ProofArtifact(
            attack_task_id=attack_probe.attack_task_id,
            proof_type=self.expected_proof_type(),
            confidence_score=confidence,
            attack_probe_id=attack_probe.id,
            control_probe_id=None,
            summary="State delta proof: pre/post state diverged after behavioral step",
            evidence_notes=(
                f"added={len(diff.added)}, removed={len(diff.removed)}, changed={len(diff.changed)}"
            ),
        )

    def _extract_state(self, source: dict[str, Any], keys: tuple[str, ...]) -> dict[str, Any] | None:
        for key in keys:
            value = source.get(key)
            if isinstance(value, dict):
                return value
        return None
