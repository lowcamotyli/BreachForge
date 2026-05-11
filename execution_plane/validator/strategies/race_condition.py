from __future__ import annotations

from execution_plane.validator.strategies.base import ValidationStrategy
from storage.db.models import ProofArtifact, RawProbe


class RaceConditionStrategy(ValidationStrategy):
    _MIN_PROOF_CONFIDENCE_THRESHOLD = 0.85

    def expected_attack_class(self) -> str:
        return "race_condition"

    def expected_proof_type(self) -> str:
        return "reproduction"

    def validate(self, attack_probe: RawProbe, control_probe: RawProbe | None) -> ProofArtifact | None:
        del control_probe

        request = attack_probe.request
        response = attack_probe.response

        reproduction_count = request.get("reproduction_count")
        reproduced = request.get("reproduced") is True
        has_reproduction_count = isinstance(reproduction_count, int) and reproduction_count >= 2
        has_reproduction_evidence = has_reproduction_count or reproduced

        has_race_winner = "race_winner" in response and response.get("race_winner") not in (None, "")
        concurrent_success = response.get("concurrent_success") is True
        has_race_signal = has_race_winner or concurrent_success

        if not has_reproduction_evidence and not has_race_signal:
            return None

        confidence = 0.88 if (has_reproduction_evidence or has_race_signal) else 0.0
        if has_race_winner:
            confidence = 0.91

        if confidence < self._MIN_PROOF_CONFIDENCE_THRESHOLD:
            return None

        evidence_parts: list[str] = []
        if has_reproduction_count:
            evidence_parts.append(f"reproduction_count={reproduction_count}")
        elif reproduced:
            evidence_parts.append("reproduced=true")

        if has_race_winner:
            evidence_parts.append(f"race_winner={response.get('race_winner')}")
        elif concurrent_success:
            evidence_parts.append("concurrent_success=true")

        return ProofArtifact(
            attack_task_id=attack_probe.attack_task_id,
            proof_type=self.expected_proof_type(),
            confidence_score=confidence,
            attack_probe_id=attack_probe.id,
            control_probe_id=None,
            summary="Race condition proof: concurrent execution produced observable state inconsistency",
            evidence_notes=", ".join(evidence_parts),
        )
