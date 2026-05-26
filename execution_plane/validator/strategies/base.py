from __future__ import annotations

from abc import ABC, abstractmethod

from storage.db.models import ProofArtifact, RawProbe


class ValidationStrategy(ABC):
    @abstractmethod
    def validate(self, attack_probe: RawProbe, control_probe: RawProbe | None) -> ProofArtifact | None:
        """Validate probes and return a proof artifact when confidence meets policy."""

    @abstractmethod
    def expected_proof_type(self) -> str:
        """Return the proof type produced by this strategy."""

    @abstractmethod
    def expected_attack_class(self) -> str:
        """Return the attack_class key that should route to this strategy."""

    def requires_state_effect(self) -> bool:
        """Return True if a finding requires observable state change evidence."""
        return False
