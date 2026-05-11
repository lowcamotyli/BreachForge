from __future__ import annotations

import json
from abc import ABC, abstractmethod
from uuid import UUID

from storage.db.models import AttackTask


class RaceTemplate(ABC):
    name: str
    description: str
    requires_auth = False

    def __init__(self, scan_id: UUID, endpoint_id: UUID) -> None:
        self._scan_id = scan_id
        self._endpoint_id = endpoint_id

    @abstractmethod
    def build_task_pair(self) -> tuple[AttackTask, AttackTask]:
        """Build two concurrent attack tasks for race-condition probing."""

    def _task(self, hypothesis_payload: dict[str, object], target_parameter: str = "race_window") -> AttackTask:
        return AttackTask(
            scan_id=self._scan_id,
            endpoint_id=self._endpoint_id,
            attack_class="race_condition",
            target_parameter=target_parameter,
            hypothesis=json.dumps(hypothesis_payload, sort_keys=True),
        )


class DoubleSpendTemplate(RaceTemplate):
    name = "double_spend"
    description = "Submit two logically equivalent spend operations in one race window."

    def build_task_pair(self) -> tuple[AttackTask, AttackTask]:
        baseline_payload = {
            "probe_type": "race_double_spend",
            "template": self.name,
            "attempt": 1,
        }
        contender_payload = {
            "probe_type": "race_double_spend",
            "template": self.name,
            "attempt": 2,
        }
        return (
            self._task(baseline_payload, target_parameter="transaction"),
            self._task(contender_payload, target_parameter="transaction"),
        )


class TOCTOUTemplate(RaceTemplate):
    name = "toctou"
    description = "Race a time-of-check step against a time-of-use step using the same resource hint."

    def build_task_pair(self) -> tuple[AttackTask, AttackTask]:
        check_payload = {
            "probe_type": "race_toctou",
            "template": self.name,
            "phase": "check",
        }
        use_payload = {
            "probe_type": "race_toctou",
            "template": self.name,
            "phase": "use",
        }
        return (
            self._task(check_payload, target_parameter="resource_state"),
            self._task(use_payload, target_parameter="resource_state"),
        )


class IdempotencyBypassTemplate(RaceTemplate):
    name = "idempotency_bypass"
    description = "Send two near-simultaneous requests to probe idempotency key enforcement."

    def build_task_pair(self) -> tuple[AttackTask, AttackTask]:
        first_payload = {
            "probe_type": "race_idempotency_bypass",
            "template": self.name,
            "idempotency_variant": "primary",
        }
        second_payload = {
            "probe_type": "race_idempotency_bypass",
            "template": self.name,
            "idempotency_variant": "contender",
        }
        return (
            self._task(first_payload, target_parameter="idempotency_key"),
            self._task(second_payload, target_parameter="idempotency_key"),
        )
