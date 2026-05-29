from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, ClassVar, TypeAlias
from uuid import UUID

from storage.db.models import AssetMap as DbAssetMap
from storage.db.models import AttackTask, Endpoint, Finding

AssetMap: TypeAlias = DbAssetMap


@dataclass(slots=True)
class ScanContext:
    scan_id: UUID
    target_url: str
    asset_map: AssetMap
    # Populated during replanning: findings confirmed so far in this scan.
    # Rules may inspect prior_findings to skip redundant probes or escalate coverage.
    prior_findings: list[Finding] = field(default_factory=list)
    # Populated during replanning: IDs of tasks already executed (dedup guard).
    completed_task_ids: set[UUID] = field(default_factory=set)
    # Populated during replanning: guard against unbounded replan loops.
    replan_budget: ReplanBudget | None = None


class AttackRule(ABC):
    attack_class: ClassVar[str]
    name: ClassVar[str]
    requires_auth: bool = False

    @abstractmethod
    def matches(self, endpoint: Endpoint, asset_map: AssetMap) -> bool:
        """Return True when this rule applies to the endpoint."""

    @abstractmethod
    def generate_tasks(self, endpoint: Endpoint, context: ScanContext) -> list[AttackTask]:
        """Build attack tasks for an endpoint in the current scan context."""

    @abstractmethod
    def expected_proof_signal(self) -> str:
        """Describe the proof signal validators should look for."""
