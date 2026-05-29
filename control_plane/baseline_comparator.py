from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class FindingStatus(str, Enum):
    NEW = "new"
    FIXED = "fixed"
    UNCHANGED = "unchanged"


@dataclass
class BaselineComparison:
    new: list[dict]
    fixed: list[dict]
    unchanged: list[dict]

    @property
    def summary(self) -> dict[str, int]:
        return {
            "new": len(self.new),
            "fixed": len(self.fixed),
            "unchanged": len(self.unchanged),
            "total": len(self.new) + len(self.fixed) + len(self.unchanged),
        }


def _fingerprint(finding: dict) -> str:
    return finding.get("fingerprint") or f"{finding.get('attack_class', '')}:{finding.get('target_url', '')}"


def compare(baseline: list[dict], current: list[dict]) -> BaselineComparison:
    baseline_fingerprints = {_fingerprint(finding): finding for finding in baseline}
    current_fingerprints = {_fingerprint(finding): finding for finding in current}
    new = [finding for fp, finding in current_fingerprints.items() if fp not in baseline_fingerprints]
    fixed = [finding for fp, finding in baseline_fingerprints.items() if fp not in current_fingerprints]
    unchanged = [finding for fp, finding in current_fingerprints.items() if fp in baseline_fingerprints]
    return BaselineComparison(new=new, fixed=fixed, unchanged=unchanged)
