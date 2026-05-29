from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml


@dataclass(slots=True)
class GateRunner:
    max_new_critical: int = 0
    max_new_high: int = 5
    no_auth_failure: bool = True

    @classmethod
    def load(cls, path: str) -> GateRunner:
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        return cls(
            max_new_critical=int(data.get("max_new_critical", 0)),
            max_new_high=int(data.get("max_new_high", 5)),
            no_auth_failure=bool(data.get("no_auth_failure", True)),
        )

    def evaluate(self, summary: dict[str, int]) -> tuple[bool, str]:
        new_critical = int(summary.get("new_critical", 0))
        new_high = int(summary.get("new_high", 0))
        auth_failures = int(summary.get("auth_failures", 0))

        if new_critical > self.max_new_critical:
            return (
                False,
                f"new_critical {new_critical} exceeds max_new_critical {self.max_new_critical}",
            )
        if new_high > self.max_new_high:
            return False, f"new_high {new_high} exceeds max_new_high {self.max_new_high}"
        if self.no_auth_failure and auth_failures > 0:
            return False, "auth_failures present while no_auth_failure is enabled"
        return True, "gate passed"
