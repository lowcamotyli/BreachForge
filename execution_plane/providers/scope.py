from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class BenchmarkScope:
    lab_url: str
    auth_material: dict[str, str] = field(default_factory=dict)
    openapi_path: Path | None = None
    har_path: Path | None = None
    policy: dict[str, Any] = field(default_factory=dict)
    time_budget_seconds: int = 120
    seed: int | None = None
    run_id: str = ""

    def for_engine(self, engine_name: str) -> dict[str, Any]:
        auth_token = self.auth_material.get(engine_name) or self.auth_material.get("default")
        return {
            "lab_url": self.lab_url,
            "auth_token": auth_token,
            "openapi_path": str(self.openapi_path) if self.openapi_path else None,
            "har_path": str(self.har_path) if self.har_path else None,
            "policy": self.policy,
            "time_budget_seconds": self.time_budget_seconds,
            "seed": self.seed,
            "run_id": self.run_id,
        }
