from __future__ import annotations

from dataclasses import dataclass, field
import json
from pathlib import Path
from typing import Any


@dataclass
class LabManifest:
    lab_id: str
    lab_version: str
    attack_classes: list[str]
    identities: list[dict[str, Any]]
    expected_surface: list[str]
    expected_endpoints: list[str]
    vulnerabilities: list[dict[str, Any]]
    discovery_surface: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> LabManifest:
        return cls(
            lab_id=data["lab_id"],
            lab_version=data.get("lab_version", "unknown"),
            attack_classes=data.get("attack_classes", []),
            identities=data.get("identities", []),
            expected_surface=data.get("expected_surface", []),
            expected_endpoints=data.get("expected_endpoints", data.get("expected_surface", [])),
            vulnerabilities=data.get("vulnerabilities", []),
            discovery_surface=data.get("discovery_surface", []),
        )

    @classmethod
    def from_json(cls, path: Path) -> LabManifest:
        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)
        return cls.from_dict(data)
