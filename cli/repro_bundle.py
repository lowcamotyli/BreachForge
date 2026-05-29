from __future__ import annotations

import hashlib
import json
import platform
import shutil
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


@dataclass(slots=True)
class ReproBundle:
    output_dir: Path

    def collect(self, scan_output: Path) -> None:
        self.output_dir.mkdir(parents=True, exist_ok=True)
        raw_output = self.output_dir / "raw_output.json"
        shutil.copyfile(scan_output, raw_output)

        data = json.loads(raw_output.read_text(encoding="utf-8"))
        findings = self._extract_findings(data)
        self._write_json("normalized_findings.json", findings)
        self._write_json("metrics.json", self._compute_metrics(data, findings))
        self._write_json(
            "env_metadata.json",
            {
                "python_version": sys.version,
                "platform": platform.platform(),
                "timestamp": datetime.now(UTC).isoformat(),
            },
        )

    def sign(self) -> str:
        hashes = []
        for path in sorted(self._bundle_files(), key=lambda item: item.name):
            hashes.append(self._sha256(path))
        return hashlib.sha256("".join(hashes).encode("utf-8")).hexdigest()

    def export(self) -> None:
        files = {path.name: self._sha256(path) for path in sorted(self._bundle_files(), key=lambda item: item.name)}
        self._write_json(
            "manifest.json",
            {
                "files": files,
                "bundle_signature": self.sign(),
            },
        )

    def _write_json(self, name: str, data: Any) -> None:
        (self.output_dir / name).write_text(
            json.dumps(data, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    @staticmethod
    def _extract_findings(data: Any) -> list[dict[str, Any]]:
        if isinstance(data, dict) and isinstance(data.get("findings"), list):
            return [finding for finding in data["findings"] if isinstance(finding, dict)]
        if isinstance(data, list):
            return [finding for finding in data if isinstance(finding, dict)]
        return []

    @staticmethod
    def _compute_metrics(data: Any, findings: list[dict[str, Any]]) -> dict[str, float | int]:
        if isinstance(data, dict) and isinstance(data.get("metrics"), dict):
            metrics = data["metrics"]
            return {
                "tp": int(metrics.get("tp", 0)),
                "fp": int(metrics.get("fp", 0)),
                "fn": int(metrics.get("fn", 0)),
                "coverage": float(metrics.get("coverage", 0.0)),
            }

        tp = 0
        fp = 0
        fn = 0
        for finding in findings:
            label = str(
                finding.get("result")
                or finding.get("label")
                or finding.get("classification")
                or ""
            ).lower()
            if label in {"tp", "true_positive", "true-positive"}:
                tp += 1
            elif label in {"fp", "false_positive", "false-positive"}:
                fp += 1
            elif label in {"fn", "false_negative", "false-negative"}:
                fn += 1
        denominator = tp + fn
        coverage = float(tp / denominator) if denominator else 0.0
        return {"tp": tp, "fp": fp, "fn": fn, "coverage": coverage}

    def _bundle_files(self) -> list[Path]:
        return [
            self.output_dir / "env_metadata.json",
            self.output_dir / "metrics.json",
            self.output_dir / "normalized_findings.json",
            self.output_dir / "raw_output.json",
        ]

    @staticmethod
    def _sha256(path: Path) -> str:
        return hashlib.sha256(path.read_bytes()).hexdigest()
