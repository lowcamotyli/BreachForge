from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(slots=True)
class BenchRunner:
    def run_native(self, corpus_dir: Path, output: Path, seed: int = 42) -> None:
        del corpus_dir
        output.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(
            [
                "python",
                "scripts/benchmark_lab.py",
                "--full",
                "--lab",
                "all",
                "--anti-gaming-seed",
                str(seed),
                "--output",
                str(output),
            ],
            check=True,
        )

    def import_results(self, file: Path, engine_name: str) -> dict[str, Any]:
        data = json.loads(file.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError("Benchmark result file must contain a JSON object")
        return {**data, "engine_name": engine_name}

    def compare(self, baseline: dict[str, Any], current: dict[str, Any]) -> dict[str, float]:
        return {
            "tp_delta": self._float_metric(current, "tp") - self._float_metric(baseline, "tp"),
            "fp_delta": self._float_metric(current, "fp") - self._float_metric(baseline, "fp"),
            "fn_delta": self._float_metric(current, "fn") - self._float_metric(baseline, "fn"),
            "coverage_delta": self._float_metric(current, "coverage")
            - self._float_metric(baseline, "coverage"),
        }

    def export_scorecard(self, results: dict[str, Any], output: Path, fmt: str = "json") -> None:
        output.parent.mkdir(parents=True, exist_ok=True)
        if fmt == "json":
            output.write_text(json.dumps(results, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            return
        if fmt == "markdown":
            output.write_text(self._to_markdown(results), encoding="utf-8")
            return
        raise ValueError(f"Unsupported scorecard format: {fmt}")

    @staticmethod
    def _float_metric(results: dict[str, Any], key: str) -> float:
        return float(results.get(key, 0.0))

    @staticmethod
    def _to_markdown(results: dict[str, Any]) -> str:
        lines = ["| Metric | Value |", "| --- | --- |"]
        for key in sorted(results):
            lines.append(f"| {key} | {results[key]} |")
        return "\n".join(lines) + "\n"
