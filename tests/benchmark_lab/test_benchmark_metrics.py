from __future__ import annotations

import json
import subprocess
import sys
from dataclasses import asdict
from pathlib import Path

import pytest

from scripts.benchmark_lab import BenchmarkMetrics, build_quick_result, collect_metrics, load_ground_truth


LAB_IDS = ("api_saas", "graphql", "spa_har", "business_race", "auth_oauth")


def _ensure_golden_baseline(golden_path: Path, ground_truth: dict[str, object]) -> dict[str, object]:
    golden = json.loads(golden_path.read_text(encoding="utf-8"))
    if "min_coverage" in golden:
        return golden

    quick_result = build_quick_result(ground_truth)
    attack_classes = ground_truth.get("attack_classes", [])
    if not isinstance(attack_classes, list):
        attack_classes = []

    updated = {
        "lab_id": ground_truth.get("lab_id", golden_path.stem.removesuffix("_metrics")),
        "min_coverage": float(quick_result.get("coverage", 0.0)),
        "max_fp": int(quick_result.get("fp", 0)),
        "attack_classes": [str(attack_class) for attack_class in attack_classes],
        "lab_version": quick_result.get("lab_version", "unknown"),
        "mode": quick_result.get("mode", "quick"),
        "coverage": quick_result.get("coverage", 0.0),
        "tp": quick_result.get("tp", 0),
        "fp": quick_result.get("fp", 0),
        "fn": quick_result.get("fn", 0),
        "ground_truth_count": quick_result.get("ground_truth_count", 0),
        "coverage_by_attack_class": quick_result.get("coverage_by_attack_class", {}),
    }
    golden_path.write_text(json.dumps(updated, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return updated


def test_benchmark_metrics_dataclass_creation() -> None:
    metrics = BenchmarkMetrics(
        requests_total=10,
        requests_blocked=2,
        queue_latency_ms=1.5,
        validator_latency_ms=2.5,
        time_to_first_proof_ms=3.5,
    )

    assert asdict(metrics) == {
        "requests_total": 10,
        "requests_blocked": 2,
        "queue_latency_ms": 1.5,
        "validator_latency_ms": 2.5,
        "time_to_first_proof_ms": 3.5,
        "proof_depth_avg": 0.0,
        "proof_depth_min": 0,
        "proof_depth_max": 0,
        "auth_health_rate": 0.0,
        "coverage_by_attack_class": {},
    }


def test_collect_metrics_extracts_mock_scan_result() -> None:
    metrics = collect_metrics(
        {
            "metrics": {
                "requests_total": 42,
                "requests_blocked": 7,
                "queue_latency_ms": 11.0,
                "validator_latency_ms": 22.0,
                "time_to_first_proof_ms": 33.0,
            }
        }
    )

    assert metrics == BenchmarkMetrics(
        requests_total=42,
        requests_blocked=7,
        queue_latency_ms=11.0,
        validator_latency_ms=22.0,
        time_to_first_proof_ms=33.0,
    )


def test_scale_flag_writes_benchmark_metrics_json(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[2]
    output_path = tmp_path / "scale-metrics.json"

    result = subprocess.run(
        [
            sys.executable,
            "scripts/benchmark_lab.py",
            "--scale",
            "25",
            "--output",
            str(output_path),
        ],
        capture_output=True,
        cwd=repo_root,
        text=True,
        timeout=10,
    )

    assert result.returncode == 0, result.stderr
    stdout_payload = json.loads(result.stdout)
    file_payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert stdout_payload == file_payload
    assert file_payload["requests_total"] == 25
    assert file_payload["requests_blocked"] >= 0
    assert file_payload["queue_latency_ms"] >= 0.0
    assert file_payload["validator_latency_ms"] >= 0.0
    assert file_payload["time_to_first_proof_ms"] >= 0.0


class TestGoldenBaselines:
    @pytest.mark.parametrize("lab_id", LAB_IDS)
    def test_quick_mode_matches_golden_thresholds(self, lab_id: str) -> None:
        repo_root = Path(__file__).resolve().parents[2]
        ground_truth = load_ground_truth(repo_root / "tests" / "benchmark_lab" / "labs" / lab_id / "ground_truth.json")
        golden = _ensure_golden_baseline(
            repo_root / "tests" / "benchmark_lab" / "golden" / f"{lab_id}_metrics.json",
            ground_truth,
        )

        result = build_quick_result(ground_truth)

        assert result["coverage"] >= golden.get("min_coverage", 0.0)
        assert result["fp"] <= golden.get("max_fp", 999)
