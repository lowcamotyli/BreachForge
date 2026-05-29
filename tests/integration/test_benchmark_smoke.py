from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path


def test_benchmark_quick_outputs_valid_json() -> None:
    start = time.monotonic()
    result = subprocess.run(
        [sys.executable, "scripts/benchmark_lab.py", "--quick"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    elapsed = time.monotonic() - start
    assert result.returncode == 0, f"Non-zero exit: {result.stderr}"
    data = json.loads(result.stdout)
    assert elapsed < 5.0, f"Too slow: {elapsed:.1f}s"
    for key in ("coverage", "tp", "fp", "fn", "ground_truth_count", "discovery_coverage_pct", "discovery_blind_spots"):
        assert key in data, f"Missing key: {key}"
    assert data["ground_truth_count"] == 7
    assert data["fn"] == 7
    assert data["tp"] == 0
    assert data["coverage"] == 0.0
    assert data["discovery_coverage_pct"] == 0.0
    assert data["discovery_gate"]["status"] == "not_run"


def test_benchmark_full_mode_exits_zero() -> None:
    result = subprocess.run(
        [sys.executable, "scripts/benchmark_lab.py", "--full", "--max-seconds", "60"],
        capture_output=True,
        text=True,
        timeout=90,
    )
    assert result.returncode == 0, f"Non-zero exit: {result.stderr}"
    data = json.loads(result.stdout)
    assert data["mode"] == "full"
    for key in ("coverage", "tp", "fp", "fn", "findings_count", "ground_truth_count",
                "time_to_proof_avg", "unsafe_block_count", "expected_endpoints",
                "discovered_endpoints", "discovery_coverage_pct", "discovery_blind_spots",
                "discovery_coverage_threshold"):
        assert key in data, f"Missing key: {key}"
    assert data["ground_truth_count"] == 7
    assert "note" not in data, "Placeholder note must not appear in full mode"
    assert data["discovery_coverage_pct"] >= 80.0
    assert data["discovery_blind_spots"] == []
    assert data["discovery_gate"]["status"] == "passed"
    # Coverage must be non-trivial: scanner detects at least some findings
    assert data["tp"] > 0, "Full scan must detect at least one vulnerability"
    assert data["coverage"] > 0.0, "Coverage must be positive after real scan"


def test_benchmark_full_mode_fails_loudly_on_discovery_blind_spots(tmp_path: Path) -> None:
    ground_truth = tmp_path / "ground_truth.json"
    ground_truth.write_text(
        json.dumps(
            {
                "lab_version": "test",
                "expected_endpoints": ["/definitely-missing"],
                "vulnerabilities": [],
            }
        ),
        encoding="utf-8",
    )
    result = subprocess.run(
        [
            sys.executable,
            "scripts/benchmark_lab.py",
            "--full",
            "--ground-truth",
            str(ground_truth),
            "--max-seconds",
            "60",
        ],
        capture_output=True,
        text=True,
        timeout=90,
    )
    assert result.returncode == 1
    assert result.stdout == ""
    assert "DISCOVERY BLIND SPOTS: coverage 0.0% below threshold 80%" in result.stderr
    assert "- /definitely-missing" in result.stderr
