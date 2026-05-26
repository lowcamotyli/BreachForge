from __future__ import annotations

import json
import subprocess
import sys
import time

import pytest


def test_benchmark_quick_outputs_valid_json():
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
    for key in ("coverage", "tp", "fp", "fn", "ground_truth_count"):
        assert key in data, f"Missing key: {key}"
    assert data["ground_truth_count"] == 7
    assert data["fn"] == 7
    assert data["tp"] == 0
    assert data["coverage"] == 0.0


def test_benchmark_full_mode_exits_zero():
    result = subprocess.run(
        [sys.executable, "scripts/benchmark_lab.py", "--full"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0
    data = json.loads(result.stdout)
    assert data["mode"] == "full"
