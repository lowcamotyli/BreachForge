from __future__ import annotations

import json
import random
import sys
import uuid
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from scripts import benchmark_lab


def test_parse_args_engine_default() -> None:
    args = benchmark_lab.parse_args(["--quick"])

    assert args.engine == "native"


def test_parse_args_seed_accepted() -> None:
    args = benchmark_lab.parse_args(["--quick", "--seed", "42"])

    assert args.seed == 42


def test_parse_args_artifacts_dir() -> None:
    args = benchmark_lab.parse_args(["--quick", "--artifacts-dir", "/tmp/bf"])

    assert args.artifacts_dir == Path("/tmp/bf")


def test_parse_args_run_id() -> None:
    args = benchmark_lab.parse_args(["--quick", "--run-id", "my-run"])

    assert args.run_id == "my-run"


def test_main_run_id_in_result(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "argv", ["benchmark_lab", "--quick"])
    with (
        patch.object(
            benchmark_lab,
            "build_quick_result",
            return_value={"tp": 1, "fp": 0, "fn": 0, "coverage": 1.0, "run_id": "SKIP"},
        ),
        patch.object(benchmark_lab, "write_result") as write_result,
        patch.object(benchmark_lab, "assert_discovery_coverage") as assert_discovery_coverage,
    ):
        assert benchmark_lab.main() == 0

    assert_discovery_coverage.assert_not_called()
    write_result.assert_called_once()
    result = write_result.call_args.args[0]
    assert "run_id" in result
    uuid.UUID(result["run_id"])


def test_matrix_exits_zero(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setattr(sys, "argv", ["benchmark_lab", "--quick", "--matrix", "native,zap"])
    from scripts.benchmark_lab import main

    assert main() == 0
    output = json.loads(capsys.readouterr().out)
    assert output["matrix_mode"] is True
    assert output["engines"] == ["native", "zap"]


def test_seed_sets_random(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "argv", ["benchmark_lab", "--quick", "--seed", "99"])
    random.seed(12345)
    before = random.getstate()
    with (
        patch.object(
            benchmark_lab,
            "build_quick_result",
            return_value={"tp": 1, "fp": 0, "fn": 0, "coverage": 1.0},
        ),
        patch.object(benchmark_lab, "write_result", MagicMock()),
    ):
        assert benchmark_lab.main() == 0

    after = random.getstate()
    random.seed(99)
    assert after != before
    assert after == random.getstate()


def test_comparison_report_single_engine() -> None:
    from scripts.benchmark_lab import generate_comparison_report

    result = generate_comparison_report(
        [
            {
                "engine": "native",
                "tp": 5,
                "fp": 1,
                "fn": 2,
                "coverage": 0.71,
                "proof_depth_avg": 3.2,
                "auth_health_rate": 0.95,
            }
        ]
    )

    assert "native" in result and "Rank Table" in result and "0.71" in result


def test_comparison_report_rank_order() -> None:
    from scripts.benchmark_lab import generate_comparison_report

    results = [
        {"engine": "zap", "tp": 3, "fp": 2, "fn": 4, "coverage": 0.43},
        {"engine": "native", "tp": 6, "fp": 0, "fn": 1, "coverage": 0.86},
    ]
    md = generate_comparison_report(results)

    assert md.index("native") < md.index("zap")


def test_benchmark_metrics_new_fields() -> None:
    from scripts.benchmark_lab import BenchmarkMetrics
    import dataclasses

    m = BenchmarkMetrics(
        requests_total=10,
        requests_blocked=0,
        queue_latency_ms=1.0,
        validator_latency_ms=2.0,
        time_to_first_proof_ms=100.0,
    )

    assert dataclasses.is_dataclass(m)
    assert hasattr(m, "proof_depth_avg")
    assert hasattr(m, "auth_health_rate")
    assert hasattr(m, "coverage_by_attack_class")
    assert isinstance(m.coverage_by_attack_class, dict)
