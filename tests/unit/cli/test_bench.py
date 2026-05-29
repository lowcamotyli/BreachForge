from __future__ import annotations

import json

from cli.bench_runner import BenchRunner


def test_bench_runner_import_results(tmp_path) -> None:
    result_file = tmp_path / "results.json"
    result_file.write_text(json.dumps({"tp": 1}), encoding="utf-8")

    results = BenchRunner().import_results(result_file, engine_name="native")

    assert results["engine_name"] == "native"


def test_bench_runner_compare() -> None:
    comparison = BenchRunner().compare(
        baseline={"tp": 1, "fp": 2, "fn": 3, "coverage": 0.5},
        current={"tp": 2, "fp": 1, "fn": 4, "coverage": 0.75},
    )

    assert set(comparison) == {"tp_delta", "fp_delta", "fn_delta", "coverage_delta"}


def test_bench_runner_export_scorecard_json(tmp_path) -> None:
    output = tmp_path / "scorecard.json"

    BenchRunner().export_scorecard({"tp": 1}, output)

    assert output.exists()


def test_bench_runner_export_scorecard_markdown(tmp_path) -> None:
    output = tmp_path / "scorecard.md"

    BenchRunner().export_scorecard({"tp": 1}, output, fmt="markdown")

    assert "|" in output.read_text(encoding="utf-8")
