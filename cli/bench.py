from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import click

from cli.bench_runner import BenchRunner


@click.group(name="bench")
def bench() -> None:
    """Benchmark operations."""


@bench.command("run")
@click.option("--engine", type=click.Choice(["native"]), default="native", show_default=True)
@click.option(
    "--corpus",
    type=click.Path(exists=False, file_okay=False, path_type=Path),
    default=Path("tests/benchmark_lab/"),
    show_default=True,
)
@click.option(
    "--output",
    type=click.Path(dir_okay=False, path_type=Path),
    default=Path(".runtime/bench.json"),
    show_default=True,
)
@click.option("--seed", type=int, default=42, show_default=True)
def run(engine: str, corpus: Path, output: Path, seed: int) -> None:
    runner = BenchRunner()
    if engine == "native":
        runner.run_native(corpus_dir=corpus, output=output, seed=seed)
        click.echo(str(output))


@bench.command("import-results")
@click.option("--file", "file_path", required=True, type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--engine-name", required=True, type=str)
def import_results(file_path: Path, engine_name: str) -> None:
    results = BenchRunner().import_results(file=file_path, engine_name=engine_name)
    click.echo(json.dumps(results, indent=2, sort_keys=True))


@bench.command("compare")
@click.option("--baseline", required=True, type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--current", required=True, type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--output", type=click.Path(dir_okay=False, path_type=Path), default=None)
def compare(baseline: Path, current: Path, output: Path | None) -> None:
    runner = BenchRunner()
    baseline_results = _load_json_object(baseline)
    current_results = _load_json_object(current)
    comparison = runner.compare(baseline=baseline_results, current=current_results)
    rendered = json.dumps(comparison, indent=2, sort_keys=True)
    if output is None:
        click.echo(rendered)
        return
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(rendered + "\n", encoding="utf-8")


@bench.command("export-scorecard")
@click.option("--input", "input_path", required=True, type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--format", "fmt", type=click.Choice(["json", "markdown"]), default="json", show_default=True)
@click.option("--output", required=True, type=click.Path(dir_okay=False, path_type=Path))
def export_scorecard(input_path: Path, fmt: str, output: Path) -> None:
    results = _load_json_object(input_path)
    BenchRunner().export_scorecard(results=results, output=output, fmt=fmt)
    click.echo(str(output))


def _load_json_object(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise click.ClickException(f"{path} must contain a JSON object")
    return data
