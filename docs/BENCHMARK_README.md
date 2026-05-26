# ProofScan Benchmark Lab

The benchmark lab is a realistic vulnerable SaaS app used to measure scanner effectiveness against known application security flaws. Its ground truth manifest defines the vulnerabilities the scanner should eventually detect, so benchmark metrics can stay repeatable across runs.

## Quick Start

```bash
python scripts/benchmark_lab.py --quick
```

Quick mode does not perform HTTP requests. It loads the ground truth manifest, compares it with an empty mock findings list, and emits baseline metrics as JSON.

## Full Benchmark

Manual lab smoke run:

```bash
python -m pytest tests/benchmark_lab/test_lab_smoke.py -q
```

The `--full` runner mode currently emits a placeholder JSON result until live scan integration is wired in:

```bash
python scripts/benchmark_lab.py --full
```

## Metrics

- `TP`: ground truth vulnerabilities matched by finding `type` and `endpoint`
- `FP`: findings that do not match any ground truth vulnerability
- `FN`: ground truth vulnerabilities with no matching finding
- `coverage`: `TP / (TP + FN)` when ground truth exists
- `time_to_proof_avg`: average time to produce proof artifacts
- `unsafe_block_count`: unsafe probes blocked by benchmark safety controls

## Ground Truth

The manifest lives at:

```text
tests/benchmark_lab/ground_truth.json
```

To add a vulnerability, edit `tests/benchmark_lab/ground_truth.json` and add the matching endpoint behavior in `tests/benchmark_lab/lab_app.py`.

## Golden Baseline

The current zero-detection baseline lives at:

```text
tests/benchmark_lab/golden/baseline_metrics.json
```

## CI Integration

`tests/integration/test_benchmark_smoke.py` runs the benchmark runner in the integration suite and verifies quick/full modes return valid JSON.
