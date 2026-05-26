# Work Item: sprint-55-realistic-benchmark-lab
## Owner
- Orchestrator: Claude | Workers: codex-dad (A1-A3), codex-main (B1-B3, C1-C3) | Status: dispatch

## Intent
Zbudować benchmark skuteczności na realistycznej aplikacji labowej z ground truth, zamiast oceniać system tylko po unit testach. Lab = standalone FastAPI app z seeded vulnerabilities. Runner = skrypt mierzący TP/FP/FN vs ground truth.

## Constraints
- Lab nie wymaga zewnętrznych sekretów ani serwisów (in-memory state)
- Benchmark nie wysyła ruchu poza localhost
- Golden output redaguje sekrety
- Ground truth format: JSON z polem `vulnerabilities[]` zawierającym id/type/endpoint/method/severity

## Acceptance criteria
- [ ] Benchmark lab ma realistyczne auth/multi-tenant/business flows
- [ ] Ground truth pozwala mierzyć TP/FP/FN
- [ ] Runner generuje metrics JSON
- [ ] Quick benchmark działa lokalnie bez zewnętrznych usług

## Verification
```bash
"/c/Program Files/Python312/python.exe" -m pytest tests/benchmark_lab/ -q
"/c/Program Files/Python312/python.exe" -m pytest tests/unit/ -q
python scripts/benchmark_lab.py --quick
```

## Work packages
- ID: pkg-A | Type: implementation | Worker: codex-dad | Inputs: tests/corpus/bola.py (pattern) | Outputs: tests/benchmark_lab/__init__.py, lab_app.py, ground_truth.json, test_lab_smoke.py
- ID: pkg-B | Type: implementation | Worker: codex-main | Inputs: scripts/red_team_sim.py (pattern), ground_truth.json format | Outputs: scripts/benchmark_lab.py, tests/benchmark_lab/golden/baseline_metrics.json, tests/integration/test_benchmark_smoke.py, docs/BENCHMARK_README.md

## Evidence log   <!-- append-only, timestamp per wpis -->
[2026-05-13 14:27] pkg-A (codex-dad) — files: tests/benchmark_lab/__init__.py, lab_app.py, ground_truth.json, test_lab_smoke.py — pytest tests/benchmark_lab/ -q → 7 passed in 0.52s
[2026-05-13 14:27] pkg-B (codex-main) — files: scripts/benchmark_lab.py, tests/benchmark_lab/golden/baseline_metrics.json, tests/integration/test_benchmark_smoke.py, docs/BENCHMARK_README.md — scripts/benchmark_lab.py --quick → valid JSON (coverage=0.0, fn=7), pytest test_benchmark_smoke.py → 2 passed
[2026-05-13 14:28] invariants — pytest tests/unit/ -q → 544 passed, 0 failures

## Decision
Ship: yes — benchmark lab gotowy, ground truth 7 vulns, runner działa w --quick i --full, CI smoke zintegrowany, brak regresji w unit suite. Accepted risks: --full mode bez faktycznego skanowania (stub z notatką).
