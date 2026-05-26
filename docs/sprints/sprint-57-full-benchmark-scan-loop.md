## Sprint 57 - Full Benchmark Scan Loop

**Goal:** `scripts/benchmark_lab.py --full` uruchamia realny lokalny scan przeciw benchmark lab, zbiera findings z systemu i liczy TP/FP/FN zamiast zwracac placeholder.

### Architektura - dokumenty referencyjne

```bash
DAD_PROMPT="cd /mnt/d/BreachForge && Read docs/architecture/attack-engine.md, docs/architecture/validation-model.md and docs/BENCHMARK_README.md. Extract the current scan loop, evidence path and benchmark gaps. Bullets. Max 30 lines." bash ~/.claude/scripts/dad-exec.sh
```

### Workstream A - Lab runtime harness

| ID | Zadanie | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| A1 | Start/stop benchmark lab jako subprocess albo in-process ASGI server z losowym localhost portem | `scripts/benchmark_lab.py`, `tests/benchmark_lab/` | codex-main | benchmark smoke | runner odpala lab bez recznej komendy |
| A2 | Seed identity/session data dla user/admin/tenantA/tenantB i wystawienie auth material do skanu | `tests/benchmark_lab/lab_app.py`, `ground_truth.json` | codex-dad | lab auth tests | skaner dostaje realne role i tenanty |
| A3 | Safety invariant: benchmark ruch tylko do localhost/127.0.0.1 | `scripts/benchmark_lab.py` | codex-main | guardrail tests | runner fail-closed poza localhost |

### Workstream B - Scan invocation

| ID | Zadanie | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| B1 | Programmatic scan runner: create scan -> inject policy/session/spec asset map -> run lifecycle to completion | `scripts/benchmark_lab.py`, `api/routers/scans.py`, `control_plane/orchestrator.py` | codex-main | integration smoke | benchmark nie uzywa mock_findings |
| B2 | Minimal local runtime dependencies: SQLite/Redis fallback albo test harness dla RQ jobs | `scripts/benchmark_lab.py`, `storage/db/session.py`, `execution_plane/workers/dispatcher.py` | codex-dad | full benchmark smoke | `--full` dziala lokalnie bez AWS/LocalStack |
| B3 | Findings collector normalizuje attack_class/type/endpoint/method do formatu benchmarkowego | `scripts/benchmark_lab.py`, `control_plane/reporting.py` | codex-main | metrics tests | TP/FP/FN liczone na realnych findings |

### Workstream C - Baseline gates

| ID | Zadanie | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| C1 | Golden full metrics zapisane osobno od zero-detection baseline | `tests/benchmark_lab/golden/` | codex-main | golden test | regresja coverage widoczna w diffie |
| C2 | CI smoke: `--full --max-seconds N` optional, szybki test nie flakuje | `tests/integration/test_benchmark_smoke.py` | codex-main | integration | pelny tryb ma kontrolowany timeout |
| C3 | README benchmark rozroznia quick/mock vs full/live scan | `docs/BENCHMARK_README.md` | codex-main | doc review | brak mylacego "full placeholder" |

### Guardrails

- Benchmark nigdy nie wysyla requestow poza localhost.
- `--quick` moze zostac jako szybki parser/metrics smoke, ale `--full` nie moze miec placeholdera.
- Wszystkie secrets/session tokens z labu sa synthetic i redagowane w output.

### Weryfikacja

```bash
python -m pytest tests/benchmark_lab/ -q
python -m pytest tests/integration/test_benchmark_smoke.py -q
python scripts/benchmark_lab.py --full --output .runtime/benchmark-full.json
python -m pytest tests/unit/ -q
```

### Global acceptance criteria

- [ ] `--full` wykonuje realny scan end-to-end.
- [ ] Metrics licza TP/FP/FN na realnych findings.
- [ ] Output zawiera coverage, time_to_proof_avg i unsafe_block_count.
- [ ] Brak placeholder note w full mode.

### Podzial pracy - codex-dad

A2 i B2 ida do **codex-dad** jako runtime/context package. A1, A3, B1, B3 i C robi **codex-main**.
