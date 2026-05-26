## Sprint 62 - Scale Reliability And Quality Gates

**Goal:** Udowodnic, ze engine jest nie tylko skuteczny w labie, ale stabilny przy duzej powierzchni: setki endpointow, restart workerow, timeouty, Redis/RQ problemy i quality gates w CI/nightly.

### Architektura - dokumenty referencyjne

```bash
DAD_PROMPT="cd /mnt/d/BreachForge && Read docs/architecture/storage-infra.md, docs/architecture/security-constraints.md and docs/sprints/sprint-54-race-concurrency-engine-v2.md. Extract reliability, queue, evidence and guardrail failure modes. Bullets. Max 35 lines." bash ~/.claude/scripts/dad-exec.sh
```

### Workstream A - Scale lab

| ID | Zadanie | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| A1 | Synthetic large AssetMap generator: 100/500/1000 endpoint profiles | `tests/benchmark_lab/`, `scripts/benchmark_lab.py` | codex-main | benchmark tests | mozna mierzyc skale bez internetu |
| A2 | Large scan budgets: max_requests, max_runtime, per-class cap, priority preservation | planner/dispatcher/policy files | codex-dad | planner tests | high-value endpoints nie gina w noise |
| A3 | Metrics: requests_total, requests_blocked, queue_latency, validator_latency, time_to_first_proof | `scripts/benchmark_lab.py`, reporting | codex-main | metrics tests | widac koszt i wydajnosc |

### Workstream B - Failure injection

| ID | Zadanie | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| B1 | Worker crash/retry simulation in integration tests | `tests/integration/`, `execution_plane/workers/supervisor.py` | codex-main | integration | scan nie traci evidence przy crashu |
| B2 | Redis/RQ transient failure handling: retry/backoff/idempotent finalize | `execution_plane/workers/dispatcher.py`, `control_plane/orchestrator.py` | codex-dad | lifecycle tests | finalize nie duplikuje findings |
| B3 | Evidence consistency checker: probes -> proof artifacts -> findings -> report links | `scripts/`, `storage/evidence/store.py`, reporting | codex-main | consistency tests | brak osieroconych dowodow |

### Workstream C - Quality gates

| ID | Zadanie | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| C1 | CI smoke gates: unit, benchmark quick, selected full lab | test config/docs/scripts | codex-main | CI smoke | szybka sciezka lapie regresje |
| C2 | Nightly gates: all labs, min coverage, max FP, max unsafe_block anomalies | docs/scripts | codex-main | manual/nightly | jasny ship/no-ship sygnal |
| C3 | Release scorecard: effectiveness, reliability, safety, blind spots | `docs/BENCHMARK_README.md`, reporting | codex-main | doc review | decyzja ship oparta na metrykach |

### Guardrails

- Scale tests nie moga wysylac ruchu poza lokalne laby.
- Failure injection nie moze ukrywac bledow przez blanket except.
- Quality gates maja byc surowe, ale osobno dla CI smoke i nightly.

### Weryfikacja

```bash
python -m pytest tests/unit/ -q
python -m pytest tests/integration/ -q
python scripts/benchmark_lab.py --full --lab all --min-coverage 0.80 --max-fp 0
python scripts/benchmark_lab.py --scale 500 --output .runtime/benchmark-scale.json
```

### Global acceptance criteria

- [ ] Large AssetMap benchmark dziala lokalnie.
- [ ] Worker/RQ failure modes sa testowane.
- [ ] Evidence consistency checker przechodzi.
- [ ] CI/nightly gates daja jednoznaczny release scorecard.

### Podzial pracy - codex-dad

A2 i B2 ida do **codex-dad** jako reliability implementation packages. Reszte robi **codex-main**.
