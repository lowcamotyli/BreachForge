## Sprint 61 - Autonomous Stateful Attack Loop

**Goal:** Narzedzie ma nie tylko wykonywac reguly, ale uczyc sie z wynikow w trakcie skanu: low/no-signal -> follow-up hypothesis -> state diff -> proof albo jawny FN.

### Architektura - dokumenty referencyjne

```bash
DAD_PROMPT="cd /mnt/d/BreachForge && Read docs/sprints/sprint-51-state-model-differential-engine.md, sprint-52-adaptive-replanning-v1.md and docs/architecture/validation-model.md. Extract current state/adaptive contracts and missing operator-grade loop pieces. Bullets. Max 35 lines." bash ~/.claude/scripts/dad-exec.sh
```

### Workstream A - Runtime feedback contract v2

| ID | Zadanie | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| A1 | Standard feedback reasons: no_signal, auth_drift, interesting_diff, state_changed, needs_identity, unsafe_blocked | `execution_plane/planner/decision_log.py`, `execution_plane/validator/validator.py` | codex-main | validator tests | planner dostaje precyzyjny feedback |
| A2 | Replan budget per scan/class/endpoint z audit trail | `execution_plane/planner/planner.py`, `dispatcher.py` | codex-dad | planner/dispatcher tests | brak nieskonczonych petli |
| A3 | Follow-up task lineage: parent_task_id, parent_probe_id, reason | `storage/db/models.py`, planner/scorer | codex-dad | model tests | mozna sledzic lancuch hipotez |

### Workstream B - Stateful proof paths

| ID | Zadanie | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| B1 | Read-after-write verifier dla business logic i privilege changes | `execution_plane/validator/state_diff.py`, strategies | codex-main | state tests | proof pokazuje skutki, nie tylko 200 |
| B2 | Chain executor wzbogacony o extracted values, rollback-safe read probes i identity switch | `execution_plane/workers/attack_worker.py` | codex-main | worker tests | multi-step exploit chain dziala deterministycznie |
| B3 | Race final-state reconciliation jako required proof dla race findings | `execution_plane/workers/dispatcher.py`, race strategies | codex-main | race tests | race bez reconciliation nie jest findingiem |

### Workstream C - Benchmark adaptive scenarios

| ID | Zadanie | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| C1 | Benchmark cases wymagajace follow-up po pierwszym no-signal | `tests/benchmark_lab/labs/business_race/` | codex-dad | benchmark | TP wymaga replanningu |
| C2 | Metrics: adaptive_rounds, follow_up_tp, dead_end_count | `scripts/benchmark_lab.py` | codex-main | metrics tests | widac wartosc autonomii |
| C3 | Report attack chain timeline dla findings z follow-up | `control_plane/reporting.py` | codex-main | reporting tests | dowod jest czytelny dla operatora |

### Guardrails

- Replanning ma twardy budzet i policy constraints.
- Follow-up nie moze rozszerzac scope poza allowed_domains.
- Stateful proof musi odroznic testowy skutek od destrukcyjnej mutacji.

### Weryfikacja

```bash
python -m pytest tests/unit/execution_plane/planner/test_planner_replan.py -q
python -m pytest tests/unit/execution_plane/validator/test_state_diff.py -q
python -m pytest tests/unit/execution_plane/workers/ -q
python scripts/benchmark_lab.py --full --lab business_race
python -m pytest tests/unit/ -q
```

### Global acceptance criteria

- [ ] Follow-up tasks maja lineage i reason.
- [ ] Adaptive TP sa mierzone w benchmarku.
- [ ] Stateful findings wymagaja state proof.
- [ ] Replanning jest bounded i audytowalny.

### Podzial pracy - codex-dad

A2, A3 i C1 ida do **codex-dad**. A1, B i C2-C3 robi **codex-main**.
