## Sprint 54 - Race And Concurrency Engine v2

**Goal:** Kontrolowane race testing z barrier start, grouped evidence i state reconciliation, bez chaosu requestowego.

### Architektura - dokumenty referencyjne

```bash
DAD_PROMPT="cd /mnt/d/BreachForge && Read docs/architecture/attack-engine.md and docs/architecture/security-constraints.md. Extract: rate limiter, worker concurrency, mutation guardrails, evidence grouping. Bullets. Max 25 lines." bash ~/.claude/scripts/dad-exec.sh
```

### Workstream A - Race coordinator

| ID | Zadanie | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| A1 | Barrier start dla grup requestow | `execution_plane/workers/concurrency.py`, `supervisor.py` | codex-dad | concurrency tests | requesty startuja w kontrolowanym oknie |
| A2 | Race group id w evidence metadata | `attack_worker.py`, `validator.py` | codex-main | evidence tests | artifacti mozna laczyc w jedna probe |
| A3 | Integracja z rate limiterem i safety budget | `rate_limiter.py`, `attack_worker.py` | codex-dad | guardrail tests | race nie omija limitow |

### Workstream B - Race classes

| ID | Klasa | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| B1 | Double spend | `planner/rules/race_advanced.py`, `validator/strategies/race_advanced.py` | codex-dad | corpus tests | potwierdza podwojny skutek |
| B2 | Limit override | same | codex-dad | corpus tests | potwierdza przekroczenie limitu |
| B3 | Inventory reservation | same | codex-dad | corpus tests | wykrywa race hold/stock |
| B4 | Idempotency bypass | same | codex-dad | corpus tests | rozroznia expected idempotency od bypassu |

### Workstream C - State reconciliation

| ID | Zadanie | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| C1 | Po burst wykonaj read-after-burst reconciliation | `attack_worker.py`, `dispatcher.py` | codex-main | integration tests | dowod pokazuje stan koncowy |
| C2 | Validator wymaga final state proof dla race finding | `validator/strategies/race_advanced.py` | codex-main | validator tests | status-only race nie przechodzi |
| C3 | Raport pokazuje timeline race attempts | `control_plane/reporting.py` | codex-main | reporting tests | czytelny grouping evidence |

### Guardrails

- Race window ma twardy max request count.
- Mutating race wymaga explicit policy.
- Rate limiter nadal obowiazuje per scan/domain.

### Weryfikacja

```bash
python -m pytest tests/unit/execution_plane/workers/test_supervisor.py -q
python -m pytest tests/unit/execution_plane/validator/test_race_advanced_strategy.py -q
python -m pytest tests/corpus/race_advanced_corpus.py -q
python -m pytest tests/unit/ -q
```

### Global acceptance criteria

- [ ] Race requests startuja przez controlled barrier.
- [ ] Evidence ma race group id.
- [ ] Finding wymaga final state reconciliation.
- [ ] Safety budget i rate limits nie sa obchodzone.

### Podzial pracy - codex-dad

A1, A3, B1-B4 ida do **codex-dad**. A2 i C1-C3 robi **codex-main**.
