## Sprint 52 - Adaptive Replanning v1

**Goal:** Planner reaguje na runtime feedback: pierwszy dowod generuje drugi, bez recznego dopisywania sciezki.

### Architektura - dokumenty referencyjne

```bash
DAD_PROMPT="cd /mnt/d/BreachForge && Read docs/architecture/attack-engine.md and docs/architecture/noise-reduction.md. Extract: planner feedback loops, task status flow, proof-gate, safe follow-up constraints. Bullets. Max 25 lines." bash ~/.claude/scripts/dad-exec.sh
```

### Workstream A - Outcome contract

| ID | Zadanie | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| A1 | Zdefiniowac outcome enum: `success`, `interesting`, `needs_followup`, `blocked`, `no_signal`, `unsafe_blocked` | `execution_plane/planner/decision_log.py`, `execution_plane/workers/dispatcher.py` | codex-main | unit tests | wszystkie runtime wyniki maja wspolny shape |
| A2 | Validator publikuje feedback payload po istotnym artifact/probe discard | `execution_plane/validator/validator.py` | codex-dad | validator tests | planner dostaje machine-readable feedback |
| A3 | Finding scorer publikuje high-signal follow-up hints | `control_plane/finding_scorer.py` | codex-main | scorer tests | secret/GraphQL/403 hints sa widoczne |

### Workstream B - Replanning queue

| ID | Zadanie | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| B1 | RQ job `replan_attack(scan_id, feedback)` | `execution_plane/planner/planner.py` | codex-dad | planner integration tests | feedback tworzy nowe bounded tasks |
| B2 | Dedup follow-up tasks po endpoint/class/parameter/hypothesis hash | `execution_plane/planner/planner.py` | codex-dad | tests | brak petli duplikatow |
| B3 | Limit rund i safety budget per scan | `execution_plane/workers/dispatcher.py`, `planner.py` | codex-main | lifecycle tests | replanning konczy sie deterministycznie |

### Workstream C - Three adaptive scenarios

| ID | Scenariusz | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| C1 | sensitive_exposure -> safe secret replay -> blast radius | `dispatcher.py`, `planner/playbooks/*`, `attack_worker.py` | codex-main | corpus tests | drugi krok wynika z secret findingu |
| C2 | GraphQL introspection -> schema driven field/depth probe | `planner/rules/graphql.py`, `validator/strategies/graphql.py` | codex-dad | GraphQL tests | schema generuje follow-up |
| C3 | 403/admin signal -> privilege drift/BFLA follow-up | `planner/rules/bfla.py`, `privilege_escalation.py` | codex-dad | authz tests | blocked signal generuje role probe |

### Guardrails

- Replanning nie moze ominac proof-gate ani safety budget.
- Kazdy follow-up ma parent evidence ref.
- `unsafe_blocked` jest sukcesem guardraila, nie powodem do obejscia.

### Weryfikacja

```bash
python -m pytest tests/unit/execution_plane/planner/ -q
python -m pytest tests/unit/execution_plane/workers/test_dispatcher_autonomous_loop.py -q
python -m pytest tests/corpus/attack_chains/ -q
python -m pytest tests/unit/ -q
```

### Global acceptance criteria

- [ ] Feedback runtime ma jeden kontrakt.
- [ ] Planner tworzy bounded follow-up tasks.
- [ ] Dedup i max rounds blokuja petle.
- [ ] Minimum 3 adaptive scenarios dzialaja w testach.

### Podzial pracy - codex-dad

A2, B1-B2, C2-C3 ida do **codex-dad**. A1, A3, B3, C1 integruje **codex-main**.
