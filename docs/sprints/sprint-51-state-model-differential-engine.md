## Sprint 51 - State Model And Differential Engine

**Goal:** Formalnie mierzyc skutki operacji: finding ma byc oparty o stan przed/po, read-after-write albo strukturalny differential, nie tylko status code.

### Architektura - dokumenty referencyjne

```bash
DAD_PROMPT="cd /mnt/d/BreachForge && Read docs/architecture/validation-model.md and docs/architecture/attack-engine.md. Extract: proof artifact contract, state diff expectations, validator strategy boundaries. Bullets. Max 25 lines." bash ~/.claude/scripts/dad-exec.sh
```

### Workstream A - State snapshot contract

| ID | Zadanie | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| A1 | Zdefiniowac formalny `StateSnapshot` contract dla before/after | `storage/evidence/state_store.py`, `execution_plane/validator/state_diff.py` | codex-main | state tests | snapshots maja wersje, timestamp, normalized state |
| A2 | Worker zapisuje before/post snapshots dla mutating i workflow tasks | `execution_plane/workers/attack_worker.py` | codex-dad | worker tests | post snapshot zawiera response + derived state |
| A3 | Guard: brak after-state dla wymagajacej klasy obniza confidence albo blokuje finding | validator strategies | codex-dad | validator tests | silent 200 bez zmiany stanu nie tworzy high confidence |

### Workstream B - Read-after-write verifier

| ID | Zadanie | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| B1 | Planner/worker potrafi zaplanowac safe read-after-write endpoint | `execution_plane/planner/planner.py`, `attack_worker.py` | codex-dad | integration tests | mutation proof ma follow-up read |
| B2 | Verifier normalizuje JSON body i ignoruje volatile fields | `execution_plane/validator/state_diff.py` | codex-main | unit tests | timestamps/request ids nie robia false positive |
| B3 | Dowod zawiera `state_diff` w ProofArtifact | `execution_plane/validator/validator.py` | codex-main | validator tests | report pokazuje added/removed/changed |

### Workstream C - Differential comparators

| ID | Zadanie | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| C1 | JSON comparator: pola, typy, listy, semantic equality | `execution_plane/validator/differential.py` | codex-main | comparator tests | stable structural diff |
| C2 | HTML/text comparator z bucketami rozmiaru i statusu | `execution_plane/validator/differential.py` | codex-main | tests | mniej false positives na szumie |
| C3 | Differential confidence model per attack class | `execution_plane/validator/strategies/*.py` | codex-dad | strategy tests | klasy logiki biznesowej wymagaja skutku |

### Guardrails

- Mutating probes musza respektowac production-safe mode.
- State diff nie moze przechowywac sekretow bez redaction policy w raporcie.
- Brak zmiany stanu nie jest automatycznym findingiem.

### Weryfikacja

```bash
python -m pytest tests/unit/execution_plane/validator/test_differential_comparator.py -q
python -m pytest tests/unit/execution_plane/validator/ -q
python -m pytest tests/unit/execution_plane/workers/ -q
python -m pytest tests/unit/ -q
```

### Global acceptance criteria

- [ ] ProofArtifact moze zawierac wiarygodny state_diff.
- [ ] Workflow/business logic findings wymagaja skutku albo mocnego differential.
- [ ] Volatile response noise nie tworzy false positive.
- [ ] Report pokazuje istotny stan przed/po.

### Podzial pracy - codex-dad

A2-A3, B1, C3 ida do **codex-dad** jako duze integracje worker/validator. A1, B2-B3, C1-C2 robi **codex-main**.
