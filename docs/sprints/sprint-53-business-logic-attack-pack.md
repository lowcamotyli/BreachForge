## Sprint 53 - Business Logic Attack Pack

**Goal:** Dodac ataki business logic oparte o stan aplikacji: wartosc, limity, approvale, workflow i finansowe skutki.

### Architektura - dokumenty referencyjne

```bash
DAD_PROMPT="cd /mnt/d/BreachForge && Read docs/architecture/attack-engine.md and docs/architecture/validation-model.md. Extract: safe mutation policy, state diff validation, business logic attack boundaries. Bullets. Max 25 lines." bash ~/.claude/scripts/dad-exec.sh
```

### Workstream A - Attack classes

| ID | Klasa | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| A1 | Coupon stacking / discount abuse | `planner/rules/business_logic_advanced.py`, `validator/strategies/business_logic_advanced.py` | codex-dad | corpus tests | wykrywa wielokrotne rabaty |
| A2 | Negative quantity/value | same | codex-dad | corpus tests | potwierdza odrzucenie albo state impact |
| A3 | Price tampering | same | codex-dad | corpus tests | cena w stanie koncowym jest walidowana |
| A4 | Inventory reservation abuse | same | codex-dad | corpus tests | wykrywa hold bez zakupu/limit bypass |
| A5 | Approval bypass / step skipping | `workflow_abuse.py`, playbooks | codex-dad | workflow tests | pomija wymagany krok i potwierdza state |

### Workstream B - Safe execution model

| ID | Zadanie | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| B1 | Mutating business logic wymaga explicit scan config flag | `api/models/requests.py`, `attack_worker.py` | codex-main | guardrail tests | default fail-closed |
| B2 | Kazdy business task ma rollback/read-after-write plan albo observe-only | planner/playbooks | codex-main | playbook tests | task nie jest destructive by default |
| B3 | State diff required dla high confidence | validator strategies | codex-main | validator tests | status-only finding nie przechodzi |

### Workstream C - Corpus and lab fixtures

| ID | Zadanie | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| C1 | Corpus flows dla cart/checkout/refund/approval | `tests/corpus/business_logic_corpus.py` | codex-main | corpus | realistyczne edge case'y |
| C2 | Negative controls: poprawna aplikacja nie generuje findingow | tests corpus | codex-main | corpus | false positives ograniczone |
| C3 | Report sekcja "business impact" | `control_plane/reporting.py` | codex-main | reporting tests | opis skutku, nie tylko technicznej klasy |

### Guardrails

- Production-safe mode blokuje destructive mutations.
- Business findings wymagaja skutku w stanie lub jednoznacznego differential.
- Nie testowac pieniedzy/zakupow realnych bez explicit target policy.

### Weryfikacja

```bash
python -m pytest tests/corpus/business_logic_corpus.py -q
python -m pytest tests/unit/execution_plane/validator/test_business_logic_advanced_strategy.py -q
python -m pytest tests/unit/execution_plane/planner/ -q
python -m pytest tests/unit/ -q
```

### Global acceptance criteria

- [ ] 5 klas business logic ma planner + validator + corpus.
- [ ] High confidence wymaga state proof.
- [ ] Guardrails blokuja destructive default.
- [ ] Raport opisuje realny business impact.

### Podzial pracy - codex-dad

A1-A5 ida do **codex-dad** jako duzy attack pack. B-C robi **codex-main**.
