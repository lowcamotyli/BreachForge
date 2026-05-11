## Sprint 25 - Hypothesis Engine

**Goal:** Po crawl'u system generuje, ocenia i aktualizuje hipotezy ataku tak, jak robi to doswiadczony pentester.

Ten sprint buduje warstwe "dlaczego warto sprawdzic X": parametry, endpointy, flow, role, statusy i zmiany odpowiedzi zamieniaja sie w priorytetyzowane hipotezy.

### Architektura - dokumenty referencyjne

```bash
DAD_PROMPT="Read /mnt/d/BreachForge/docs/architecture/attack-engine.md and validation-model.md. Extract constraints for planner signals, validator proof, and safe prioritization. Bullets. Max 25 lines." bash ~/.claude/scripts/dad-exec.sh
```

### Workstream A - Signal Extraction

| ID | Zadanie | Pliki | Testy | Definition of Done |
|---|---|---|---|---|
| A1 | Dodaj `AttackSignal` dataclass dla endpoint, param, identity, response_delta, state_delta | `execution_plane/planner/hypotheses.py` (new) | planner unit tests | signals sa normalizowane i serializowalne |
| A2 | Ekstrahuj parametry wysokiego ryzyka: id, user_id, org_id, tenant_id, role, status, price, redirect, callback | hypothesis helper | unit tests | ranking parametrow deterministyczny |
| A3 | Ekstrahuj flow hints z AssetMap: create/update/delete/approve/export/admin | hypothesis helper | unit tests | endpointy dostaja opisane intent hints |

### Workstream B - Hypothesis Generation

| ID | Zadanie | Pliki | Testy | Definition of Done |
|---|---|---|---|---|
| B1 | Dodaj `AttackHypothesis` z type, target, rationale, required_identities, candidate_playbooks | `execution_plane/planner/hypotheses.py` | unit tests | hipoteza jest explainable |
| B2 | Generator BOLA/IDOR hypotheses | `execution_plane/planner/hypothesis_generators/bola.py` (new) | unit tests | zasoby z id generuja cross-user candidates |
| B3 | Generator privilege/workflow hypotheses | `execution_plane/planner/hypothesis_generators/workflow.py` (new) | unit tests | approve/status/admin flow generuja testy logiki |
| B4 | Generator secret-impact hypotheses | `execution_plane/planner/hypothesis_generators/secrets.py` (new) | unit tests | secret metadata laczy sie z blast-radius playbookiem |

### Workstream C - Prioritization & Feedback

| ID | Zadanie | Pliki | Testy | Definition of Done |
|---|---|---|---|---|
| C1 | Scoring hipotez: impact x likelihood x reachability x cost x safety | `execution_plane/planner/hypothesis_ranker.py` (new) | unit tests | top-k stabilne przy tym samym input |
| C2 | Feedback loop: probe outcome aktualizuje confidence hipotezy | planner integration | integration tests | nieudane probe'y obnizaja priorytet |
| C3 | Codex CLI advisory hook tylko dla ranking/rationale | `control_plane/codex_analyst.py` | mock tests | sugestie sa advisory i filtrowane politykami |

### Guardrails

- Hipoteza nie jest findingiem.
- Hypothesis ranker nie moze omijac scope/rate/safety caps.
- LLM/Codex output jest traktowany jako nieufna sugestia i przechodzi walidacje polityk.
- Brak raw credentials w rationale, promptach i decision log.

### Weryfikacja

```bash
python -m pytest tests/unit/execution_plane/planner/ -q
python -m pytest tests/unit/control_plane/test_codex_analyst.py -q
python -m pytest tests/unit/ -q
```

### Global acceptance criteria

- [ ] AssetMap generuje hipotezy dla BOLA, privilege/workflow i secret-impact.
- [ ] Kazda hipoteza ma rationale, required identities i powiazany playbook.
- [ ] Runtime feedback zmienia ranking bez restartu skanu.
- [ ] Codex CLI nie ma authority do tworzenia findingow.

### Post-sprint: przeglad skillow

Czy pojawil sie nowy powtarzalny pattern? Jesli tak - zaktualizuj lub dodaj skill w `.workflow/skills/` przed zamknieciem sprintu. Regula: pattern >= 2x -> skodyfikuj.
