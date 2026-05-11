## Sprint 27 - Behavioral Attack Scenarios

**Goal:** Dodac scenariusze atakow na zachowanie aplikacji: kolejnosc krokow, replay, race conditions, cache/auth drift i forced browsing.

Ten sprint odchodzi od payload-centric testing. System zaczyna sprawdzac logike biznesowa i stan aplikacji w sposob kontrolowany, powtarzalny i bezpieczny.

### Architektura - dokumenty referencyjne

```bash
DAD_PROMPT="Read /mnt/d/BreachForge/docs/architecture/attack-engine.md and security-constraints.md. Extract constraints for stateful probes, concurrency, rate limits, mutation safety, and replay. Bullets. Max 25 lines." bash ~/.claude/scripts/dad-exec.sh
```

### Workstream A - Stateful Flow Engine

| ID | Zadanie | Pliki | Testy | Definition of Done |
|---|---|---|---|---|
| A1 | Dodaj `FlowTrace` z ordered steps, pre/post snapshots i identity context | `execution_plane/planner/flows.py` (new) | planner tests | flow da sie odtworzyc deterministycznie |
| A2 | Mapuj crawl events do candidate flows: create, edit, approve, export, delete, checkout | crawler/planner integration | integration tests | AssetMap zawiera flow hints |
| A3 | Flow mutation policy: mutating steps wymagaja safe fixture albo explicit allowlist | planner guard | guardrail tests | default fail-closed dla mutacji |

### Workstream B - Scenario Templates

| ID | Zadanie | Pliki | Testy | Definition of Done |
|---|---|---|---|---|
| B1 | Step skipping: final action bez required intermediate state | `execution_plane/planner/playbooks/step_skipping.yaml` (new) | corpus tests | wykrywa accepted skipped step tylko przy proof |
| B2 | Replay after state change: powtorzenie requestu po complete/cancel/logout | `execution_plane/planner/playbooks/replay_state_change.yaml` (new) | corpus tests | replay finding wymaga roznicy stanu |
| B3 | Race templates: double-submit, TOCTOU, idempotency bypass | `execution_plane/planner/playbooks/race_conditions.yaml` (new) | worker/validator tests | burst ma twardy limit i repeatability policy |
| B4 | Cache/auth drift: authenticated response dostepna po logout/anon albo cross-user cache | `execution_plane/planner/playbooks/cache_auth_drift.yaml` (new) | corpus tests | body harvesting ograniczony i redacted |
| B5 | Forced browsing: high-value paths z AssetMap i word hints, tylko in-scope | `execution_plane/planner/playbooks/forced_browsing.yaml` (new) | planner tests | generuje bounded read-only probes |

### Workstream C - Validators & Evidence

| ID | Zadanie | Pliki | Testy | Definition of Done |
|---|---|---|---|---|
| C1 | State delta validator dla step skipping/replay | `execution_plane/validator/state_diff.py` | validator tests | finding wymaga pre/post delta |
| C2 | Race validator wymaga reprodukcji zgodnie z profilem | validator strategy | tests | pojedynczy burst nie wystarcza do High confidence |
| C3 | Evidence pack dla behavioral chains | `storage/evidence/` + reporting hooks | reporting tests | raport pokazuje sekwencje, nie raw sensitive body |

### Guardrails

- Race probes maja niski domyslny concurrency cap i sa rate-limited per scan/domain.
- Mutacje sa wykonywane tylko na safe fixture albo jawnie dozwolonym flow.
- Forced browsing nie wychodzi poza target domains i ma bounded path budget.
- Behavioral validators musza miec repeatability albo jasny state delta.

### Weryfikacja

```bash
python -m pytest tests/unit/execution_plane/workers/ -q
python -m pytest tests/unit/execution_plane/validator/ -q
python -m pytest tests/corpus/ -q
python -m pytest tests/unit/ -q
```

### Global acceptance criteria

- [ ] Minimum 5 behavioral playbookow dziala end-to-end.
- [ ] Mutating scenarios sa fail-closed bez safe fixture.
- [ ] Race condition finding wymaga reprodukcji.
- [ ] Raport pokazuje flow sequence i evidence references.

### Post-sprint: przeglad skillow

Czy pojawil sie nowy powtarzalny pattern? Jesli tak - zaktualizuj lub dodaj skill w `.workflow/skills/` przed zamknieciem sprintu. Regula: pattern >= 2x -> skodyfikuj.
