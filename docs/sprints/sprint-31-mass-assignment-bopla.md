## Sprint 31 - Mass Assignment & BOPLA (API3)

**Goal:** Wykrywanie mass assignment (zapis nieautoryzowanych pol przez PUT/PATCH/POST) oraz Broken Object Property Level Authorization (roznica uprawnien na poziomie wlasciwosci obiektu).

OWASP API3 — bardzo czesta luka w aplikacjach ktore auto-binduja request body do modeli danych. Przyklad: `{"role": "admin"}` w payload aktualizacji profilu.

### Architektura - dokumenty referencyjne

```bash
DAD_PROMPT="Read /mnt/d/BreachForge/docs/architecture/attack-engine.md and validation-model.md. Extract: differential proof mechanics, body schema comparison, identity context in probes. Bullets. Max 25 lines." bash ~/.claude/scripts/dad-exec.sh
```

### Workstream A - Mass Assignment Rule & Planner

| ID | Zadanie | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| A1 | Reguła wykrywajaca PUT/PATCH/POST endpointy — buduje probe z rozszerzonymi polami: `role`, `admin`, `is_admin`, `verified`, `balance`, `credits`, `permission`, `status`, `plan`, `subscription_tier` | `execution_plane/planner/rules/mass_assignment.py` (new) | **codex-dad** | planner unit tests | rule generuje candidates dla kazdego write endpoint |
| A2 | Reguła excessive data exposure — porownuje response schema z request schema (pola zwracane > pola w spec) | `execution_plane/planner/rules/mass_assignment.py` | **codex-dad** | planner tests | candidate generowany gdy response ma > 30% wiecej pol niz spec |
| A3 | Playbook mass assignment probe — wysyla PUT/PATCH z hidden privilege fields, sprawdza czy zostaly zaakceptowane przez compare GET | `execution_plane/planner/playbooks/mass_assignment_probe.yaml` (new) | codex-main | corpus tests | max_requests: 3 (GET baseline, PUT z extra fields, GET verify) |
| A4 | Playbook excessive exposure — GET endpoint, porownaj response z OpenAPI schema jesli dostepna | `execution_plane/planner/playbooks/excessive_data_exposure.yaml` (new) | codex-main | corpus tests | max_requests: 1, read-only |

### Workstream B - BOPLA Validator Strategy

| ID | Zadanie | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| B1 | Strategia `mass_assignment`: proof `differential` — GET przed vs GET po write z extra fields; checking czy zakazane pola zmienly sie w response | `execution_plane/validator/strategies/mass_assignment.py` (new) | **codex-dad** | validator unit tests | confidence 0.92 gdy extra field zmienil sie w response post-write |
| B2 | Strategia `excessive_exposure`: proof `absolute` — response zawiera pola oznaczone jako sensitive: `password_hash`, `salt`, `internal_id`, `secret_key`, `ssn`, `credit_card` | `execution_plane/validator/strategies/mass_assignment.py` | **codex-dad** | validator tests | confidence 0.87 przy sensitive field hit |
| B3 | Rollback guard: po mass assignment probe wysyla reverse request (original value) gdy modul ma `safe_fixture: true` | `execution_plane/validator/strategies/mass_assignment.py` | **codex-dad** | guardrail tests | rollback jest logowany w evidence |
| B4 | Rejestracja strategii | `execution_plane/validator/registry.py` (edit < 5 linii) | Claude | brak | klucze `mass_assignment`, `excessive_exposure` dostepne |

### Workstream C - Tests & Corpus

| ID | Zadanie | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| C1 | Unit testy: hidden field accepted, excessive fields in response, rollback trigger | `tests/unit/execution_plane/validator/test_mass_assignment_strategy.py` (new) | codex-main | pytest -q | wszystkie scenariusze pokryte |
| C2 | Corpus: mock API ktory akceptuje `is_admin: true` w PATCH /profile | `tests/corpus/mass_assignment_corpus.py` (new) | codex-main | corpus tests | finding wygenerowany z confidence 0.92 |

### Guardrails

- Write probes sa wykonywane TYLKO na safe fixtures lub gdy endpoint ma jawny `allow_mutation: true` w scan config — domyslnie tylko GET do weryfikacji.
- Po kazdej write probe strategia emituje rollback request (przywrocenie wartosci).
- Sensitive pola w response sa redagowane w raporcie — tylko typy pol sa logowane, nie wartosci.
- Mass assignment probe nie wysyla payloadow z wartosciami ktore moga uszkodzic stan aplikacji (tylko boolean flags i incrementalne wartosci).

### Weryfikacja

```bash
"/c/Program Files/Python312/python.exe" -m pytest tests/unit/execution_plane/validator/test_mass_assignment_strategy.py -q
"/c/Program Files/Python312/python.exe" -m pytest tests/unit/execution_plane/planner/ -q
"/c/Program Files/Python312/python.exe" -m pytest tests/corpus/ -q
"/c/Program Files/Python312/python.exe" -m pytest tests/unit/ -q
```

### Global acceptance criteria

- [ ] Rule wykrywa write endpointy i rozszerza probe o hidden privilege fields.
- [ ] Strategia potwierdza mass assignment przez pre/post GET comparison.
- [ ] Excessive exposure detekcja dziala bez write (read-only GET).
- [ ] Rollback jest wykonywany automatycznie po kazda mutacji.
- [ ] Sensitive field values nie sa w logach — tylko nazwy pol.

### Podział pracy — codex-dad

Wiekszosc pracy (A1, A2, B1, B2, B3): codex-dad — wrażliwa domena (write probes, rollback logic).
Playbooki i testy (A3, A4, C1, C2): codex-main.
Rejestracja (B4): codex-main.

### Post-sprint: przeglad skillow

Czy pojawil sie nowy powtarzalny pattern? Jesli tak - zaktualizuj lub dodaj skill w `.workflow/skills/`. Regula: pattern >= 2x -> skodyfikuj.
