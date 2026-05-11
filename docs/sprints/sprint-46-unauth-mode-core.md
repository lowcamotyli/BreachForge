## Sprint 46 - Unauth Mode Core Integration

**Goal:** Chirurgiczne odblokowanie unauth mode w istniejacych komponentach — minimalne zmiany, maksymalny efekt. Po tym sprincie tool skanuje bez credentials end-to-end.

### Stan wyjsciowy — co JUZ dziala bez auth (0 zmian)

| Komponent | Status |
|---|---|
| Wszystkie validator strategies | ✅ pattern-matchery, nie sprawdzaja auth |
| Planner rules: misconfiguration, sensitive_exposure, injection, tenant_isolation, race_templates, workflow_abuse | ✅ brak zaleznosci od sesji |
| AuthManager `auth_type="none"` | ✅ branch juz istnieje, produkuje empty SessionSnapshot |
| Crawler (engine.py) | ✅ dziala z empty SessionSnapshot, auto-wykrywa unauth endpoints |
| Playbooki: workflow_abuse, secret_to_impact, race_conditions, replay_state_change, step_skipping | ✅ brak `auth_required` |
| forced_browsing.yaml | ✅ ma JUZ `identity_selector: anonymous_user` w step 3 |

**Tool jest 60% unauth-ready dzisiaj. Ten sprint domknie reszte.**

### Architektura — dokumenty referencyjne

```bash
DAD_PROMPT="Read /mnt/d/BreachForge/docs/architecture/attack-engine.md and security-constraints.md. Extract: AuthContext schema, SessionSnapshot fields, worker isolation invariants, dispatcher task execution flow. Bullets. Max 25 lines." bash ~/.claude/scripts/dad-exec.sh
```

### Workstream A — dispatcher.py: usun hard crash bez AuthContext

**BLOKER KRYTYCZNY.** Bez tej zmiany zadne zadanie nie wykonuje sie bez sesji.

| ID | Zadanie | Plik | Linia | Worker | Testy |
|---|---|---|---|---|---|
| A1 | Zamien `raise RuntimeError("Auth context is not initialized")` na graceful fallback: brak auth_context → `create_empty_auth_context(scan_id)` z `auth_type="none"` | `execution_plane/workers/dispatcher.py` | **121-122** | **codex-dad** | dispatcher unit tests |
| A2 | `create_empty_auth_context()`: produkuje AuthContext z `auth_type="none"`, empty credentials — reuzywaj logike z `AuthManager._empty_snapshot()` | `execution_plane/workers/dispatcher.py` (nowa funkcja pomocnicza) | — | **codex-dad** | unit tests |
| A3 | Pomijaj auth health check gdy `auth_context.auth_type == "none"` — health check nie ma sensu dla empty context | `execution_plane/workers/dispatcher.py` | ~line 174-182 area | **codex-dad** | guardrail tests |

**Definition of Done:** dispatcher nie crashuje gdy brak AuthContext w DB — tworzy empty i kontynuuje.

---

### Workstream B — attack_worker.py: empty session bez GuardrailViolation

| ID | Zadanie | Plik | Linia | Worker | Testy |
|---|---|---|---|---|---|
| B1 | Zmien guardrail line 169: `raise GuardrailViolation("session is required")` → gdy `unauth_mode=True` w scan config: uzyj empty SessionSnapshot zamiast crash | `execution_plane/workers/attack_worker.py` | **169** | **codex-dad** | worker guardrail tests |
| B2 | Zmien guardrail line 166-167: brak auth_manager + `identity_role=None` + `identity_name=None` → dozwolone w unauth mode (anonymous probe) | `execution_plane/workers/attack_worker.py` | **166-167** | **codex-dad** | worker tests |
| B3 | Dodaj `identity_selector: "anonymous"` jako valid selector — zwraca empty headers/cookies (analogicznie do impact probe na line 318-319) | `execution_plane/workers/attack_worker.py` | ~318-319 area | **codex-dad** | worker tests |

**Definition of Done:** worker wykonuje probe z empty session bez wyjatku — response jest zarejestrowany normalnie.

---

### Workstream C — Planner rules: 3 chirurgiczne zmiany

| ID | Zadanie | Plik | Linia | Worker | Testy |
|---|---|---|---|---|---|
| C1 | Dodaj `requires_auth = False` i usun filtr `endpoint.auth_required` z matches() — BOLA rule dziala na publicznych endpointach z ID params | `execution_plane/planner/rules/bola.py` | **21** | Claude | planner tests |
| C2 | Usun fallback `return endpoint.auth_required` — rate_limit rule matchuje przez path-hints, nie przez auth flag | `execution_plane/planner/rules/rate_limit_abuse.py` | **26** | Claude | planner tests |
| C3 | Dodaj `requires_auth = False` na: injection.py, misconfiguration.py, sensitive_exposure.py (rule), tenant_isolation.py, workflow_abuse.py, rate_limit_abuse.py, bola.py, session_misuse.py, privilege_escalation.py | wszystkie rules/*.py | class attr | Claude | brak (atrybut) |
| C4 | Dodaj `requires_auth = True` na: auth_bypass.py, jwt_attack.py — te wymagaja sesji z definicji | `rules/auth_bypass.py`, `rules/jwt_attack.py` | class attr | Claude | brak (atrybut) |

**Definition of Done:** kazdy rule ma atrybut `requires_auth`; planner filtruje w unauth mode.

---

### Workstream D — AttackPlanner: filtr unauth_mode

| ID | Zadanie | Plik | Worker | Testy |
|---|---|---|---|---|
| D1 | W `AttackPlanner.generate_tasks()`: gdy `scan.unauth_mode = True`, pomijaj rules z `requires_auth = True` | `execution_plane/planner/attack_planner.py` | **codex-dad** | planner integration tests |
| D2 | Dodaj `unauth_mode: bool = False` do ScanConfig (scan schema) i propaguj do orchestratora i planera | `api/models/requests.py` + `storage/db/models.py` (jesli scan config jest w DB) | **codex-dad** | API tests |

**Definition of Done:** `POST /scans` z `{"unauth_mode": true}` uruchamia skan bez auth_bootstrap.

---

### Workstream E — Validator: sensitive_exposure confidence fix

| ID | Zadanie | Plik | Linia | Worker | Testy |
|---|---|---|---|---|---|
| E1 | Usun penalty za brak auth headerow z confidence scoring — brak sesji NIE powinien obnizac confidence dla exposure findingu (linia 60-65 juz analizuje request_has_auth, logika jest odwrotna) | `execution_plane/validator/strategies/sensitive_exposure.py` | **60-65** | Claude | validator tests |
| E2 | Dodaj: jesli `probe_type == "unauth_baseline"` → confidence += 0.03 (unauth exposure jest GORSZA niz auth, bo dane sa dostepne publicznie) | `execution_plane/validator/strategies/sensitive_exposure.py` | po line 65 | Claude | validator tests |

---

### Workstream F — Playbooki: anonymous identity w 5 istniejacych

5 istniejacych playbookow uzywa `identity_selector: current_user` na wszystkich steps. Dla unauth mode: dodaj `auth_required: false` w preconditions i zmien identity_selector na `anonymous`.

| Playbook | Zmiana | Worker |
|---|---|---|
| `workflow_abuse.yaml` | preconditions: dodaj `auth_required: false`; steps: `current_user` → `anonymous` | codex-main |
| `race_conditions.yaml` | jak wyzej | codex-main |
| `replay_state_change.yaml` | jak wyzej | codex-main |
| `step_skipping.yaml` | jak wyzej | codex-main |
| `secret_to_impact.yaml` | jak wyzej + `auth_required: false` bo secret byl znaleziony bez sesji | codex-main |

**forced_browsing.yaml** — nie wymaga zmian, juz ma `anonymous_user` w step 3.

---

### Workstream G — Nowe playbooki czysto unauth

| ID | Playbook | Cel | Worker |
|---|---|---|---|
| G1 | `unauth_sensitive_exposure.yaml` | Skanuje wszystkie publiczne endpointy na credentials/PII/tokens — max_requests: 20, rate: 0.5 RPS, GET only | codex-main |
| G2 | `unauth_misconfiguration_full.yaml` | CORS + debug + headers + methods + verbose errors — 3 requestow na domain, read-only | codex-main |
| G3 | `unauth_rate_limit_public.yaml` | Burst na login/search/register/api bez credentials — max 10 req, staircase + burst patterns | codex-main |
| G4 | `unauth_injection_public_forms.yaml` | SQL + NoSQL + SSTI na publicznych formach — max 5 payloadow per endpoint, tylko read-only | codex-main |
| G5 | `unauth_graphql_recon.yaml` | Introspection + field suggestion — max 3 requestow, bez mutations | codex-main |

---

### Workstream H — Testy end-to-end

| ID | Zadanie | Plik | Worker | Testy |
|---|---|---|---|---|
| H1 | Integration test: pelny skan z `unauth_mode=True`, bez AuthContext w DB — musi przejsc przez FSM do complete bez crash | `tests/integration/test_unauth_scan_e2e.py` (new) | codex-main | pytest -q |
| H2 | Corpus test: mock target z publicznymi endpointami — unauth scan produkuje >= 3 findings (misconfiguration, sensitive_exposure, rate_limit) | `tests/corpus/unauth_mode_corpus.py` (new) | codex-main | corpus tests |
| H3 | Regression: istniejace auth testy nie regreduja — `auth_type="credentials"` nadal dziala | istniejace testy | codex-main | pytest tests/ -q |

---

### Guardrails

- Empty SessionSnapshot nie daje falszywych identity — brak cookies/headers, nie "jakis default user".
- Unauth mode NIE omija proof-gate (0.85 confidence) — bar jest identyczny.
- Worker isolation invariant: empty session → Redis-only writes, jak zawsze.
- `anonymous` identity selector nie moze byc uzywany dla attack types ktore potrzebuja roli (bola, privilege) — planner filtruje.

### Weryfikacja

```bash
"/c/Program Files/Python312/python.exe" -m pytest tests/integration/test_unauth_scan_e2e.py -q
"/c/Program Files/Python312/python.exe" -m pytest tests/unit/execution_plane/workers/ -q
"/c/Program Files/Python312/python.exe" -m pytest tests/unit/execution_plane/planner/ -q
"/c/Program Files/Python312/python.exe" -m pytest tests/corpus/unauth_mode_corpus.py -q
"/c/Program Files/Python312/python.exe" -m pytest tests/ -q
```

### Global acceptance criteria

- [ ] `POST /scans {"unauth_mode": true}` uruchamia pelny skan bez zadnych credentials.
- [ ] dispatcher.py nie crashuje gdy brak AuthContext — tworzy empty i kontynuuje.
- [ ] 8 rules ma `requires_auth = False`; 2 (auth_bypass, jwt_attack) maja `True`.
- [ ] AttackPlanner filtruje rules na podstawie `requires_auth` i trybu skanu.
- [ ] 5 istniejacych playbookow dziala z `identity_selector: anonymous`.
- [ ] sensitive_exposure confidence nie jest karana za brak auth — wrecz odwrotnie.
- [ ] End-to-end corpus test produkuje >= 3 unauth findings.
- [ ] Istniejace auth testy nie regreduja (auth mode nadal dziala).

### Podział pracy — codex-dad

Kluczowe: A1-A3, B1-B3, D1-D2, E1-E2 (dispatcher, worker, planner, validator) → **codex-dad** — sensitive domain + edycje duzych plikow.
Mniejsze: C1-C4 (1-2 linie per file, class attributes) → **Claude** bezposrednio.
Playbooki i testy: F1-F5, G1-G5, H1-H3 → **codex-main**.

### Sekwencja dispatchu (nie pelny parallel — sa zaleznosci)

```
Phase 1 (parallel):
  dad → dispatcher.py A1-A3 (bg)
  dad → attack_worker.py B1-B3 (bg)
  Claude → rules attributes C3-C4 (bezposrednio)

Phase 2 (po Phase 1):
  dad → attack_planner.py D1-D2 (bg)
  Claude → bola.py C1, rate_limit.py C2, sensitive_exposure.py E1-E2

Phase 3 (po Phase 2):
  main → playbook edits F1-F5 (bg)
  main → nowe playbooki G1-G5 (bg)
  main → testy H1-H3 (bg)

Phase 4:
  pytest full suite
```

### Post-sprint: przeglad skillow

Czy pojawil sie nowy powtarzalny pattern? Jesli tak - zaktualizuj lub dodaj skill w `.workflow/skills/`. Regula: pattern >= 2x -> skodyfikuj.
