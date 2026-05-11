## Sprint 32 - BFLA (Broken Function Level Authorization)

**Goal:** Wykrywanie sytuacji gdy nisko-uprzywilejowane konto wywoluje funkcje zarezerwowane dla administratorow lub innych ról — przez HTTP verb manipulation i direct function access.

OWASP API5. Czesto pomijane podczas testow bo wymaga znajomosci hierarchii rol. BreachForge ma identities z roznych ról — to naturalne srodowisko testowe.

### Architektura - dokumenty referencyjne

```bash
DAD_PROMPT="Read /mnt/d/BreachForge/docs/architecture/attack-engine.md and auth-architecture.md. Extract: identity context structure, role hierarchy, multi-identity probes, safe fixture rules. Bullets. Max 25 lines." bash ~/.claude/scripts/dad-exec.sh
```

### Workstream A - BFLA Rule & Planner

| ID | Zadanie | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| A1 | Reguła wykrywajaca admin-path patterns: `/admin/`, `/internal/`, `/management/`, `/superuser/`, `/ops/`, `/system/` oraz role-restricted HTTP verbs (DELETE, PUT na resource endpoints) | `execution_plane/planner/rules/bfla.py` (new) | **codex-dad** | planner unit tests | rule klasyfikuje admin paths jako high-priority BFLA candidates |
| A2 | Logika cross-role probing: dla kazdego admin-candidate identities z roli `user`/`viewer`/`guest` wykonuja ten sam request co `admin`/`manager` | `execution_plane/planner/rules/bfla.py` | **codex-dad** | planner tests | candidate ma `required_identities` z min. 2 rolami |
| A3 | Playbook admin function access — non-admin token probe na admin-path endpoints | `execution_plane/planner/playbooks/bfla_admin_function.yaml` (new) | codex-main | corpus tests | max_requests: 2 (baseline admin, probe user) |
| A4 | Playbook HTTP verb escalation — GET jest dozwolone, ale DELETE/PUT/PATCH tez dziala bez admin roli | `execution_plane/planner/playbooks/bfla_http_verb.yaml` (new) | codex-main | corpus tests | max_requests: 3, safe verbs only na safe fixtures |

### Workstream B - BFLA Validator Strategy

| ID | Zadanie | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| B1 | Strategia `bfla`: proof `differential` — response od low-priv identity na admin-only endpoint vs expected 403/404; confidence 0.92 gdy low-priv = 200 z treсią | `execution_plane/validator/strategies/bfla.py` (new) | **codex-dad** | validator unit tests | false positive guard: 401 redirect != BFLA |
| B2 | HTTP verb BFLA: DELETE/PUT bez autoryzacji = absolute proof; sprawdza czy response nie jest 405 (method not allowed) ale 200/204 | `execution_plane/validator/strategies/bfla.py` | **codex-dad** | validator tests | confidence 0.95 przy 200 na DELETE bez admin token |
| B3 | False positive filter: rozroznia "endpoint nie istnieje" (404 dla obu ról) od "dostep zabroniony dla admina tez" | `execution_plane/validator/strategies/bfla.py` | **codex-dad** | fp filter tests | FP rate < 5% na corpus |
| B4 | Rejestracja strategii | `execution_plane/validator/registry.py` (edit < 5 linii) | Claude | brak | klucz `bfla` dostepny |

### Workstream C - Tests & Corpus

| ID | Zadanie | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| C1 | Unit testy: admin path access by user, verb escalation, FP rejection (404 case, 405 case) | `tests/unit/execution_plane/validator/test_bfla_strategy.py` (new) | codex-main | pytest -q | wszystkie przypadki pokryte |
| C2 | Corpus: mock API z `/admin/users` dostepnym dla roli `user` oraz DELETE bez uprawnien | `tests/corpus/bfla_corpus.py` (new) | codex-main | corpus tests | BFLA finding z confidence 0.92+ |

### Guardrails

- DELETE/PUT probes sa wykonywane TYLKO na safe fixtures oznaczonych w scan config jako `mutation_allowed`.
- BFLA probe nie usuwa danych — gdy metoda DELETE musi byc uzyto, fixture tworzy tymczasowy zasob przed probe i po nim sprawdza czy nadal istnieje.
- Cross-role testing wymaga co najmniej 2 aktywnych identity snapshots w sesji — brak identity = skip tego playbooку.
- Admin-path patterns sa konfigurowalnym listą — domyslna lista pokrywa typowe wzorce REST.

### Weryfikacja

```bash
"/c/Program Files/Python312/python.exe" -m pytest tests/unit/execution_plane/validator/test_bfla_strategy.py -q
"/c/Program Files/Python312/python.exe" -m pytest tests/unit/execution_plane/planner/ -q
"/c/Program Files/Python312/python.exe" -m pytest tests/corpus/ -q
"/c/Program Files/Python312/python.exe" -m pytest tests/unit/ -q
```

### Global acceptance criteria

- [ ] Rule wykrywa admin-path patterns i tworzy cross-role candidates.
- [ ] Strategia rozroznia BFLA od "endpoint nie istnieje" i "method not allowed".
- [ ] DELETE probe wymaga safe fixture — brak fixture = skip.
- [ ] Finding zawiera: wywolana rola, oczekiwany status, otrzymany status, dowod body.
- [ ] Cross-role probe wymaga min. 2 identity snapshots.

### Podział pracy — codex-dad

Wiekszosc pracy (A1, A2, B1, B2, B3): codex-dad — sensitive domain (role hierarchy, DELETE probes).
Playbooki i testy (A3, A4, C1, C2): codex-main.
Rejestracja (B4): Claude.

### Post-sprint: przeglad skillow

Czy pojawil sie nowy powtarzalny pattern? Jesli tak - zaktualizuj lub dodaj skill w `.workflow/skills/`. Regula: pattern >= 2x -> skodyfikuj.
