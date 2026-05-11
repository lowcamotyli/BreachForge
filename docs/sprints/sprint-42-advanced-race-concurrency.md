## Sprint 42 - Advanced Race Conditions & Concurrency Exploits

**Goal:** Rozszerzenie istniejacych race condition testow o konkretne scenariusze eksploitacji: limit override (zakup > allowed), double-spend w transferach, idempotency key bypass i distributed lock evasion.

Istniejacy `race_condition.py` wykrywa anomalie — ten sprint buduje ukierunkowane exploitacje konkretnych wartosciowych scenariuszy ktore maja bezposredni impact finansowy.

### Architektura - dokumenty referencyjne

```bash
DAD_PROMPT="Read /mnt/d/BreachForge/docs/architecture/attack-engine.md and security-constraints.md. Extract: current race_condition strategy mechanics, concurrency limits, burst_concurrency cap, reproducibility requirements. Bullets. Max 25 lines." bash ~/.claude/scripts/dad-exec.sh
```

### Workstream A - Advanced Race Rules & Planner

| ID | Zadanie | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| A1 | Reguła advanced race: wykrywa endpointy z limitami: `limit`, `max_per_user`, `one_per_account`, `quota`, `balance` — generuje limit-override candidates | `execution_plane/planner/rules/race_advanced.py` (new) | **codex-dad** | planner tests | rule rankuje limit-bearing params jako high-priority race candidates |
| A2 | Transfer/payment endpoint detection: `transfer`, `withdraw`, `debit`, `purchase`, `checkout`, `redeem` — double-spend candidates | `execution_plane/planner/rules/race_advanced.py` | **codex-dad** | planner tests | transfer endpoints sa oznaczone jako double-spend candidates |
| A3 | Idempotency endpoint detection: endpointy z `Idempotency-Key` header lub `idempotency_key` param — reuse candidates | `execution_plane/planner/rules/race_advanced.py` | **codex-dad** | planner tests | idempotency pattern wykryty |

### Workstream B - Advanced Race Validator Strategies

| ID | Zadanie | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| B1 | Strategia `limit_override_race`: N concurrent requests na limit-capped endpoint — proof gdy odpowiedzi wskazuja na akceptacje > allowed (N success > 1 gdzie only 1 allowed) | `execution_plane/validator/strategies/race_advanced.py` (new) | **codex-dad** | validator tests | burst_concurrency: max 5, proof wymaga 2+ success responses; confidence 0.92 |
| B2 | Strategia `double_spend`: 2 concurrent identical transfer requests — proof gdy oba zwracaja success i sum > original balance | `execution_plane/validator/strategies/race_advanced.py` | **codex-dad** | validator tests | burst_concurrency: 2, wymaga safe fixture z temporary balance; confidence 0.94 |
| B3 | Strategia `idempotency_bypass`: wysyla ten sam request z tym samym Idempotency-Key ale innymi parametrami — proof gdy serwer wykonuje drugi request zamiast zwrocic cached response | `execution_plane/validator/strategies/race_advanced.py` | **codex-dad** | validator tests | proof przez response diff na re-use; confidence 0.88 |
| B4 | Strategia `distributed_lock_evasion`: szybkie cancel→re-acquire w petli — proof gdy zasob moze byc zarezerwowany wiecej razy niz inventory pozwala | `execution_plane/validator/strategies/race_advanced.py` | **codex-dad** | validator tests | max 3 cycles, safe fixture; confidence 0.87 |
| B5 | Reproducibility requirement: wszystkie advanced race findings wymagaja 2. reprodukcji zanim confidence > 0.85 | `execution_plane/validator/strategies/race_advanced.py` | **codex-dad** | tests | single burst = capped na 0.70; 2x = pełna confidence |
| B6 | Rejestracja strategii | `execution_plane/validator/registry.py` (edit < 5 linii) | Claude | brak | klucze `limit_override_race`, `double_spend`, `idempotency_bypass`, `distributed_lock_evasion` |

### Workstream C - Playbooks & Tests

| ID | Zadanie | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| C1 | Playbook limit override | `execution_plane/planner/playbooks/limit_override_race.yaml` (new) | codex-main | corpus tests | burst_concurrency: 5, max_requests: 10 |
| C2 | Playbook double-spend | `execution_plane/planner/playbooks/double_spend.yaml` (new) | codex-main | corpus tests | burst_concurrency: 2, wymaga safe fixture balance |
| C3 | Playbook idempotency bypass | `execution_plane/planner/playbooks/idempotency_bypass.yaml` (new) | codex-main | corpus tests | max_requests: 4 (setup, send x2, verify) |
| C4 | Unit testy wszystkich strategii z reprodukcja requirement | `tests/unit/execution_plane/validator/test_race_advanced_strategy.py` (new) | codex-main | pytest -q | coverage > 90%, reproducibility logika przetestowana |
| C5 | Corpus: mock limiter API, mock transfer endpoint, mock idempotency store | `tests/corpus/race_advanced_corpus.py` (new) | codex-main | corpus tests | 4 race findingi z odpowiednimi confidence |

### Guardrails

- Limit override: max burst_concurrency 5 — nie sluzy do pelnego stress testu.
- Double-spend: WYMAGA safe fixture z tymczasowym saldem — nie na prawdziwych kontach.
- Idempotency bypass: idempotency key jest generowany losowo per probe — nie reuzywamy kluczy z prawdziwych transakcji.
- Reproducibility: single burst nie wystarczy — dwa razy lub confidence jest cappowana (chroni przed false positives pod loadem serwera).
- Wszystkie burst probes sa oznaczone w EvidenceStore z `probe_type: race_concurrent`.

### Weryfikacja

```bash
"/c/Program Files/Python312/python.exe" -m pytest tests/unit/execution_plane/validator/test_race_advanced_strategy.py -q
"/c/Program Files/Python312/python.exe" -m pytest tests/unit/ -q
"/c/Program Files/Python312/python.exe" -m pytest tests/corpus/ -q
```

### Global acceptance criteria

- [ ] Limit override finding zawiera: ile requestow wyslano, ile zaakceptowano, allowed limit.
- [ ] Double-spend finding zawiera: oba responses, suma vs original balance.
- [ ] Idempotency bypass finding zawiera: klucz, pierwsza vs druga operacja.
- [ ] Reproducibility: single burst finding cappowany na 0.70 confidence.
- [ ] Wszystkie advanced race scenarios wymagaja safe fixture lub explicit allowlist.

### Podział pracy — codex-dad

Wiekszosc pracy (A1, A2, A3, B1, B2, B3, B4, B5): codex-dad — sensitive domain (financial endpoints, concurrency).
Playbooki i testy (C1–C5): codex-main.
Rejestracja (B6): Claude.

### Post-sprint: przeglad skillow

Czy pojawil sie nowy powtarzalny pattern? Jesli tak - zaktualizuj lub dodaj skill w `.workflow/skills/`. Regula: pattern >= 2x -> skodyfikuj.
