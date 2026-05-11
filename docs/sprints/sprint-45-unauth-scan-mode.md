## Sprint 45 - Unauthenticated Scan Mode

**Goal:** Formalny tryb skanowania bez credentials: mapowanie ktore klasy ataków dzialaja bez sesji, ujednolicona logika "unauth-first" i wordlist-guided forced browsing z kontekstem z Sprintu 44.

Wielu uzytkownikow nie moze podac credentials (external pentest, bug bounty target bez konta, pre-engagement recon). Ten sprint buduje "unauth mode" jako first-class citizen.

### Architektura - dokumenty referencyjne

```bash
DAD_PROMPT="Read /mnt/d/BreachForge/docs/architecture/attack-engine.md and security-constraints.md and noise-reduction.md. Extract: attack class priority scoring, how planner selects rules without identity context, safe probe rules for unauth. Bullets. Max 25 lines." bash ~/.claude/scripts/dad-exec.sh
```

### Unauth Coverage Matrix (co działa bez sesji)

| Klasa ataku | Unauth coverage | Warunki |
|---|---|---|
| misconfiguration | **100%** | CORS, debug, headers, methods, verbose errors — read-only |
| sensitive_exposure | **80%** | Publiczne JSON, source maps, configi, cache — potrzebny tylko recon |
| security_headers | **100%** | Czysto read-only headers analysis |
| shadow_api / api_inventory | **90%** | JS mining, deprecated versions, API docs — tylko GET |
| rate_limit_abuse | **70%** | Login/search/public API — auth endpoints czesto publiczne |
| graphql_introspection | **95%** | Introspection nie wymaga auth (czesto) |
| injection (public forms) | **50%** | Tylko publiczne endpointy z paramami |
| workflow_abuse | **30%** | Modeled z HAR/OpenAPI bez sesji |
| bola / tenant_isolation | **15%** | Mozliwe tylko z HAR session cookies |
| auth_bypass | **10%** | Wymaga auth baseline |
| privilege_escalation | **10%** | Wymaga multi-identity |
| jwt_attack | **20%** | Potrzebny token (z JS/HAR/response leak) |

### Workstream A - Unauth Scan Orchestrator Mode

| ID | Zadanie | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| A1 | `unauth_mode: true` flag w scan config — orchestrator pomija auth_bootstrap phase, uruchamia tylko unauth-compatible rules | `control_plane/orchestrator.py` (edit) | **codex-dad** | FSM tests | FSM przechodzi bezposrednio do recon phase bez auth_bootstrap |
| A2 | Rule filter: kazdý `AttackRule` ma nowy atrybut `requires_auth: bool` — planner pomija `requires_auth=True` w unauth mode | `execution_plane/planner/attack_planner.py` (edit) | **codex-dad** | planner tests | requires_auth rules sa filtrowane; unauth rules sa aktywne |
| A3 | Oznaczenie wszystkich istniejacych rules `requires_auth` — misconfiguration/headers/shadow_api = False; bola/tenant/privilege = True | `execution_plane/planner/rules/*.py` (batch edit wszystkich plikow rules/) | **codex-dad** | planner tests | kazdy rule ma requires_auth atrybut |
| A4 | Unauth input fallback: jesli brak sesji ale jest HAR lub OpenAPI (Sprint 44) — orchestrator uzywa spec AssetMap zamiast crawl | `control_plane/orchestrator.py` | **codex-dad** | integration tests | scan dziala bez Playwright gdy dostepny HAR/OpenAPI |

### Workstream B - Wordlist-Guided Forced Browsing (Context-Aware)

| ID | Zadanie | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| B1 | Context-aware wordlist builder: z JS mining + robots.txt + AssetMap paths buduje wordlist specyficzny dla aplikacji (nazwy zasobow, versje, segmenty URL) | `execution_plane/planner/rules/shadow_api.py` (edit) | **codex-dad** | planner tests | wordlist zawiera kandydatow z kontekstu aplikacji, nie tylko generic paths |
| B2 | Wordlist generator: dolacza standardowe API-specific paths (`/api/v1`, `/actuator/health`, `/debug`, `/console`, `/.well-known/`) do kontekstowego wordlistu | `execution_plane/planner/rules/shadow_api.py` | **codex-dad** | tests | total wordlist capped na 100 paths per scan (configurowalny) |
| B3 | Playbook wordlist-forced-browsing — uzywa context-aware wordlist, bounded rate | `execution_plane/planner/playbooks/wordlist_forced_browsing.yaml` (new) | codex-main | corpus tests | max_requests: 100, rate: 1 RPS, read-only |

### Workstream C - Unauth Injection on Public Forms

| ID | Zadanie | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| C1 | Public form detector: w AssetMap oznacza endpointy dostepne bez auth ktore maja string params (login, search, contact, newsletter) jako `unauth_injectable: true` | `execution_plane/planner/rules/nosql_injection.py`, `ssti.py`, `injection.py` (edits) | **codex-dad** | planner tests | `unauth_injectable` candidates generowane dla publicznych formularzy |
| C2 | Unauth injection probe: injection strategia sprawdza `unauth_injectable` flage — jesli True, probe bez credentials; jesli False i unauth_mode — skip | `execution_plane/validator/strategies/nosql_injection.py`, `ssti.py` (edits) | **codex-dad** | validator tests | injection bez sesji na publicznych endpointach dziala |

### Workstream D - Unauth Sensitive Exposure Enhancement

| ID | Zadanie | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| D1 | Public response scanner: w unauth baseline (Sprint 44 E1) — automatycznie aplikuje sensitive_exposure strategię na kazdy publiczny endpoint bez potrzeby auth | `execution_plane/validator/strategies/sensitive_exposure.py` (edit) | **codex-dad** | validator tests | sensitive_exposure dziala na unauth_baseline responses |
| D2 | JavaScript secret scanner: podczas JS mining ekstrahuje hardcoded secrets (API keys, tokens, passwords) z bundle JS — uzywa patterns z sensitive_exposure strategii | `execution_plane/crawler/js_endpoint_extractor.py` (edit) | **codex-dad** | crawler tests | JS secret findings z confidence >= 0.85 |
| D3 | Playbook unauth-sensitive-exposure | `execution_plane/planner/playbooks/unauth_sensitive_exposure.yaml` (new) | codex-main | corpus tests | max_requests: 10, rate: 0.5 RPS, GET only |

### Workstream E - Reporting & Scan Summary dla Unauth Mode

| ID | Zadanie | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| E1 | Raport unauth mode ma sekcje "Untested attack classes (require auth)" z lista klas ktore zostaly pominiete i co by daly z credentials | `control_plane/reporting.py` (edit) | **codex-dad** | reporting tests | sekcja "Untested" zawiera: klasa, dlaczego wymaga auth, co dodac |
| E2 | Coverage percentage w raporcie: X% powierzchni ataku przetestowane w unauth mode vs pelny skan | `control_plane/reporting.py` | **codex-dad** | tests | coverage % jest w executive summary |

### Guardrails

- Unauth mode NIGDY nie probuje zgadywac haseł ani bruteforcing kont.
- Wordlist forced browsing ma twardy limit 100 requestow — nie sluzy do pelnego skanowania.
- Public form injection uzywa tych samych BEZPIECZNYCH payloadow co auth mode — bez RCE.
- JS secret scanner nie ujawnia pelnych znalezionych tokenow w logach — tylko typ i pierwsze 8 znakow.
- Unauth mode nie omija istniejacych safety caps — rate, scope, mutation constraints sa identyczne.

### Weryfikacja

```bash
"/c/Program Files/Python312/python.exe" -m pytest tests/unit/control_plane/test_orchestrator.py -q
"/c/Program Files/Python312/python.exe" -m pytest tests/unit/execution_plane/planner/ -q
"/c/Program Files/Python312/python.exe" -m pytest tests/unit/execution_plane/validator/ -q
"/c/Program Files/Python312/python.exe" -m pytest tests/unit/ -q
```

### Global acceptance criteria

- [ ] `unauth_mode: true` pomija auth_bootstrap i wszystkie `requires_auth=True` rules.
- [ ] Scan dziala end-to-end z tylko HAR lub OpenAPI jako input (bez sesji).
- [ ] Wordlist jest context-aware (zawiera paths z JS mining i AssetMap).
- [ ] JS bundle scanner wykrywa hardcoded API keys z confidence >= 0.85.
- [ ] Raport unauth mode zawiera "Untested attack classes" z poradami.
- [ ] Unauth coverage >= 60% klas ataków aktywna bez credentials.

### Podział pracy — codex-dad

Wiekszosc pracy (A1–A4, B1–B2, C1–C2, D1–D2, E1–E2): codex-dad — integracje z core orchestrator, planner, validator, crawler.
Playbooki (B3, D3): codex-main.

### Post-sprint: przeglad skillow

Czy pojawil sie nowy powtarzalny pattern? Jesli tak - zaktualizuj lub dodaj skill w `.workflow/skills/`. Regula: pattern >= 2x -> skodyfikuj.
