## Sprint 43 - OOB Callback Infrastructure (Blind SSRF/XXE Upgrade)

**Goal:** Zbudowanie infrastruktury Out-of-Band (OOB) callback — HTTP listener i DNS monitor — ktore podniesie confidence blind SSRF (Sprint 30) i blind XXE (Sprint 36) z 0.65 do 0.92+.

Blind SSRF i blind XXE sa wykrywalne tylko przez OOB — serwer nie zwraca dowodow w response, ale wykonuje zewnetrzny request. Bez OOB te wektory sa czesto pomijane.

### Architektura - dokumenty referencyjne

```bash
DAD_PROMPT="Read /mnt/d/BreachForge/docs/architecture/attack-engine.md and storage-infra.md and security-constraints.md. Extract: worker isolation rules (Redis-only writes), network constraints, external service allowlist, evidence storage path. Bullets. Max 25 lines." bash ~/.claude/scripts/dad-exec.sh
```

### Workstream A - OOB HTTP Listener

| ID | Zadanie | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| A1 | OOB Manager: koordynuje generowanie unikalnych callback URLs, rejestracje oczekujacych callbackow i matching przychodzeajacych requestow do probe ID | `execution_plane/oob/oob_manager.py` (new) | **codex-dad** | unit tests | per-probe unikalny token, TTL na oczekiwanie |
| A2 | HTTP Callback Listener: FastAPI endpoint na osobnym porcie (konfigurowalnym) — rejestruje przychodzeace requesty jako OOB hits, zapisuje do Redis Evidence Buffer | `execution_plane/oob/callback_server.py` (new) | **codex-dad** | integration tests | NIGDY nie zapisuje do DB bezposrednio (Worker Isolation invariant) |
| A3 | OOB callback URL generator: `https://oob.<scan_id>.breachforge.internal/<probe_token>` — URL jest unikalny per probe i zawiera scan_id w path | `execution_plane/oob/oob_manager.py` | **codex-dad** | unit tests | kolizja tokenow niemozliwa (UUID4) |
| A4 | Konfiguracja: `OOB_LISTENER_HOST`, `OOB_LISTENER_PORT`, `OOB_BASE_URL` w scan config — domyslnie disabled | `execution_plane/oob/oob_manager.py` | **codex-dad** | config tests | OOB jest off bez explicit config |

### Workstream B - DNS Monitor

| ID | Zadanie | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| B1 | DNS Callback Monitor: subskrybuje na DNS lookups dla wildcard subdomain `*.oob.breachforge.internal` — rejestruje jako OOB hit z probe_token z subdomain | `execution_plane/oob/dns_monitor.py` (new) | **codex-dad** | unit tests | DNS hit matchuje probe token z subdomain |
| B2 | DNS integration z OOB Manager: DNS hit jest rejestrowany przez ten sam OOB Manager co HTTP (unified evidence) | `execution_plane/oob/dns_monitor.py` | **codex-dad** | integration tests | http i dns hity sa w jednym evidence record |
| B3 | DNS monitor jest opcjonalny: dziala tylko gdy `OOB_DNS_ENABLED: true` i serwer DNS jest skonfigurowany pod nasza kontrola | `execution_plane/oob/dns_monitor.py` | **codex-dad** | config tests | bez DNS config — tylko HTTP OOB |

### Workstream C - Integration z istniejacymi strategiami

| ID | Zadanie | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| C1 | Upgrade blind SSRF w strategii ssrf.py: gdy OOB dostepny, uzyj OOB URL jako SSRF target zamiast cloud metadata — confidence 0.92 przy OOB hit | `execution_plane/validator/strategies/ssrf.py` (edit) | **codex-dad** | validator tests | blind SSRF z OOB = 0.92, bez OOB = 0.65 (bez zmian) |
| C2 | Upgrade blind XXE w strategii xxe.py: OOB URL w SYSTEM entity — DNS/HTTP callback potwierdza XXE | `execution_plane/validator/strategies/xxe.py` (edit) | **codex-dad** | validator tests | blind XXE z OOB = 0.92, bez OOB = 0.65 (bez zmian) |
| C3 | OOB Manager dostepny jako dependency injection w strategiach — optional, None gdy nie skonfigurowany | `execution_plane/validator/strategies/ssrf.py`, `xxe.py` | **codex-dad** | tests | brak OOB config nie crashuje strategii |

### Workstream D - Tests & Corpus

| ID | Zadanie | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| D1 | Unit testy OOB Manager: token generation, match, TTL expiry | `tests/unit/execution_plane/oob/test_oob_manager.py` (new) | codex-main | pytest -q | coverage > 90% |
| D2 | Integration test: mock SSRF endpoint ktory wykonuje callback, OOB listener rejestruje hit, finding generowany z 0.92 | `tests/integration/test_oob_integration.py` (new) | codex-main | pytest -q | end-to-end flow dziala |
| D3 | Test ze bez OOB config — istniejace testy blind SSRF/XXE nadal zdaja z nizsza confidence | `tests/unit/execution_plane/validator/test_ssrf_strategy.py` (edit) | codex-main | pytest -q | backward compatible |

### Guardrails

- OOB listener NIGDY nie zapisuje do bazy danych bezposrednio — tylko do Redis Evidence Buffer (Worker Isolation invariant).
- OOB callback URLs zawieraja tylko scan_id i probe_token — nie ma w nich wrażliwych danych.
- TTL na oczekiwany callback: 30 sekund — po TTL probe jest uznany za miss.
- OOB infrastructure dziala TYLKO dla biezacego skanu — nie persystuje miedzy skanami.
- DNS monitor wymaga kontroli nad nameserverem — nie mozna uzyc publicznego DNS jako OOB (brak kontroli).

### Weryfikacja

```bash
"/c/Program Files/Python312/python.exe" -m pytest tests/unit/execution_plane/oob/ -q
"/c/Program Files/Python312/python.exe" -m pytest tests/integration/test_oob_integration.py -q
"/c/Program Files/Python312/python.exe" -m pytest tests/unit/execution_plane/validator/test_ssrf_strategy.py -q
"/c/Program Files/Python312/python.exe" -m pytest tests/unit/ -q
```

### Global acceptance criteria

- [ ] OOB Manager generuje unikalne per-probe tokeny.
- [ ] HTTP callback listener nie zapisuje do DB (Worker Isolation).
- [ ] Blind SSRF z OOB = confidence 0.92 vs 0.65 bez OOB.
- [ ] Blind XXE z OOB = confidence 0.92 vs 0.65 bez OOB.
- [ ] OOB jest disabled domyslnie — wymaga explicit config.
- [ ] Backward compatibility: brak OOB nie psuje istniejacych testow.

### Podział pracy — codex-dad

Wiekszosc pracy (A1, A2, A3, A4, B1, B2, B3, C1, C2, C3): codex-dad — cala infrastruktura OOB + integracje ze strategiami (sensitive domain).
Testy (D1, D2, D3): codex-main.

### Post-sprint: przeglad skillow

Czy pojawil sie nowy powtarzalny pattern? Jesli tak - zaktualizuj lub dodaj skill w `.workflow/skills/`. Regula: pattern >= 2x -> skodyfikuj.
