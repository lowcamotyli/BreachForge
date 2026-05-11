## Sprint 37 - HTTP-Level Attacks (Smuggling, Cache Poisoning, HPP)

**Goal:** Wykrywanie atakow na poziomie protokolu HTTP: request smuggling (CL.TE/TE.CL), web cache deception, cache poisoning przez injektowane headery, i HTTP method override bypass.

Ataki HTTP-level sa niewidoczne dla aplikacyjnych WAFow i testow funkcjonalnych. Smuggling i cache poisoning to typowe krytyczne znaleziska w bug bounty.

### Architektura - dokumenty referencyjne

```bash
DAD_PROMPT="Read /mnt/d/BreachForge/docs/architecture/attack-engine.md and storage-infra.md. Extract: HTTP client configuration (httpx), timeout constraints, retry policy, connection pool rules, evidence storage limits. Bullets. Max 25 lines." bash ~/.claude/scripts/dad-exec.sh
```

### Workstream A - HTTP Request Smuggling

| ID | Zadanie | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| A1 | Reguła HTTP smuggling: wykrywa endpointy za reverse proxy / load balancer (przez `Via`, `X-Forwarded-For`, `Server` headers) jako smuggling candidates | `execution_plane/planner/rules/http_level.py` (new) | **codex-dad** | planner tests | proxy-behind endpoints maja wysoki priorytet |
| A2 | Strategia `http_smuggling`: CL.TE probe — wysyla request z `Content-Length: N` i `Transfer-Encoding: chunked` z niezgodnoscia; proof przez timeout differential lub "poisoned" response na kolejnym request | `execution_plane/validator/strategies/http_smuggling.py` (new) | **codex-dad** | validator tests | confidence 0.88 przy timeout + 2. request zawiera prefix; max 2 probes |
| A3 | TE.CL probe — wysyla chunk 0 zamiast Content-Length wartosci | `execution_plane/validator/strategies/http_smuggling.py` | **codex-dad** | validator tests | ta sama confidence, osobny fingerprint |
| A4 | Playbook smuggling detection | `execution_plane/planner/playbooks/http_request_smuggling.yaml` (new) | codex-main | corpus tests | max_requests: 2, tylko detection (nie exploitation) |

### Workstream B - Web Cache Attacks

| ID | Zadanie | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| B1 | Reguła cache attacks: wykrywa caching headers (`Cache-Control: public`, `Age:`, `X-Cache:`, `CF-Cache-Status:`, `ETag:`) jako cache candidates | `execution_plane/planner/rules/http_level.py` | **codex-dad** | planner tests | cache-enabled endpoints maja cache_attack candidate |
| B2 | Strategia `web_cache_deception`: probe path suffix — `GET /api/user/profile/test.css` i sprawdza czy response zawiera prywatne dane z cache | `execution_plane/validator/strategies/cache_poisoning.py` (new) | **codex-dad** | validator tests | confidence 0.90 gdy profile data w response na static extension path |
| B3 | Strategia `cache_poisoning`: injektuje `X-Forwarded-Host: evil.com` lub `X-Host: evil.com` — proof gdy reflection w response (Location, CORS, links) wskazuje na injektowany host | `execution_plane/validator/strategies/cache_poisoning.py` | **codex-dad** | validator tests | confidence 0.87 przy host reflection |
| B4 | Playbook web cache deception | `execution_plane/planner/playbooks/web_cache_deception.yaml` (new) | codex-main | corpus tests | max_requests: 2 (probe + verify), private data w fixture |
| B5 | Playbook cache poisoning | `execution_plane/planner/playbooks/cache_poisoning.yaml` (new) | codex-main | corpus tests | max_requests: 2, nie zapisuje zatrutych danych do cache produkcyjnego |

### Workstream C - HTTP Parameter & Method Abuse

| ID | Zadanie | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| C1 | Strategia `http_method_override`: wysyla `POST` z `X-HTTP-Method-Override: DELETE` i `_method=DELETE` — proof gdy serwer wykonuje DELETE | `execution_plane/validator/strategies/http_smuggling.py` | **codex-dad** | validator tests | confidence 0.90 przy DELETE execution przez POST+override |
| C2 | Strategia `http_parameter_pollution`: `?id=1&id=2` — sprawdza ktora wartosc jest uzyrana (pierwsza vs ostatnia vs obie) przez response diff | `execution_plane/validator/strategies/http_smuggling.py` | **codex-dad** | validator tests | roznica w response przy HPP = 0.80 confidence |
| C3 | Playbook method override + HPP | `execution_plane/planner/playbooks/http_method_override.yaml` (new) | codex-main | corpus tests | max_requests: 3 |
| C4 | Rejestracja wszystkich nowych strategii | `execution_plane/validator/registry.py` (edit) | Claude | brak | klucze `http_smuggling`, `web_cache_deception`, `cache_poisoning`, `http_method_override`, `http_parameter_pollution` |

### Workstream D - Tests & Corpus

| ID | Zadanie | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| D1 | Unit testy: smuggling timeout diff, cache deception private data, poisoning header reflection, method override | `tests/unit/execution_plane/validator/test_http_level_strategy.py` (new) | codex-main | pytest -q | coverage > 85% |
| D2 | Corpus: mock endpoints z cache headers i method override support | `tests/corpus/http_level_corpus.py` (new) | codex-main | corpus tests | 4 findingi z roznymi wektorami |

### Guardrails

- HTTP smuggling proby WYMAGAJA `allow_smuggling_probes: true` w scan config — domyslnie off (zbyt duze ryzyko destabilizacji).
- Cache poisoning probe nie persystuje zatruwajacego requestu — wysyla header injection i natychmiast sprawdza jeden response.
- Web cache deception NIE loguje prywatnych danych z cache — tylko potwierdza ze prywatne pole bylo dostepne.
- HPP probe nie zmienia stanu aplikacji — tylko odczytuje.

### Weryfikacja

```bash
"/c/Program Files/Python312/python.exe" -m pytest tests/unit/execution_plane/validator/test_http_level_strategy.py -q
"/c/Program Files/Python312/python.exe" -m pytest tests/unit/ -q
"/c/Program Files/Python312/python.exe" -m pytest tests/corpus/ -q
```

### Global acceptance criteria

- [ ] Smuggling proby sa off domyslnie i wymagaja explicit opt-in.
- [ ] Cache deception finding zawiera: sciezka, typ danych (nie wartosci), kod odpowiedzi.
- [ ] Cache poisoning finding zawiera: injektowany header, gdzie refleksja nastapila.
- [ ] Method override finding zawiera: oryginalny verb, override verb, wynik operacji (tylko dla fixtures).
- [ ] Zaden atak nie persystuje efektu — jeden probe, jeden verify, koniec.

### Podział pracy — codex-dad

Wiekszosc pracy (A1, A2, A3, B1, B2, B3, C1, C2): codex-dad — kompleksowy HTTP protocol layer + sensitive validator.
Playbooki i testy (A4, B4, B5, C3, D1, D2): codex-main.
Rejestracja (C4): Claude.

### Post-sprint: przeglad skillow

Czy pojawil sie nowy powtarzalny pattern? Jesli tak - zaktualizuj lub dodaj skill w `.workflow/skills/`. Regula: pattern >= 2x -> skodyfikuj.
