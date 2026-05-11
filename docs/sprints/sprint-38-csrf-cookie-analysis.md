## Sprint 38 - CSRF & Cookie Security Analysis

**Goal:** Wykrywanie braku ochrony CSRF na state-changing endpoints oraz analize bezpieczenstwa cookies: brak HttpOnly/Secure/SameSite flags, zbyt szeroki scope i double-submit pattern weakness.

CSRF jest trivialny do exploitacji gdy brakuje state-changing endpoint protection. Cookie flags sa podstawa defense-in-depth — ich brak widac w jednym request.

### Architektura - dokumenty referencyjne

```bash
DAD_PROMPT="Read /mnt/d/BreachForge/docs/architecture/auth-architecture.md and validation-model.md. Extract: session cookie structure, how cookies are stored in SessionSnapshot, CORS rules, Origin/Referer handling. Bullets. Max 25 lines." bash ~/.claude/scripts/dad-exec.sh
```

### Workstream A - CSRF Detection

| ID | Zadanie | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| A1 | Reguła CSRF: wykrywa state-changing endpoints (POST/PUT/PATCH/DELETE) — sprawdza obecnosc CSRF token w request (form field, header `X-CSRF-Token`, `X-XSRF-Token`) | `execution_plane/planner/rules/csrf.py` (new) | **codex-dad** | planner tests | rule generuje CSRF candidate dla endpoints bez CSRF token |
| A2 | Logika CSRF probe: wysyla state-changing request bez `Origin` i bez `Referer` headera — sprawdza czy serwer akceptuje | `execution_plane/planner/rules/csrf.py` | **codex-dad** | planner tests | probe jest wygenerowany z stripped headers |
| A3 | Playbook CSRF token absence — POST bez CSRF token na formularzu | `execution_plane/planner/playbooks/csrf_state_change.yaml` (new) | codex-main | corpus tests | max_requests: 2 (baseline z tokenem, probe bez tokenu) |
| A4 | Playbook CSRF weak token — token reuse (ten sam token wielokrotnie) i static token | `execution_plane/planner/playbooks/csrf_weak_token.yaml` (new) | codex-main | corpus tests | max_requests: 3, sprawdza czy token jest per-request |

### Workstream B - Cookie Security Analysis

| ID | Zadanie | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| B1 | Strategia `cookie_analysis`: analizuje Set-Cookie headers — sprawdza flagi: `HttpOnly`, `Secure`, `SameSite` (None/Lax/Strict), `Domain` (zbyt szeroki), `Path` (/), `__Host-` prefix | `execution_plane/validator/strategies/cookie_analysis.py` (new) | **codex-dad** | validator tests | raport per-cookie z missing flags jako severity per rule |
| B2 | Severity mapping cookies: session cookie bez HttpOnly = High; Secure=false = High; SameSite=None bez Secure = High; SameSite=Lax (akceptowalne) = Info | `execution_plane/validator/strategies/cookie_analysis.py` | **codex-dad** | validator tests | severity macierz deterministyczna |
| B3 | Strategia `csrf`: proof `absolute` — state-changing request bez Origin/Referer i bez CSRF token zwraca 2xx = CSRF possible; confidence 0.90 | `execution_plane/validator/strategies/csrf.py` (new) | **codex-dad** | validator tests | redirect z 302 != CSRF; 400/403/422 = protected |
| B4 | CSRF double-submit weakness: token w cookie == token w header — probe z rozroznionymi wartosciami sprawdza czy walidacja jest po stronie serwera | `execution_plane/validator/strategies/csrf.py` | **codex-dad** | validator tests | confidence 0.88 przy akceptacji mismatched double-submit |
| B5 | Rejestracja strategii | `execution_plane/validator/registry.py` (edit < 5 linii) | Claude | brak | klucze `cookie_analysis`, `csrf` dostepne |

### Workstream C - Playbooks & Tests

| ID | Zadanie | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| C1 | Playbook cookie flags audit — GET endpoint, analiza Set-Cookie response headers | `execution_plane/planner/playbooks/cookie_flags_audit.yaml` (new) | codex-main | corpus tests | max_requests: 1, read-only |
| C2 | Unit testy: brak CSRF token akceptowany, cookie flags missing, double-submit mismatch | `tests/unit/execution_plane/validator/test_csrf_cookie_strategy.py` (new) | codex-main | pytest -q | coverage > 90% |
| C3 | Corpus: mock endpoint akceptujacy POST bez CSRF token + endpoint z insecure cookies | `tests/corpus/csrf_corpus.py` (new) | codex-main | corpus tests | CSRF finding 0.90, cookie issues findings per flag |

### Workstream D - No-Auth Coverage

Cookie analysis jest **100% unauth** — nie wymaga sesji. CSRF wymaga co najmniej jednego state-changing request jako baseline.

| ID | Zadanie | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| D1 | `requires_auth: False` dla cookie_analysis rule — Set-Cookie headers sa analizowane z kazdej odpowiedzi, nawet publicznie dostepnej | `execution_plane/planner/rules/csrf.py` (dodaj atrybut) | Claude | brak | `cookie_analysis` rule ma `requires_auth = False` |
| D2 | Unauth cookie audit: jesli endpoint jest dostepny bez auth i zwraca Set-Cookie — cookie_analysis automatycznie startuje bez sesji | `execution_plane/validator/strategies/cookie_analysis.py` (dodaj unauth path) | **codex-dad** | validator tests | cookie flags analysis dziala bez SessionSnapshot |
| D3 | Login endpoint cookie audit: endpoint `/login`, `/signin`, `/auth` jest zawsze probowany GET (bez credentials) dla analizy cookie flags — najczesciej ustawia session cookie w Set-Cookie nawet przed logowaniem | `execution_plane/planner/rules/csrf.py` | **codex-dad** | planner tests | login endpoint = automatyczny cookie_audit candidate |
| D4 | HAR cookie analysis: cookies z HAR import (Sprint 44) sa przechodzace przez cookie_analysis strategię — raportuje missing flags na cookies ktore juz widzielismy | `execution_plane/validator/strategies/cookie_analysis.py` | **codex-dad** | tests | HAR cookies → cookie audit without any live probe |

> **Zaleznosc:** D4 wymaga Sprint 44 (HAR import). D1/D2/D3 niezalezne.

### Guardrails

- CSRF probe nie wykonuje realnych mutacji biznesowych — uzywa safe fixture (tymczasowy obiekt) lub GET-equivalent state check.
- Cookie analysis jest czysto read-only — nie modyfikuje cookies, tylko analizuje response headers.
- CSRF probe NIE wysyla prawdziwych credentials w modyfikowanym request — uzywa sesji testowej.
- Double-submit probe sprawdza walidacje serwera bez zmiany stanu (jesli endpoint powoduje skutki uboczne — wymaga safe fixture).

### Weryfikacja

```bash
"/c/Program Files/Python312/python.exe" -m pytest tests/unit/execution_plane/validator/test_csrf_cookie_strategy.py -q
"/c/Program Files/Python312/python.exe" -m pytest tests/unit/ -q
"/c/Program Files/Python312/python.exe" -m pytest tests/corpus/ -q
```

### Global acceptance criteria

- [ ] CSRF rule wykrywa state-changing endpoints bez CSRF token.
- [ ] CSRF finding zawiera: endpoint, metoda HTTP, brak headera ochrony, confidence.
- [ ] Cookie finding zawiera per-cookie: nazwa, missing flags, severity.
- [ ] Session cookie (zawierajacy `session`/`token`/`auth` w nazwie) bez HttpOnly = High severity.
- [ ] CSRF probe nie wykonuje real mutations bez safe fixture.

### Podział pracy — codex-dad

Wiekszosc pracy (A1, A2, B1, B2, B3, B4): codex-dad — sensitive domain (session cookies, auth token analysis).
Playbooki i testy (A3, A4, C1, C2, C3): codex-main.
Rejestracja (B5): Claude.

### Post-sprint: przeglad skillow

Czy pojawil sie nowy powtarzalny pattern? Jesli tak - zaktualizuj lub dodaj skill w `.workflow/skills/`. Regula: pattern >= 2x -> skodyfikuj.
