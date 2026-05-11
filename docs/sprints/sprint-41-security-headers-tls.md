## Sprint 41 - Security Headers & TLS Deep Scan

**Goal:** Systematyczna analiza security headers (HSTS, CSP, X-Frame-Options, etc.), gleboka analiza CORS (null origin, wildcard z credentials), i detekcja slabosci TLS/SSL.

Security headers sa pierwsza linia obrony. Ich brak to nie tyle luka aplikacyjna co kompletna nieobecnosc defense-in-depth — czesto pomijana w pospesznych deployach.

### Architektura - dokumenty referencyjne

```bash
DAD_PROMPT="Read /mnt/d/BreachForge/docs/architecture/attack-engine.md and validation-model.md. Extract: how misconfiguration class is handled, response header analysis patterns, severity assignment for config findings. Bullets. Max 25 lines." bash ~/.claude/scripts/dad-exec.sh
```

### No-Auth Note

**Security headers i TLS analysis sa w 100% unauth** — zadne z zadan w tym sprincie nie wymaga sesji. `requires_auth: False` na wszystkich rules. Sprint 41 dziala jako pierwszy w unauth mode scan.

Hierarchia: security_headers i tls_analysis uruchamiane SA przed jakimkolwiek auth probe — wyniki sa dostepne juz w recon phase.

### Workstream A - Security Headers Rule & Planner

| ID | Zadanie | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| A1 | Reguła security headers: kazdý endpoint w AssetMap jest kandydatem — headers sa analizowane z response bez dodatkowych requestow | `execution_plane/planner/rules/security_headers.py` (new) | **codex-dad** | planner tests | rule generuje header_audit candidate per domain (nie per endpoint) |
| A2 | Playbook security headers audit — GET homepage/API root, analiza response headers | `execution_plane/planner/playbooks/security_headers_audit.yaml` (new) | codex-main | corpus tests | max_requests: 3 (homepage, API root, login endpoint) |
| A3 | Playbook CORS deep analysis — probe z `Origin: null`, `Origin: evil.com`, `Origin: sub.target.com` | `execution_plane/planner/playbooks/cors_deep_analysis.yaml` (new) | codex-main | corpus tests | max_requests: 4 per domain |
| A4 | Playbook TLS analysis — HEAD request z TLS metadata extraction | `execution_plane/planner/playbooks/tls_analysis.yaml` (new) | codex-main | corpus tests | max_requests: 1, timeout: 10s |

### Workstream B - Security Headers Validator

| ID | Zadanie | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| B1 | Strategia `security_headers`: analizuje obecnosc i poprawnosc kazdego headera — macierz severity per header | `execution_plane/validator/strategies/security_headers.py` (new) | **codex-dad** | validator tests | kazdy missing/misconfigured header = osobny sub-finding z severity |
| B2 | Severity macierz nagłówków: HSTS missing/short=High, CSP missing=High, CSP unsafe-inline=Medium, X-Frame-Options missing=Medium, X-Content-Type-Options missing=Low, Permissions-Policy missing=Info | `execution_plane/validator/strategies/security_headers.py` | **codex-dad** | tests | macierz deterministyczna, nie heurystyczna |
| B3 | CORS deep analysis strategia: `Access-Control-Allow-Origin: *` + `Access-Control-Allow-Credentials: true` = Critical; `null` origin akceptowany = High; reflecting arbitrary Origin = High | `execution_plane/validator/strategies/security_headers.py` | **codex-dad** | validator tests | confidence 0.95 dla CORS+credentials misconfiguration |
| B4 | CSP parser: wykrywa `unsafe-inline`, `unsafe-eval`, wildcard sources (`*`), brak `default-src` — kazda dyrektywa osobno | `execution_plane/validator/strategies/security_headers.py` | **codex-dad** | tests | CSP issues jako osobne findings z affected directive |
| B5 | TLS weak config detection: TLS 1.0/1.1 accepted, weak cipher patterns w server hello (przez SSL error messages lub explicit TLS version negotiation) | `execution_plane/validator/strategies/security_headers.py` | **codex-dad** | tests | TLS 1.0 = High, TLS 1.1 = Medium |
| B6 | Rejestracja strategii | `execution_plane/validator/registry.py` (edit < 5 linii) | Claude | brak | klucze `security_headers`, `cors_analysis`, `tls_analysis` |

### Workstream C - Tests & Corpus

| ID | Zadanie | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| C1 | Unit testy: HSTS missing, CSP unsafe-inline, CORS wildcard+credentials, TLS 1.0, null origin accepted | `tests/unit/execution_plane/validator/test_security_headers_strategy.py` (new) | codex-main | pytest -q | wszystkie scenariusze pokryte |
| C2 | Corpus: mock server bez security headers i z CORS misconfiguration | `tests/corpus/security_headers_corpus.py` (new) | codex-main | corpus tests | findingi dla 3 kategorii headers |

### Guardrails

- Security headers analysis jest czysto read-only — 1-3 GET requestow per domain, nie per endpoint.
- TLS analysis nie przeprowadza aktywnego cipher suite scanning (zbyt inwazyjne) — tylko sprawdza minimalna wersje TLS przez probny handshake.
- CORS probe z `Origin: null` jest wysylany jako osobny request — nie modyfikuje innych requestow.
- Wildcard+credentials finding jest automatycznie kategoryzowany jako Critical i wymaga Claude approve przed finalnym raportem.

### Weryfikacja

```bash
"/c/Program Files/Python312/python.exe" -m pytest tests/unit/execution_plane/validator/test_security_headers_strategy.py -q
"/c/Program Files/Python312/python.exe" -m pytest tests/unit/ -q
"/c/Program Files/Python312/python.exe" -m pytest tests/corpus/ -q
```

### Global acceptance criteria

- [ ] Header audit generuje osobny finding per missing/misconfigured header.
- [ ] CORS wildcard+credentials = Critical z confidence 0.95.
- [ ] CSP parser rozpoznaje co najmniej 5 unsafe dyrektyw.
- [ ] TLS 1.0 acceptance = High severity finding.
- [ ] Caly header audit = max 3 requestow per domain.

### Podział pracy — codex-dad

Wiekszosc pracy (A1, B1, B2, B3, B4, B5): codex-dad — kompleksowa analiza headers + severity macierz.
Playbooki i testy (A2–A4, C1, C2): codex-main.
Rejestracja (B6): Claude.

### Post-sprint: przeglad skillow

Czy pojawil sie nowy powtarzalny pattern? Jesli tak - zaktualizuj lub dodaj skill w `.workflow/skills/`. Regula: pattern >= 2x -> skodyfikuj.
