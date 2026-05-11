## Sprint 35 - Advanced Injection Suite (NoSQL, SSTI, LDAP, Header)

**Goal:** Rozszerzenie pokrycia injection poza SQL — MongoDB operator injection, Server-Side Template Injection, LDAP injection, XPath injection i HTTP header injection.

Obecna strategia `injection.py` pokrywa tylko SQL error i timing. Nowoczesne aplikacje czesto uzywaja MongoDB, szablonow Jinja2/Twig i LDAP — kazde z innych payloadow.

### Architektura - dokumenty referencyjne

```bash
DAD_PROMPT="Read /mnt/d/BreachForge/docs/architecture/attack-engine.md and noise-reduction.md. Extract: injection signal detection, confidence scoring for error-based vs timing-based, dedup fingerprint for injection findings. Bullets. Max 25 lines." bash ~/.claude/scripts/dad-exec.sh
```

### Workstream A - NoSQL Injection

| ID | Zadanie | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| A1 | Reguła NoSQL: wykrywa JSON-body endpoints z string parameters (login, search, filter) — kandydaci dla operator injection | `execution_plane/planner/rules/nosql_injection.py` (new) | **codex-dad** | planner tests | rule rankuje JSON-body params wysoko |
| A2 | Strategia `nosql_injection`: testuje `{"$gt": ""}`, `{"$ne": null}`, `{"$regex": ".*"}`, `{"$where": "1==1"}` — proof przez response diff vs baseline | `execution_plane/validator/strategies/nosql_injection.py` (new) | **codex-dad** | validator tests | confidence 0.90 przy body diff >= 60% lub auth bypass |
| A3 | Playbook NoSQL — inject operators w JSON body parametrach | `execution_plane/planner/playbooks/nosql_injection.yaml` (new) | codex-main | corpus tests | max_requests: 4, rate: 0.5 RPS |

### Workstream B - SSTI (Server-Side Template Injection)

| ID | Zadanie | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| B1 | Reguła SSTI: wykrywa string parameters ktore sa reflectowane w response (fuzzing `echo` check w crawler) | `execution_plane/planner/rules/ssti.py` (new) | **codex-dad** | planner tests | reflection-based candidate generation |
| B2 | Strategia `ssti`: probe payloady `{{7*7}}`, `${7*7}`, `<%= 7*7 %>`, `#{7*7}`, `*{7*7}` — proof gdy response zawiera `49` | `execution_plane/validator/strategies/ssti.py` (new) | **codex-dad** | validator tests | confidence 0.95 przy math eval hit; 0.0 przy brak refleksji |
| B3 | Engine fingerprinting: rozroznia Jinja2 (`{{config}}`), Twig (`{{_self.env}}`), ERB, Smarty po error patterns | `execution_plane/validator/strategies/ssti.py` | **codex-dad** | tests | finding zawiera: engine, payload ktory trafil, context |
| B4 | Playbook SSTI | `execution_plane/planner/playbooks/ssti.yaml` (new) | codex-main | corpus tests | max_requests: 5, tylko string params |

### Workstream C - LDAP, XPath, Header Injection

| ID | Zadanie | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| C1 | Strategia `ldap_injection` w rozszerzonym pliku injection: `*)(uid=*))(|(uid=*`, `admin)(|(password=*` — proof przez auth bypass lub error disclosure | `execution_plane/validator/strategies/advanced_injection.py` (new) | **codex-dad** | validator tests | confidence 0.88 przy auth bypass, 0.70 przy error disclosure |
| C2 | Strategia `xpath_injection`: `' or '1'='1`, `' or ''='` — proof przez unexpected data return | `execution_plane/validator/strategies/advanced_injection.py` | **codex-dad** | validator tests | confidence 0.85 przy data return |
| C3 | Strategia `header_injection`: Host header manipulation (`Host: evil.com`), X-Forwarded-For spoofing (`X-Forwarded-For: 127.0.0.1`) — proof gdy response zmienia sie | `execution_plane/validator/strategies/advanced_injection.py` | **codex-dad** | validator tests | confidence 0.87 przy Host reflection, 0.80 przy IP-based access change |
| C4 | Playbooki: ldap i header injection | `execution_plane/planner/playbooks/ldap_injection.yaml`, `header_injection.yaml` (new) | codex-main | corpus tests | kazdy max_requests: 3 |
| C5 | Rejestracja wszystkich nowych strategii | `execution_plane/validator/registry.py` (edit) | Claude | brak | klucze `nosql_injection`, `ssti`, `ldap_injection`, `xpath_injection`, `header_injection` |

### Workstream D - No-Auth Coverage

| ID | Zadanie | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| D1 | Public form detection: crawler oznacza endpointy dostepne bez auth z string params jako `unauth_injectable: true` — SSTI i NoSQL rules uzywaja tej flagi | `execution_plane/planner/rules/ssti.py`, `nosql_injection.py` (dodaj atrybut + filter) | **codex-dad** | planner tests | injection rules generuja candidates z `unauth_injectable` bez auth |
| D2 | `requires_auth: False` dla ssti i nosql_injection rules — aktywne w unauth mode na publicznych endpointach | `execution_plane/planner/rules/ssti.py`, `nosql_injection.py` | Claude | brak | atrybuty `requires_auth = False` |
| D3 | Header injection unauth: Host header i X-Forwarded-For injection sa zawsze probowane bez credentials (serwer widzi nagłówek zanim sprawdzi auth) | `execution_plane/planner/rules/advanced_injection.py` (new, wydzielona regula) | **codex-dad** | planner tests | header_injection rule ma `requires_auth = False` |
| D4 | LDAP/XPath: `requires_auth: True` — te wektory sa typowo za login page; nie probuj unauth | `execution_plane/planner/rules/advanced_injection.py` | Claude | brak | ldap i xpath rules maja `requires_auth = True` |

> **Zaleznosc:** D1 jest wzmocniony przez Sprint 44 unauth baseline — wiemy ktore endpointy sa publiczne zanim zacznie probe.

### Workstream E - Tests & Corpus

| ID | Zadanie | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| E1 | Unit testy wszystkich nowych strategii | `tests/unit/execution_plane/validator/test_advanced_injection_strategy.py` (new) | codex-main | pytest -q | wszystkie payloady i scenariusze pokryte |
| E2 | Corpus: mock MongoDB endpoint, mock Jinja2 render endpoint, mock LDAP auth | `tests/corpus/advanced_injection_corpus.py` (new) | codex-main | corpus tests | 3 findingi z odpowiednimi confidence |

### Guardrails

- SSTI payloady sa TYLKO matematycznymi wyrażeniami (`7*7`) — nigdy RCE payloadami (`__import__('os').system(...)`).
- Header injection testuje tylko reflection i access control — nie sluzy do cache poisoning w tym sprincie (Sprint 37).
- NoSQL operators sa testowane w JSON body — nigdy przez URL injection ktore moze byc logowane przez WAF.
- Injection payloady sa obcinane w logach evidencji po 128 znakach.

### Weryfikacja

```bash
"/c/Program Files/Python312/python.exe" -m pytest tests/unit/execution_plane/validator/test_advanced_injection_strategy.py -q
"/c/Program Files/Python312/python.exe" -m pytest tests/unit/ -q
"/c/Program Files/Python312/python.exe" -m pytest tests/corpus/ -q
```

### Global acceptance criteria

- [ ] NoSQL operator injection wykrywany przez auth bypass lub body diff.
- [ ] SSTI: math eval proof (`49`) + engine fingerprint w finding.
- [ ] LDAP/XPath: blad autoryzacji lub unexpected data = finding.
- [ ] Header injection: Host/XFF reflection zmienia response.
- [ ] Zaden payload nie jest RCE — tylko detection, nie exploitation.

### Podział pracy — codex-dad

Wiekszosc pracy (A1, A2, B1, B2, B3, C1, C2, C3): codex-dad — wszystkie strategie i reguly (sensitive domain).
Playbooki i testy (A3, B4, C4, D1, D2): codex-main.
Rejestracja (C5): Claude.

### Post-sprint: przeglad skillow

Czy pojawil sie nowy powtarzalny pattern? Jesli tak - zaktualizuj lub dodaj skill w `.workflow/skills/`. Regula: pattern >= 2x -> skodyfikuj.
