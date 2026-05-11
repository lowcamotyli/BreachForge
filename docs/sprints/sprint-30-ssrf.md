## Sprint 30 - SSRF (Server-Side Request Forgery)

**Goal:** Wykrywanie SSRF przez identyfikacje parametrow przyjmujacych URL/sciezki i testowanie dostepu do cloud metadata, internal services i restricted protokolow.

SSRF to jedna z najcenniejszych luk w srodowiskach cloud — pozwala na dostep do metadata serwisu (IAM credentials), wewnetrznych API i S3 bucketow przez podatny serwer.

### Architektura - dokumenty referencyjne

```bash
DAD_PROMPT="Read /mnt/d/BreachForge/docs/architecture/security-constraints.md and attack-engine.md. Extract: scope enforcement, outbound request constraints, safe probe rules, worker isolation invariants. Bullets. Max 25 lines." bash ~/.claude/scripts/dad-exec.sh
```

### Workstream A - SSRF Rule & Planner

| ID | Zadanie | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| A1 | Reguła wykrywajaca parametry SSRF: `url`, `endpoint`, `callback`, `redirect`, `webhook`, `src`, `href`, `fetch`, `load`, `file` w query/body | `execution_plane/planner/rules/ssrf.py` (new) | **codex-dad** | planner unit tests | rule rankuje URL-accepting params jako high-risk |
| A2 | Playbook cloud metadata — testuje `http://169.254.169.254/latest/meta-data/` (AWS), `http://100.100.100.200/` (Alibaba), `http://metadata.google.internal/` | `execution_plane/planner/playbooks/ssrf_cloud_metadata.yaml` (new) | codex-main | corpus tests | max_requests: 3, tylko GET |
| A3 | Playbook internal discovery — testuje `http://localhost/`, `http://127.0.0.1/`, `http://10.0.0.1/`, `http://192.168.1.1/` | `execution_plane/planner/playbooks/ssrf_internal_discovery.yaml` (new) | codex-main | corpus tests | max_requests: 4, rate: 0.3 RPS |
| A4 | Playbook protocol SSRF — testuje `file:///etc/passwd`, `dict://127.0.0.1:6379/`, `gopher://127.0.0.1:25/` | `execution_plane/planner/playbooks/ssrf_protocol_abuse.yaml` (new) | codex-main | corpus tests | max_requests: 3, tylko przy explicit allowlist |

### Workstream B - SSRF Validator Strategy

| ID | Zadanie | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| B1 | Strategia `ssrf`: proof type `absolute` — response zawiera cloud metadata markers (`ami-id`, `iam/security-credentials`, `hostname`, `instance-id`) | `execution_plane/validator/strategies/ssrf.py` (new) | **codex-dad** | validator unit tests | confidence 0.95 przy metadata hit, 0.70 przy timing delta |
| B2 | Blind SSRF detection przez timing: czas odpowiedzi dla internal IP > baseline_delta (>2s) jako low-confidence sygnał | `execution_plane/validator/strategies/ssrf.py` | **codex-dad** | validator tests | blind SSRF max confidence 0.72 (wymaga OOB z Sprint 43 dla wysokiej pewnosci) |
| B3 | Scope guard: ssrf prober NIE wysyla requestow poza target-scope IP ranges bez explicit allowlist | `execution_plane/validator/strategies/ssrf.py` | **codex-dad** | guardrail tests | probe do external IP blokowany |
| B4 | Rejestracja w registry | `execution_plane/validator/registry.py` (edit < 5 linii) | Claude | brak | strategy `ssrf` dostepna |

### Workstream C - Tests & Corpus

| ID | Zadanie | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| C1 | Unit testy: metadata hit, internal IP timing, protocol rejection, scope guard | `tests/unit/execution_plane/validator/test_ssrf_strategy.py` (new) | codex-main | pytest -q | coverage > 90% |
| C2 | Corpus fixture: mock endpoint ktory forward'uje URL param do wewnetrznego requests.get() | `tests/corpus/ssrf_corpus.py` (new) | codex-main | corpus tests | hit na metadata fixture = confidence 0.95 |

### Workstream D - No-Auth Coverage

| ID | Zadanie | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| D1 | `requires_auth: False` — SSRF rule aktywna w unauth mode: publiczne endpointy z URL params (webhooks, image fetchers) sa czesto dostepne bez sesji | `execution_plane/planner/rules/ssrf.py` (dodaj atrybut) | Claude | brak | rule ma `requires_auth = False` |
| D2 | Unauth SSRF probe: jesli endpoint jest dostepny bez auth (unauth_baseline status < 400) — SSRF probe wykonywany bez credentials | `execution_plane/validator/strategies/ssrf.py` (dodaj unauth branch) | **codex-dad** | validator tests | probe bez Authorization header jesli endpoint jest publiczny |
| D3 | HAR-hint SSRF: jesli HAR import (Sprint 44) dostarczyl entries z URL params — SSRF rule uzywa tych params jako dodatkowe candidates | `execution_plane/planner/rules/ssrf.py` | **codex-dad** | planner tests | HAR body fields z URL pattern = SSRF candidates |

> **Zaleznosc:** D3 wymaga Sprint 44 (HAR import). D1/D2 dzialaja niezaleznie.

### Guardrails

- SSRF prober dziala TYLKO wobec IP/hostnamen ktore sa w allowlist lub sa cloud-metadata ranges — nigdy wobec arb. external IPs.
- Protokoly `file://`, `dict://`, `gopher://` sa probed tylko gdy skan ma explicit `allow_protocol_ssrf: true` flag — domyslnie off.
- Blind SSRF confidence jest cappowana na 0.72 bez OOB infrastruktury (Sprint 43).
- Kazdy SSRF finding zawiera w evidence: oryginalny request, response (skrocony, bez credentials), latency delta.

### Weryfikacja

```bash
"/c/Program Files/Python312/python.exe" -m pytest tests/unit/execution_plane/validator/test_ssrf_strategy.py -q
"/c/Program Files/Python312/python.exe" -m pytest tests/unit/execution_plane/planner/ -q
"/c/Program Files/Python312/python.exe" -m pytest tests/corpus/ -q
"/c/Program Files/Python312/python.exe" -m pytest tests/unit/ -q
```

### Global acceptance criteria

- [ ] Rule wykrywa URL-accepting parameters z priorytetem high dla nazw: url, callback, webhook.
- [ ] Metadata markers hit = confidence 0.95, timing = 0.72 max.
- [ ] Scope guard blokuje probes poza target domain.
- [ ] Protokoly file/dict/gopher wymagaja explicit allowlist.
- [ ] Finding evidence nie zawiera raw response body z credentials.

### Podział pracy — codex-dad

Wiekszosc pracy (A1, B1, B2, B3): codex-dad — sensitive domain (outbound requests, scope enforcement).
Playbooki i testy (A2–A4, C1, C2): codex-main.
Rejestracja (B4): Claude.

### Post-sprint: przeglad skillow

Czy pojawil sie nowy powtarzalny pattern? Jesli tak - zaktualizuj lub dodaj skill w `.workflow/skills/`. Regula: pattern >= 2x -> skodyfikuj.
