## Sprint 40 - Shadow API & Inventory Management (API9)

**Goal:** Wykrywanie deprecated API versions, niechronionych admin endpoints, ujawnionych dokumentacji API (Swagger/OpenAPI), ukrytych endpointow w JS bundlach i backup/temp files.

OWASP API9 — shadow API to najszybsza droga atakujacego. Stare wersje API czesto nie maja takich samych zabezpieczen jak nowe.

### Architektura - dokumenty referencyjne

```bash
DAD_PROMPT="Read /mnt/d/BreachForge/docs/architecture/attack-engine.md and auth-architecture.md. Extract: crawler AssetMap structure, how paths are stored, JS file parsing, recon phase constraints. Bullets. Max 25 lines." bash ~/.claude/scripts/dad-exec.sh
```

### Workstream A - JS Endpoint Extractor & Crawler Extension

| ID | Zadanie | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| A1 | JS endpoint extractor: parsuje downloaded JS bundles przez regex — wykrywa stringi wyglada jak API paths (`/api/`, `/v1/`, `/admin/`, fetch/axios URL patterns) | `execution_plane/crawler/js_endpoint_extractor.py` (new) | **codex-dad** | crawler tests | zwraca list[str] paths z JS bundle |
| A2 | Integracja z CrawlerReconEngine: po recon phase, aplikuj js_endpoint_extractor na wszystkich `.js` assets w AssetMap | `execution_plane/crawler/recon_engine.py` (edit, check size) | **codex-dad** | integration tests | AssetMap zawiera `js_discovered_paths` |
| A3 | API version detector: z istniejacych paths buduje versioned variants — `/api/users` → `/api/v1/users`, `/api/v2/users`, `/v0/users`, `/api/beta/users` | `execution_plane/planner/rules/shadow_api.py` (new) | **codex-dad** | planner tests | generuje wersjonowane candidates dla kazdego odkrytego base path |

### Workstream B - Shadow API Rule & Planner

| ID | Zadanie | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| B1 | Admin endpoint wordlist: rule generuje probes dla `/admin/`, `/internal/`, `/management/`, `/actuator/`, `/debug/`, `/console/`, `/ops/` — tylko w-scope | `execution_plane/planner/rules/shadow_api.py` | **codex-dad** | planner tests | bounded path budget, max 20 paths per scan |
| B2 | API docs exposure detector: probes `GET /swagger.json`, `/openapi.json`, `/api-docs`, `/swagger-ui.html`, `/api/swagger` | `execution_plane/planner/rules/shadow_api.py` | **codex-dad** | planner tests | candidates dla doc exposure |
| B3 | Backup file detector: wykrywa `.bak`, `.old`, `.swp`, `.tmp`, `~`, `.php.bak`, `copy_` w znanych sciezkach | `execution_plane/planner/rules/shadow_api.py` | **codex-dad** | planner tests | backup candidates dla kazdego zasobu w AssetMap |
| B4 | Playbook deprecated version — probes na `/v1/`, `/v0/`, `/api/beta/` variants | `execution_plane/planner/playbooks/deprecated_version_probe.yaml` (new) | codex-main | corpus tests | max_requests: 5 per base path, read-only |
| B5 | Playbook admin endpoint fuzz | `execution_plane/planner/playbooks/admin_endpoint_fuzz.yaml` (new) | codex-main | corpus tests | max_requests: 20 total per scan, bounded_path_budget: true |
| B6 | Playbook API doc exposure | `execution_plane/planner/playbooks/api_doc_exposure.yaml` (new) | codex-main | corpus tests | max_requests: 6, read-only |

### Workstream B2 - No-Auth & Spec-Driven Enhancement

| ID | Zadanie | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| B2a | `requires_auth: False` dla wszystkich shadow_api rules — deprecated endpoints, admin fuzz, doc exposure sa czesto dostepne publicznie | `execution_plane/planner/rules/shadow_api.py` | Claude | brak | wszystkie shadow_api rules maja `requires_auth = False` |
| B2b | OpenAPI-driven shadow API: jesli spec (Sprint 44) ujawnia `/api/v1/` — automatycznie generuje deprecated variants `/api/v0/`, `/api/v2-beta/` jako shadow candidates | `execution_plane/planner/rules/shadow_api.py` (edit) | **codex-dad** | planner tests | spec paths sa bazą do version permutation |
| B2c | HAR-sourced admin paths: jesli HAR (Sprint 44) zawiera requesty do `/admin/` lub `/internal/` — sa dodawane do wordlist jako wysokopriorytetowe targets | `execution_plane/planner/rules/shadow_api.py` (edit) | **codex-dad** | planner tests | HAR admin paths wchodza do wordlist z `priority: high` |
| B2d | Sourcemap endpoint discovery: sciezki z `.js.map` (Sprint 44) sa automatycznie dodawane do shadow API candidates | `execution_plane/planner/rules/shadow_api.py` (edit) | **codex-dad** | planner tests | sourcemap paths w candidatach |

> **Zaleznosc:** B2b/B2c/B2d wymagaja Sprint 44 (spec/HAR/sourcemap import). B2a niezalezne.

### Workstream C - Shadow API Validator Strategy

| ID | Zadanie | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| C1 | Strategia `api_inventory`: proof `absolute` — deprecated endpoint zwraca 200 z JSON (nie 404/410) = shadow API active; confidence 0.87 | `execution_plane/validator/strategies/api_inventory.py` (new) | **codex-dad** | validator tests | 404/410/301 = not finding; 200 z body = finding |
| C2 | Strategia `api_doc_exposure`: response zawiera `swagger`, `openapi`, `paths`, `definitions` klucze w JSON = API spec exposed; confidence 0.93 | `execution_plane/validator/strategies/api_inventory.py` | **codex-dad** | validator tests | spec exposure = High severity finding |
| C3 | Strategia `backup_file_exposure`: response na `.bak`/`.old` path jest 200 z content-type text lub application = source code exposure; confidence 0.90 | `execution_plane/validator/strategies/api_inventory.py` | **codex-dad** | validator tests | content-type check odroznia backup od redirect |
| C4 | Rejestracja strategii | `execution_plane/validator/registry.py` (edit < 5 linii) | Claude | brak | klucze `api_inventory`, `api_doc_exposure`, `backup_file_exposure` |

### Workstream D - Tests & Corpus

| ID | Zadanie | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| D1 | Unit testy: deprecated endpoint active, swagger exposed, backup file hit, JS path extraction | `tests/unit/execution_plane/validator/test_api_inventory_strategy.py` (new) | codex-main | pytest -q | coverage > 90% |
| D2 | Corpus: mock server z aktywnym `/api/v1/` (stary) i `/swagger.json` | `tests/corpus/shadow_api_corpus.py` (new) | codex-main | corpus tests | findingi dla deprecated + docs exposure |

### Guardrails

- Admin endpoint fuzzing ma twardy limit 20 requestow per scan — nie sluzy do pelnego bruteforce.
- JS extraction dziala na JUZPOBRANYCH assetach z crawl phase — nie robi dodatkowych requestow do CDN.
- Deprecated version probe jest read-only — nie wykonuje mutacji na starych endpointach.
- Backup file check: jesli response > 1MB — skracaj do 1KB i oznacz jako "large file exposure".

### Weryfikacja

```bash
"/c/Program Files/Python312/python.exe" -m pytest tests/unit/execution_plane/validator/test_api_inventory_strategy.py -q
"/c/Program Files/Python312/python.exe" -m pytest tests/unit/execution_plane/planner/ -q
"/c/Program Files/Python312/python.exe" -m pytest tests/corpus/ -q
"/c/Program Files/Python312/python.exe" -m pytest tests/unit/ -q
```

### Global acceptance criteria

- [ ] JS extractor znajduje API paths z bundled JS.
- [ ] Deprecated endpoint finding zawiera: sciezka, wersja, kod odpowiedzi, czy wymaga autoryzacji.
- [ ] API docs exposure finding zawiera: URL, typ spec (swagger/openapi), liczba endpoints ujawnionych.
- [ ] Admin fuzz bounded do 20 requestow per scan.
- [ ] Backup file exposure nie loguje full content pliku — tylko typ i pierwsze 256 bajtow.

### Podział pracy — codex-dad

Wiekszosc pracy (A1, A2, A3, B1, B2, B3, C1, C2, C3): codex-dad — kompleksowa logika crawlera i strategii.
Playbooki i testy (B4–B6, D1, D2): codex-main.
Rejestracja (C4): Claude.

### Post-sprint: przeglad skillow

Czy pojawil sie nowy powtarzalny pattern? Jesli tak - zaktualizuj lub dodaj skill w `.workflow/skills/`. Regula: pattern >= 2x -> skodyfikuj.
