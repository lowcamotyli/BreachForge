## Sprint 44 - Pre-Auth Recon Pack

**Goal:** Budowa warstwy wejściowej która dostarcza kontekst PRZED i BEZ autoryzacji: import sesji z przeglądarki, HAR import, OpenAPI/Postman/Insomnia import, wzbogacony JS mining i public baseline differential.

Ten sprint zmienia BreachForge z narzędzia wymagającego credentials na narzędzie które dostaje maksymalny kontekst z tego co użytkownik MA — przechwycona sesja, nagrany ruch, spec API.

### Architektura - dokumenty referencyjne

```bash
DAD_PROMPT="Read /mnt/d/BreachForge/docs/architecture/auth-architecture.md and attack-engine.md. Extract: SessionSnapshot structure, AssetMap schema, how crawler feeds planner, recon phase constraints, identity context fields. Bullets. Max 25 lines." bash ~/.claude/scripts/dad-exec.sh
```

### Workstream A - Browser Session Import

| ID | Zadanie | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| A1 | `BrowserSessionImporter`: Playwright otwiera URL, czeka 5s, przechwytuje cookies + localStorage + sessionStorage; produkuje `SessionSnapshot` bez znajomosci hasla | `control_plane/auth_manager.py` (edit — nowa metoda `import_from_browser`) | **codex-dad** | auth tests | SessionSnapshot z przechwyconymi cookies; haslo nigdy nie jest potrzebne |
| A2 | CLI endpoint: `POST /session/import` z `{ "url": "...", "wait_seconds": 5 }` — zwraca session_id | `api/routers/session.py` (new) | **codex-dad** | API tests | endpoint zwraca session_id i summary (domain, cookie_count, has_auth_token) |
| A3 | Session health check po imporcie: weryfikuje czy sesja ma dostep do co najmniej 1 authenticated endpoint | `control_plane/auth_manager.py` | **codex-dad** | auth tests | import bez sesji = warning, nie error; scan kontynuuje jako unauth |

### Workstream B - HAR Import

| ID | Zadanie | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| B1 | `HarImporter`: parsuje HAR v1.2 JSON, buduje AssetMap z entries — ekstrahuje: URL, method, request headers, response status, content-type, timing | `execution_plane/crawler/har_importer.py` (new) | **codex-dad** | crawler tests | AssetMap z HAR ma te same pola co AssetMap z Playwright crawl |
| B2 | Cookie extraction z HAR: Set-Cookie headers w HAR entries → automatycznie produkuje SessionSnapshot (jesli zawiera sesyjne cookies) | `execution_plane/crawler/har_importer.py` | **codex-dad** | tests | sesja z HAR = identity context dostepny dla planera |
| B3 | Body schema inference z HAR: request body JSON → ekstrakcja pol → hints dla mass_assignment, injection, bola rules | `execution_plane/crawler/har_importer.py` | **codex-dad** | tests | body fields sa rejestrowane w AssetMap jako `body_schema` |
| B4 | CLI endpoint: `POST /recon/har` z multipart HAR file | `api/routers/recon.py` (new or edit) | **codex-dad** | API tests | endpoint zwraca asset_count, identity_found bool, endpoint_count |

### Workstream C - OpenAPI / Postman / Insomnia Import

| ID | Zadanie | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| C1 | `SpecImporter`: parsuje OpenAPI 3.x i Swagger 2.0 JSON/YAML — buduje AssetMap z `paths`, `parameters`, `requestBody`, `securitySchemes` | `execution_plane/crawler/spec_importer.py` (new) | **codex-dad** | crawler tests | kazdy path w spec = endpoint w AssetMap z method, params, schema |
| C2 | Postman Collection v2.1 parser: extrahuje items → endpoints, pre-request scripts jako body hints | `execution_plane/crawler/spec_importer.py` | **codex-dad** | tests | Postman collection daje endpoint_count zbliżony do OpenAPI |
| C3 | Insomnia v4 parser: extrahuje resources → requests | `execution_plane/crawler/spec_importer.py` | **codex-dad** | tests | Insomnia export parsowany poprawnie |
| C4 | Security scheme extraction: `securitySchemes` w OpenAPI → typy auth (bearer, apiKey, oauth2) jako hints dla jwt_attack, oauth rules | `execution_plane/crawler/spec_importer.py` | **codex-dad** | tests | security schemes registrowane w AssetMap jako `auth_hints` |
| C5 | CLI endpoint: `POST /recon/spec` z multipart file (json/yaml/json) | `api/routers/recon.py` | **codex-dad** | API tests | endpoint przyjmuje OpenAPI, Postman, Insomnia |

### Workstream D - Enhanced JS Mining & Public Sources

| ID | Zadanie | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| D1 | Sourcemap parser: jesli `*.js.map` dostepny — ekstrahuje oryginalne sciezki plikow i importowane moduły jako hints do endpoint discovery | `execution_plane/crawler/js_endpoint_extractor.py` (edit — add sourcemap) | **codex-dad** | crawler tests | sourcemap routes sa w AssetMap |
| D2 | robots.txt + sitemap.xml extractor: parsuje w recon phase bez dodatkowej konfiguracji | `execution_plane/crawler/recon_engine.py` (edit) | **codex-dad** | crawler tests | robots/sitemap paths sa w AssetMap z flagą `unauth_discovered: true` |
| D3 | Error page path disclosure: 404 responses ktore ujawniaja internal paths (stack traces, file paths) — ekstrahuje jako AssetMap hints | `execution_plane/crawler/recon_engine.py` (edit) | **codex-dad** | tests | paths z 404 error body sa oznaczone `source: error_disclosure` |

### Workstream E - Public Baseline Differential

| ID | Zadanie | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| E1 | `UnauthBaselineProber`: dla kazdego endpointu z AssetMap wykonuje probe bez credentials (usuniete auth headers) i rejestruje: status, response_size, content-type, cache headers | `execution_plane/workers/unauth_baseline.py` (new) | **codex-dad** | worker tests | baseline dostepny jako `unauth_response` w evidence |
| E2 | Differential engine: porownuje unauth_response vs auth_response — roznica statusu, roznica rozmiaru body, roznica pol JSON = input dla auth_bypass, bola, sensitive_exposure planners | `execution_plane/workers/unauth_baseline.py` | **codex-dad** | tests | diff jest strukturalny (pola JSON), nie text diff |
| E3 | Playbook public baseline | `execution_plane/planner/playbooks/public_baseline_differential.yaml` (new) | codex-main | corpus tests | max_requests: 1 per endpoint, rate: 0.5 RPS |

### Workstream F - Secret-to-Impact Bez Credentials

| ID | Zadanie | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| F1 | Jesli sensitive_exposure finding zawiera token/API key — skaner moze wykonac read-only replay tym znalezionym tokenem BEZ logowania sie jako uzytkownik | `execution_plane/workers/attack_worker.py` (edit) | **codex-dad** | worker tests | replay uzywa znalezionego tokenu jako Bearer; nigdy nie zapisuje go do logow |
| F2 | Safe replay policy: znaleziony token jest uzywany TYLKO do GET requests na in-scope endpoints; brak mutations | `execution_plane/workers/attack_worker.py` | **codex-dad** | guardrail tests | mutation z discovered token = blocked |
| F3 | Playbook unauth-secret-replay | `execution_plane/planner/playbooks/unauth_secret_replay.yaml` (new) | codex-main | corpus tests | max_requests: 3, GET-only |

### Guardrails

- Browser session import nigdy nie prosi o haslo — tylko przechwytuje juz istniejaca sesje przegladarki.
- HAR moze zawierac credentials w Authorization headers — sa redagowane przed zapisem do EvidenceStore.
- Spec import jest czysto statyczny — nie wysyla zadnych requestow do aplikacji.
- Unauth baseline probe jest rate-limited identycznie jak auth probes — nie jest szybszy.
- Secret-to-impact replay — TYLKO GET, TYLKO in-scope, brak credentials w logach.

### Weryfikacja

```bash
"/c/Program Files/Python312/python.exe" -m pytest tests/unit/execution_plane/crawler/ -q
"/c/Program Files/Python312/python.exe" -m pytest tests/unit/control_plane/test_auth_manager.py -q
"/c/Program Files/Python312/python.exe" -m pytest tests/unit/execution_plane/workers/ -q
"/c/Program Files/Python312/python.exe" -m pytest tests/unit/ -q
```

### Global acceptance criteria

- [ ] HAR import produkuje AssetMap z >= 80% endpoints ktore sa tez w Playwright crawl (na tym samym target).
- [ ] OpenAPI import pokrywa 100% paths z spec.
- [ ] Browser session import produkuje valid SessionSnapshot bez znajomosci hasla.
- [ ] Sourcemap i robots.txt sa parsowane automatycznie w recon phase.
- [ ] Unauth baseline differential dostarcza diff dla auth_bypass i sensitive_exposure planners.
- [ ] Secret-to-impact replay jest GET-only i in-scope.

### Podział pracy — codex-dad

Wiekszosc pracy (A1–A3, B1–B4, C1–C5, D1–D3, E1–E2, F1–F2): codex-dad — kompleksowe moduły parsowania i integracje z core.
Playbooki (E3, F3): codex-main.

### Post-sprint: przeglad skillow

Czy pojawil sie nowy powtarzalny pattern? Jesli tak - zaktualizuj lub dodaj skill w `.workflow/skills/`. Regula: pattern >= 2x -> skodyfikuj.
