## Sprint 60 - Operator Grade Auth And Discovery

**Goal:** Podniesc auth i discovery do poziomu, na ktorym czysty raport nie oznacza slepego skanu: sesje, role, HAR/OpenAPI/JS i health checks musza miec mierzalna skutecznosc.

### Architektura - dokumenty referencyjne

```bash
DAD_PROMPT="cd /mnt/d/BreachForge && Read docs/architecture/auth-architecture.md, docs/architecture/attack-engine.md and docs/sprints/sprint-49-session-import-hardening.md. Extract auth/discovery blind spots and invariants. Bullets. Max 35 lines." bash ~/.claude/scripts/dad-exec.sh
```

### Workstream A - Auth reliability score

| ID | Zadanie | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| A1 | Auth coverage metrics: session_valid, role_count, tenant_count, health_check_pass_rate | `control_plane/auth_manager.py`, `control_plane/reporting.py` | codex-main | auth tests | raport pokazuje jak dobrze skan byl zalogowany |
| A2 | Per-identity failure reasons: expired, missing, forbidden, csrf_failed, refresh_failed | `control_plane/auth_manager.py`, `execution_plane/workers/dispatcher.py` | codex-dad | worker/session tests | brak cichych pominiec identity |
| A3 | Session import verifier: probe auth-required endpoint przed attack planning | `api/routers/session.py`, `control_plane/orchestrator.py` | codex-main | integration | zla sesja blokuje albo degraduje scan jawnie |

### Workstream B - Discovery completeness

| ID | Zadanie | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| B1 | AssetMap source attribution: crawler/HAR/OpenAPI/JS/wordlist/manual | `execution_plane/crawler/asset_map.py`, storage models | codex-dad | crawler tests | kazdy endpoint ma zrodlo |
| B2 | Discovery coverage score: expected_surface vs discovered_surface w benchmark labs | `scripts/benchmark_lab.py`, `control_plane/reporting.py` | codex-main | benchmark | widzimy blind spots przed attack coverage |
| B3 | JS endpoint extraction hardening: sourcemaps, relative routes, fetch/axios/graphql patterns | `execution_plane/crawler/js_endpoint_extractor.py` | codex-main | corpus tests | SPA lab endpointy odkryte |

### Workstream C - Operator UX

| ID | Zadanie | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| C1 | Report "Scan Blind Spots": auth, discovery, policy, skipped classes | `control_plane/reporting.py` | codex-main | reporting tests | klient wie czego nie przetestowano |
| C2 | API endpoint for scan readiness/preflight | `api/routers/scans.py`, `api/models/responses.py` | codex-main | API tests | mozna sprawdzic scan zanim ruszy |
| C3 | Benchmark asserts: discovery_coverage >= target before finding coverage gates | `scripts/benchmark_lab.py` | codex-main | metrics tests | benchmark nie ukrywa slepego crawla |

### Guardrails

- Auth failures nie moga przechodzic jako successful scan.
- Redakcja credentials w logach i audit events zostaje nienaruszona.
- Discovery score nie moze udawac potwierdzonych findingow.

### Weryfikacja

```bash
python -m pytest tests/unit/control_plane/test_auth_manager.py -q
python -m pytest tests/unit/execution_plane/crawler/ -q
python -m pytest tests/unit/control_plane/test_reporting.py -q
python scripts/benchmark_lab.py --full --lab all
python -m pytest tests/unit/ -q
```

### Global acceptance criteria

- [ ] Raport pokazuje auth reliability i discovery coverage.
- [ ] Session import jest walidowany przed atakiem.
- [ ] Endpointy maja source attribution.
- [ ] Blind spots sa widoczne w benchmarku i raporcie.

### Podzial pracy - codex-dad

A2 i B1 ida do **codex-dad** jako context-heavy implementation. Reszte robi **codex-main**.
