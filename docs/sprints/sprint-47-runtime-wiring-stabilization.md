## Sprint 47 - Runtime Wiring Stabilization

**Goal:** Ustabilizowac wiring runtime: aplikacja startuje, endpointy sa podpiete, a scan lifecycle nie zostawia martwych skanow bez jobow.

Ten sprint jest warstwa fundamentu. Bez niego kolejne capability beda poprawne na papierze, ale potkna sie o routing, env, packaging albo kolejki.

### Architektura - dokumenty referencyjne

```bash
DAD_PROMPT="cd /mnt/d/BreachForge && Read docs/architecture/attack-engine.md and docs/architecture/security-constraints.md. Extract: scan FSM, RQ job flow, package/runtime entrypoints, worker isolation invariants. Bullets. Max 25 lines." bash ~/.claude/scripts/dad-exec.sh
```

### Workstream A - API routing i packaging

| ID | Zadanie | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| A1 | Podpiac `recon_router` w `api/routers/__init__.py` i `api/main.py` | `api/routers/__init__.py`, `api/main.py` | codex-main | API route tests | `/recon/har` i `/recon/spec` widoczne w OpenAPI |
| A2 | Dodac `execution_plane` do wheel packages | `pyproject.toml` | codex-main | package/import smoke | installowany pakiet zawiera planner/crawler/workers/validator |
| A3 | Dodac brakujaca zaleznosc `PyYAML` | `pyproject.toml` | codex-main | import smoke | `api.routers.recon` importuje sie po installu |

### Workstream B - DB/session import safety

| ID | Zadanie | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| B1 | Zamien import-time `os.environ["DATABASE_URL"]` na lazy engine init z kontrolowanym bledem runtime | `storage/db/session.py` | codex-main | health smoke | `import api.main` nie crashuje bez DB env |
| B2 | Dodaj test: `/health` nie wymaga DB connection | `tests/unit/api/test_health.py` lub istniejące API tests | codex-main | pytest | health endpoint dziala w minimalnym env |

### Workstream C - Unauth scan lifecycle z API

| ID | Zadanie | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| C1 | `create_scan()` dla `unauth_mode=True` ustawia phase `recon`, nie `auth_bootstrap` | `api/routers/scans.py` | codex-main | API tests | scan bez auth nie wisi w `running/auth_bootstrap` |
| C2 | Enqueue recon job albo wywolaj orchestrator path dla unauth scan | `api/routers/scans.py` | codex-main | queue stub tests | unauth scan ma realny nastepny job |
| C3 | Enqueue failure ma fail-closed: scan `failed`, API 503, log bez sekretow | `api/routers/scans.py` | codex-main | API tests | cichy blad kolejki nie zostawia running scan |

### Workstream D - Crawler accepts unauth scans

| ID | Zadanie | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| D1 | `run_crawler()` nie wymaga `AuthContext`, jesli `Target.config.unauth_mode=True` | `execution_plane/crawler/engine.py` | codex-dad | crawler integration tests | unauth scan bez AuthContext przechodzi recon |
| D2 | Dla auth_type `none` uzyj empty `SessionSnapshot` bez bootstrapu AuthManager | `execution_plane/crawler/engine.py` | codex-dad | unit tests | brak KMS/auth dependency dla unauth crawl |
| D3 | Zachowaj fail-closed dla auth scan bez AuthContext | `execution_plane/crawler/engine.py` | codex-dad | regression tests | auth scan nadal wymaga sesji |

### Guardrails

- Brak `DATABASE_URL` moze blokowac endpointy DB, ale nie import calej aplikacji ani `/health`.
- Unauth scan nie moze ominac scope/rate/proof-gate.
- Enqueue failure musi byc widoczny w statusie skanu.
- Nie dodawac fallbackow typu global localhost DB w produkcyjnym kodzie.

### Weryfikacja

```bash
python -c "import api.main"
python -m pytest tests/unit/api/ -q
python -m pytest tests/unit/execution_plane/crawler/ -q
python -m pytest tests/integration/test_unauth_scan_e2e.py -q
python -m pytest tests/unit/ -q
```

### Global acceptance criteria

- [x] `GET /health` dziala bez skonfigurowanej bazy.
- [x] `/recon/har` i `/recon/spec` sa aktywne.
- [x] `POST /scans` z `unauth_mode=true` uruchamia recon path.
- [x] Brak scanow stuck w `running/auth_bootstrap` bez auth joba.
- [x] Crawler obsluguje unauth scan bez AuthContext.

### Podzial pracy - codex-dad

D1-D3 ida do **codex-dad**, bo `engine.py` jest duzy i dotyka runtime lifecycle. A-C robi **codex-main** jako lokalne wiring fixes.

### Post-sprint: przeglad skillow

Jesli pojawi sie kolejny pattern "route exists but not mounted", dodaj test/skill review-ready-diff dla router wiring.

### Evidence log

- [2026-05-11] A1-A3: `recon_router` exported and mounted; `execution_plane` added to wheel packages; `PyYAML` dependency present. Smoke import for `yaml`, `api.routers.recon`, planner, crawler, workers, validator passed.
- [2026-05-11] B1-B2: DB session factory is lazy; `import api.main` and `/health` work without `DATABASE_URL`. Covered by `tests/unit/api/test_runtime_wiring.py`.
- [2026-05-11] C1-C3: unauth scan API sets `running/recon`, enqueues `execution_plane.crawler.engine.run_crawler`, and marks scan `failed` with API `503` on enqueue failure. Covered by `tests/integration/test_scan_api.py`.
- [2026-05-11] D1-D3: delegated to codex-dad. `run_crawler()` accepts unauth scans without `AuthContext`, uses empty `SessionSnapshot` for auth type `none`, and preserves fail-closed behavior for authenticated scans without `AuthContext`.

### Verification results

```bash
python -c "import os; os.environ.pop('DATABASE_URL', None); import api.main"
# PASS

python -m pytest tests/unit/api/ -q
# 4 passed

python -m pytest tests/integration/test_scan_api.py tests/integration/test_unauth_scan_e2e.py tests/unit/execution_plane/crawler/ -q
# 17 passed

python -c "import yaml; import api.routers.recon; import execution_plane.planner.planner; import execution_plane.crawler.engine; import execution_plane.workers.attack_worker; import execution_plane.validator.validator"
# PASS

python -m pytest tests/unit/ -q
# 490 passed

python -m pytest tests/ -q
# 549 passed
```

### Review

- No blocking findings in Sprint 47 scope.
- Guardrails preserved: DB absence no longer breaks import or health; unauth scan does not bypass crawler scope handling; enqueue failure is visible in scan status; no production localhost DB fallback added.
- Existing unrelated worktree changes are outside Sprint 47 review scope and were not reverted.

### Decision

Ship: yes - Sprint 47 acceptance criteria met with full test suite passing.
