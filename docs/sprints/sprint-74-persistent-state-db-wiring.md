## Sprint 74 — Persistent State: DB Wiring

**Goal:** Podłączyć istniejący kod do istniejącego schematu DB (migracja 20260528100000 już istnieje).
Usunąć wszystkie in-memory module-level stores, które giną po restarcie procesu API.

### Problem

Migracja `20260528100000_add_saas_org_project_rbac_apikeys.py` tworzy tabele:
`organizations`, `projects`, `service_groups`, `org_members`, `api_keys`, `service_tokens`.

Kod ich **nie używa**:
- `api/routers/orgs.py` → `_ORG_STORE: dict[UUID, OrgResponse] = {}`
- `api/routers/api_keys.py` → `_API_KEYS: dict[UUID, _StoredAPIKey] = {}` (TODO w kodzie)
- `api/middleware/rbac.py` → `RoleStore._roles: dict[...]` in-memory
- `api/routers/runners.py` → `_registry = RunnerRegistry()` (in-memory instance)

Efekt: restart API = utrata wszystkich org, kluczy API, uprawnień i runnerów.

### Scope — tylko wiring, bez nowych funkcji

**Nie zmieniamy:**
- schematu DB (migracja istnieje)
- logiki biznesowej RBAC
- API contracts (request/response shapes)
- flow autentykacji (Sprint 75)

**Zmieniamy:**
- backend storage każdego store'a: dict → `AsyncSession` + ORM query

### Architektura — dokumenty referencyjne

```bash
{
  echo "=== FILE: data-model.md ==="; cat ~/Projects/BreachForge/docs/architecture/data-model.md
  echo "=== FILE: storage-infra.md ==="; cat ~/Projects/BreachForge/docs/architecture/storage-infra.md
} | gemini --output-format text \
  -p "Files above. Extract: ORM patterns for async SQLAlchemy used in this codebase, DB session injection pattern, existing CRUD examples. Bullets. Max 20 lines." \
  2>&1 | grep -v "^Warning:" | grep -v "^Ripgrep"
```

### Workstream A — Org i API Keys persistence

| ID | Zadanie | Pliki | Worker |
|---|---|---|---|
| A1 | `orgs.py`: zastąp `_ORG_STORE` → async CRUD na tabeli `organizations` | `api/routers/orgs.py` | codex-dad |
| A2 | `api_keys.py`: zastąp `_API_KEYS` → async CRUD na tabeli `api_keys` z haszowaniem SHA-256 | `api/routers/api_keys.py` | codex-dad |
| A3 | ORM models dla `Organization`, `Project`, `OrgMember`, `APIKey` w `storage/db/models.py` | `storage/db/models.py` | codex-dad |

### Workstream B — RBAC i Runner Registry persistence

| ID | Zadanie | Pliki | Worker |
|---|---|---|---|
| B1 | `rbac.py`: zastąp `RoleStore._roles` → async query na `org_members` | `api/middleware/rbac.py` | codex-dad |
| B2 | `runners.py`: zastąp `_registry = RunnerRegistry()` → nowa migracja `runners` table + async CRUD | `api/routers/runners.py`, nowa migracja | codex-dad |

### Workstream C — Testy persistence

| ID | Zadanie | Pliki | Worker |
|---|---|---|---|
| C1 | Testy: org/API-key CRUD survives restart simulation (mock session, verify DB calls) | `tests/unit/api/routers/test_orgs.py`, `test_api_keys.py` | codex-main |
| C2 | Testy: `require_role()` wywołuje DB query, nie pamięć procesu | `tests/unit/api/middleware/test_rbac.py` | codex-main |

### Dispatch pattern

**Phase 1 (parallel):** dad → A3 (models must exist first)
**Phase 2 (parallel, po A3):** dad → A1, A2, B1, B2 równolegle; main → C1, C2
**Zależność:** A1/A2/B1 importują modele z A3 → A3 musi być gotowe przed resztą

### Guardrails

- Każde query do DB musi przyjmować `AsyncSession` przez FastAPI `Depends()` — bez global DB connection
- `key_hash` w `api_keys` to SHA-256 plaintext klucza — nigdy plaintext w DB
- `RoleStore` class może pozostać jako adapter (nie usuwamy klasy, zmieniamy backend)
- Żadne `await session.execute()` bez `try/except` z rollback

### Weryfikacja

```bash
python -m pytest tests/unit/api/routers/test_orgs.py tests/unit/api/routers/test_api_keys.py \
  tests/unit/api/middleware/test_rbac.py -q

# Sprawdź że nie ma żadnych module-level dict stores:
grep -rn "^_[A-Z].*=\s*{}\|^_[A-Z].*=\s*\[\]" api/routers/ api/middleware/ --include="*.py"
# Wynik: 0 linii (brak in-memory stores)
```

### TL_PROMPT

```bash
TL_PROMPT="Read ~/Projects/BreachForge/.workflow/skills/testing-lead.md and follow it.
Sprint: 74 - Persistent State DB Wiring
Changed: api/routers/orgs.py, api/routers/api_keys.py, api/middleware/rbac.py, api/routers/runners.py, storage/db/models.py
Test cases:
- Org CRUD operacje trafiają do bazy danych (nie in-memory dict)
- API key create/revoke używa tabeli api_keys z hash kluczy
- require_role() odpytuje tabelę org_members z bazy
- Brak module-level dict stores w api/routers/ i api/middleware/" bash ~/.claude/scripts/testing-lead-exec.sh < /dev/null
```

### Global acceptance criteria

- [ ] Brak `^_[A-Z].*= {}` i `^_[A-Z].*= \[\]` w `api/routers/` i `api/middleware/` (grep zwraca 0)
- [ ] Org create/get/list używa tabeli `organizations`
- [ ] API key create/revoke używa tabeli `api_keys`, hash SHA-256 w DB
- [ ] `require_role()` odpytuje `org_members` przez `AsyncSession`
- [ ] Nowa migracja dla tabeli `runners` (jeśli RunnerRegistry tego wymaga)
- [ ] Wszystkie testy zielone: `python -m pytest tests/unit/ -q --ignore=tests/unit/scripts`
