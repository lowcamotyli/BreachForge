## Sprint 75 — Real Auth: API Key Verification

**Goal:** Zastąpić `X-Actor-Email` header trust realną weryfikacją `Authorization: Bearer <key>` przeciwko tabeli `api_keys` w DB.
Po tym sprincie tożsamość aktora pochodzi wyłącznie z zweryfikowanego klucza — fałszowanie headera nie daje uprawnień.

**Zależy od:** Sprint 74 (persistent `api_keys` table + ORM models)

### Problem

```python
# api/middleware/rbac.py — aktualne zachowanie
actor_email: str | None = Header(default=None, alias="X-Actor-Email"),
```

Każdy klient może wysłać `X-Actor-Email: admin@company.com` i uzyskać uprawnienia admina.
Brak weryfikacji tokenu. Brak JWT. Brak API key lookup. To jest dev shortcut w kodzie produkcyjnym.

### Scope

**Zmieniamy:**
- Dodajemy `api/dependencies/auth.py` z FastAPI dependency `get_verified_actor()`
- `get_verified_actor()` weryfikuje `Authorization: Bearer <key>` → lookup w DB → zwraca `VerifiedActor(org_id, email, role)`
- `require_role()` przyjmuje `VerifiedActor` zamiast ufać headerowi `X-Actor-Email`
- `X-Actor-Email` header → ignorowany w prod, fallback dev mode za env flag

**Nie zmieniamy:**
- Flow autentykacji skanów (Playwright browser sessions — to inna warstwa)
- JWT dla end-users (poza scope beta v1 — API keys wystarczą)
- Kształt API (request/response)

### Architektura — dokumenty referencyjne

```bash
cat ~/Projects/BreachForge/docs/architecture/security-constraints.md \
  | gemini --output-format text \
  -p "List ALL constraints around API authentication, actor identity, and token verification in this system. No summaries — every rule. Bullets." \
  2>&1 | grep -v "^Warning:" | grep -v "^Ripgrep"
```

### Workstream A — Auth dependency

| ID | Zadanie | Pliki | Worker |
|---|---|---|---|
| A1 | `api/dependencies/auth.py`: `get_verified_actor()` — verifies Bearer token against `api_keys.key_hash` SHA-256, returns `VerifiedActor` dataclass | `api/dependencies/auth.py` (nowy) | codex-dad |
| A2 | `api/dependencies/auth.py`: dev mode bypass — `PROOFSCAN_DEV_MODE=1` pozwala na `X-Actor-Email` fallback (gate musi być explicit, nie default) | `api/dependencies/auth.py` | codex-dad |

### Workstream B — RBAC update

| ID | Zadanie | Pliki | Worker |
|---|---|---|---|
| B1 | `api/middleware/rbac.py`: `require_role()` przyjmuje `VerifiedActor` z `Depends(get_verified_actor)` zamiast raw headera | `api/middleware/rbac.py` | codex-dad |
| B2 | Zaktualizuj wszystkie endpointy które używają `require_role()` — zastąp `Header(alias="X-Actor-Email")` zależnością auth | `api/routers/scans.py`, `api/routers/api_keys.py`, `api/routers/orgs.py`, `api/routers/runners.py`, `api/routers/audit.py` | codex-dad |

### Workstream C — Testy

| ID | Zadanie | Pliki | Worker |
|---|---|---|---|
| C1 | Test: request bez Authorization → 401 | `tests/unit/api/dependencies/test_auth.py` (nowy) | codex-main |
| C2 | Test: request z ważnym Bearer key → `VerifiedActor` poprawnie rozwiązany | `tests/unit/api/dependencies/test_auth.py` | codex-main |
| C3 | Test: `X-Actor-Email` header bez Bearer token → 401 (w trybie prod) | `tests/unit/api/dependencies/test_auth.py` | codex-main |
| C4 | Test: revoked API key → 401 | `tests/unit/api/dependencies/test_auth.py` | codex-main |

### Dispatch pattern

**Phase 1:** dad → A1, A2 (muszą być przed B)
**Phase 2 (po A1/A2):** dad → B1, B2 równolegle; main → C1-C4
**Zależność:** B1 importuje `VerifiedActor` z A1; B2 wymaga B1 (nowy `require_role` signature)

### Guardrails

- Lookup `api_keys` musi sprawdzać `revoked_at IS NULL` i `(expires_at IS NULL OR expires_at > NOW())`
- `VerifiedActor` musi zawierać: `org_id: UUID`, `email: str`, `role: OrgRole`
- Dev mode bypass (`PROOFSCAN_DEV_MODE=1`) musi być udokumentowany z explicit warning w logu przy starcie
- Żadnego `if DEBUG:` w middleware — tylko explicit env var check
- `key_hash` verification: `hashlib.sha256(raw_key.encode()).hexdigest()` — ten sam algorytm co przy tworzeniu klucza (Sprint 74)

### Weryfikacja

```bash
python -m pytest tests/unit/api/dependencies/test_auth.py \
  tests/unit/api/middleware/test_rbac.py \
  tests/unit/api/routers/test_scans.py -q

# Sprawdź że X-Actor-Email nie jest ufany bez weryfikacji:
grep -rn "X-Actor-Email\|actor_email" api/routers/ api/middleware/ --include="*.py"
# Wynik: tylko w auth.py jako fallback za DEV_MODE gate

# Sprawdź że DEV_MODE gate istnieje:
grep -rn "PROOFSCAN_DEV_MODE\|DEV_MODE" api/dependencies/auth.py
```

### TL_PROMPT

```bash
TL_PROMPT="Read ~/Projects/BreachForge/.workflow/skills/testing-lead.md and follow it.
Sprint: 75 - Real Auth API Key Verification
Changed: api/dependencies/auth.py, api/middleware/rbac.py, api/routers/scans.py, api/routers/api_keys.py, api/routers/orgs.py
Test cases:
- Request bez Authorization header zwraca 401
- Request z ważnym Bearer API key zwraca poprawnie zidentyfikowany aktor
- Request z revoked API key zwraca 401
- X-Actor-Email header bez Bearer token zwraca 401 w trybie prod (PROOFSCAN_DEV_MODE nie jest ustawiony)
- PROOFSCAN_DEV_MODE=1 pozwala na X-Actor-Email fallback (dev only)" bash ~/.claude/scripts/testing-lead-exec.sh < /dev/null
```

### Global acceptance criteria

- [ ] `api/dependencies/auth.py` istnieje z `get_verified_actor()` dependency
- [ ] Brak endpointów które ufają `X-Actor-Email` bez weryfikacji tokenu (w trybie prod)
- [ ] `VerifiedActor(org_id, email, role)` pochodzi wyłącznie z DB lookup
- [ ] Dev mode bypass jest explicit (`PROOFSCAN_DEV_MODE=1`) i loguje warning
- [ ] Testy: 401 bez tokenu, 401 z revoked key, 200 z ważnym key
- [ ] `python -m pytest tests/unit/ -q --ignore=tests/unit/scripts` — zielone
