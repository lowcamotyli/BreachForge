## Sprint 49 - Session Import Hardening

**Goal:** Utwardzic `/session/import`, zeby nie byl SSRF-em, memory leakiem ani blokujaca operacja browserowa bez limitow.

### Architektura - dokumenty referencyjne

```bash
DAD_PROMPT="cd /mnt/d/BreachForge && Read docs/architecture/auth-architecture.md and docs/architecture/security-constraints.md. Extract: credential handling, session snapshot constraints, logging redaction, scope invariants. Bullets. Max 25 lines." bash ~/.claude/scripts/dad-exec.sh
```

### Workstream A - URL and SSRF guardrails

| ID | Zadanie | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| A1 | Walidacja `url`: tylko `http`/`https`, poprawny host, brak pustych URL | `api/routers/session.py` | codex-main | API tests | `file://`, `ftp://`, puste URL zablokowane |
| A2 | DNS/IP guard: blokuj localhost, private, link-local, loopback, metadata IP | `api/routers/session.py` lub helper | codex-main | SSRF tests | `127.0.0.1`, `10/8`, `169.254.169.254` zablokowane |
| A3 | Limit redirectow i timeout dla health check/import | `control_plane/auth_manager.py` | codex-main | auth tests | brak nieskonczonego czekania |

### Workstream B - Browser execution safety

| ID | Zadanie | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| B1 | `BrowserSessionImporter` uzywa `headless=True` w API flow | `control_plane/auth_manager.py` | codex-main | unit tests | server nie otwiera widocznego browsera |
| B2 | `wait_seconds` ma `ge=0`, `le=30` | `api/routers/session.py` | codex-main | API tests | request nie blokuje workerow minutami |
| B3 | Ogranicz rozmiar cookies/localStorage/sessionStorage | `control_plane/auth_manager.py` | codex-main | auth tests | gigantyczna storage nie zjada pamieci |

### Workstream C - Session store lifecycle

| ID | Zadanie | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| C1 | Zastap globalny dict TTL store albo Redis-backed transient store | `api/routers/session.py` | codex-dad | API/store tests | sesje wygasaja automatycznie |
| C2 | Dodaj limit liczby sesji per process/scan | `api/routers/session.py` | codex-dad | tests | brak unbounded memory growth |
| C3 | Dodaj audyt importu bez sekretow | `api/routers/session.py`, `api/middleware/logging.py` | codex-main | logging tests | log ma domain/count, nie raw cookies/tokeny |

### Guardrails

- Endpoint nie moze byc uzyty jako proxy do internal network.
- Raw cookies/tokens nie trafiaja do logow.
- Import sesji jest dev/staging safe; production exposure wymaga dodatkowej auth policy.

### Weryfikacja

```bash
python -m pytest tests/unit/control_plane/test_auth_manager.py -q
python -m pytest tests/unit/api/ -q
python -m pytest tests/integration/test_auth_check.py -q
python -m pytest tests/unit/ -q
```

### Global acceptance criteria

- [ ] Private/internal hosty sa blokowane.
- [ ] `wait_seconds` i storage size maja twarde limity.
- [ ] Session store ma TTL i bounded size.
- [ ] Browser import nie loguje sekretow.

### Podzial pracy - codex-dad

C1-C2 ida do **codex-dad**, bo zmieniaja lifecycle store. A-B i C3 robi **codex-main**.
