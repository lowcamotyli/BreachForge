## Sprint 2 — AuthManager + API Skeleton

**Goal:** AuthManager z Playwright login flows, session cookie escape hatch, scan creation endpoint.

### Architektura — dokumenty referencyjne

```bash
DAD_PROMPT="Read /mnt/d/SimpliAppSec/docs/architecture/auth-architecture.md. List ALL auth input types, login flow steps, session health rules, escape hatch requirements. Bullets. Max 25 lines." bash ~/.claude/scripts/dad-exec.sh
```

### Graf zależności

```
api/models/requests.py ──┐
api/models/responses.py ─┤ parallel
                         ↓
control_plane/auth_manager.py ─────────────────── codex-main (complex Playwright)
api/routers/scans.py ──────────────────────────── codex-dad (po models)
tests/unit/control_plane/test_auth_manager.py ──── po auth_manager
```

### Dispatch table

| Plik | Worker | Skill | Uwagi |
|------|--------|-------|-------|
| `api/models/requests.py` + `responses.py` | codex-dad | `skill:scoped-implementation` | Pydantic v2 schemas |
| `control_plane/auth_manager.py` | codex-main | `skill:safe-sensitive-change` | Playwright — wrażliwy, Claude review |
| `api/routers/scans.py` | codex-dad | `skill:scoped-implementation` | parallel z auth_manager |
| `tests/unit/control_plane/test_auth_manager.py` | codex-main | `skill:test-impact-check` | po auth_manager |

### Prompty

```bash
# codex-dad — API models (batch)
DAD_PROMPT='Read /mnt/d/SimpliAppSec/.workflow/skills/scoped-implementation.md and follow its procedure.
Read /mnt/d/SimpliAppSec/docs/architecture/auth-architecture.md.
Goal: Create Pydantic v2 request/response models.
Files:
- /mnt/d/SimpliAppSec/api/models/requests.py — ScanCreate (target_url, auth_context: AuthContextCreate), AuthContextCreate (type: credential|session|token|none, credentials optional, cookies optional, bearer_token optional, login_recipe optional JSON)
- /mnt/d/SimpliAppSec/api/models/responses.py — ScanResponse (id, status, phase, created_at), FindingResponse (id, title, severity, attack_class, affected_endpoint), ReportResponse (scan_id, findings list, generated_at)
from __future__ import annotations at top. Done when: both files exist.' bash ~/.claude/scripts/dad-exec.sh

# codex-main — AuthManager (safe-sensitive-change skill)
codex exec --dangerously-bypass-approvals-and-sandbox \
'Read d:/SimpliAppSec/.workflow/skills/safe-sensitive-change.md and follow its procedure.
Read d:/SimpliAppSec/docs/architecture/auth-architecture.md for context (ask dad to summarize if blocked).
Read d:/SimpliAppSec/storage/db/models.py for AuthContext entity.
Do NOT use Gemini — write directly.
Goal: Implement AuthManager in d:/SimpliAppSec/control_plane/auth_manager.py
Requirements:
- SessionSnapshot dataclass: scan_id, cookies list, auth_headers dict, csrf_tokens dict, captured_at, expires_at optional
- AuthManager class with: bootstrap(auth_input) dispatching to _from_cookies / _from_bearer / _playwright_login
- _playwright_login executes login_recipe JSON steps: navigate/fill/click/wait_for_url actions
- _health_loop: asyncio loop every 300s, probes authenticated endpoint, calls _attempt_refresh or scan.pause on failure
- get_session_snapshot(scan_id) returns copy — workers never hold state
- NEVER log Authorization, Cookie, password, token fields
- from __future__ import annotations at top
Constraints: auth fail must pause scan with explicit error — never silent continue.
Done when: file exists with all methods, no print() calls.'

# codex-dad — scans router (parallel)
DAD_PROMPT='Read /mnt/d/SimpliAppSec/.workflow/skills/scoped-implementation.md and follow its procedure.
Read /mnt/d/SimpliAppSec/api/models/requests.py and /mnt/d/SimpliAppSec/storage/db/models.py.
Goal: Create /mnt/d/SimpliAppSec/api/routers/scans.py
Endpoints: POST /scans (create Scan, queue auth bootstrap task via rq), GET /scans/{id} (return ScanResponse), PATCH /scans/{id}/pause (set status=paused).
Use FastAPI async, SQLAlchemy async session via get_db(). from __future__ import annotations.
Done when: all 3 endpoints exist.' bash ~/.claude/scripts/dad-exec.sh
```

### Weryfikacja

```bash
python -m pytest tests/unit/control_plane/ -q
# Manual: POST /scans with session cookie type — verify scan created in DB
```

### Acceptance criteria

- [ ] `AuthManager.bootstrap()` handles all 4 auth types (credential/session/token/none)
- [ ] Login recipe JSON steps execute via Playwright
- [ ] Health loop pauses scan on auth failure — never silent continue
- [ ] `get_session_snapshot()` returns copy, not reference
- [ ] No credentials in structlog output (verify test)
- [ ] `POST /scans` creates Scan entity in DB

### Post-sprint: przegląd skillów

Czy pojawił się nowy powtarzalny pattern? Jeśli tak — zaktualizuj lub dodaj skill w .workflow/skills/ przed zamknięciem sprintu. Reguła: pattern >= 2x → skodyfikuj.

