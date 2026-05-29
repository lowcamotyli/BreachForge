## Sprint 65 - Enterprise Auth Recording And Identity Reliability

**Goal:** Zrobic z auth realny produktowy moat: BreachForge ma przechodzic przez SSO/OIDC/SAML-heavy aplikacje dzieki nagrywaniu sesji, importowi session material i mierzalnej reliability per identity.

### Architektura - dokumenty referencyjne

```bash
# sprint-49, sprint-60 → Claude: Read docs/sprints/sprint-{49,60}-*.md bezposrednio
{
  echo "=== FILE: auth-architecture.md ==="; cat ~/BreachForge/docs/architecture/auth-architecture.md
} | gemini --output-format text \
  -p "File above. Extract remaining enterprise auth gaps for SSO/OIDC/SAML, session recording, identity reliability and preflight requirements. Bullets. Max 40 lines." \
  2>&1 | grep -v "^Warning:" | grep -v "^Ripgrep"
```

### Workstream A - Auth recording and import

| ID | Zadanie | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| A1 | Browser auth recorder: captures cookies, storage, relevant headers and auth-success probes | `control_plane/auth_manager.py`, `api/routers/session.py` | codex-main | session tests | operator moze nagrac login bez przepisywania flow |
| A2 | Session bundle format: encrypted portable auth bundle with expiry, identity labels and redacted preview | `storage/db/models.py`, encryption/session APIs | codex-dad | model/redaction tests | session import/export jest audytowalny i bezpieczny |
| A3 | HAR/Postman/OpenAPI auth material extraction and validation | crawler/importers/session | codex-main | importer fixtures | auth setup bierze material z narzedzi uzywanych przez klienta |

### Workstream B - Identity reliability engine

| ID | Zadanie | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| B1 | Identity matrix health: anon/user/admin/tenantA/tenantB pass rate, role markers, tenant markers | `control_plane/auth_manager.py`, reporting | codex-main | auth tests | raport pokazuje jak dobrze skan byl zalogowany |
| B2 | Auto-refresh recipes: bearer refresh, cookie re-login, CSRF token renewal, expiry prediction | auth manager/workers | codex-dad | lifecycle tests | dlugi scan nie driftuje cicho do unauth |
| B3 | Preflight hard fail/degrade states: invalid session, missing role, missing tenant, csrf_failed | API/orchestrator | codex-main | API/integration | zly auth nie produkuje falszywie czystego raportu |

### Workstream C - Operator diagnostics

| ID | Zadanie | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| C1 | Auth readiness endpoint: diagnostics, failing probes, redacted evidence, recommended fix | `api/routers/scans.py`, responses | codex-main | API tests | klient widzi problem przed skanem |
| C2 | Auth setup report section with reliability score and blind spots per identity | `control_plane/reporting.py` | codex-main | reporting tests | clean scan nie ukrywa auth blind spots |
| C3 | Auth corpus: expired/logout/revoked/csrf/role-mismatch sessions | `tests/benchmark_lab/labs/auth_oauth/` | codex-dad | benchmark | reliability mierzona powtarzalnie |

### Dispatch pattern

**Phase 1 (parallel):** main → A1, A3, B3; dad → (brak — A2 zalezy od A1, B2 od B1)
**Phase 2 (parallel, po verify):** main → B1, C1, C2; dad → A2 → B2 → C3
**Dad sequence:** A2 (po A1) → B2 (po B1 z fazy 2) → C3 (po A1+B1)
**Kluczowe zaleznosci:** A2 wymaga A1 (bundle format po recorder); B1 wymaga A1 (health po auth manager); B2 wymaga B1; C3 wymaga A1+B1

### Guardrails

- Auth bundles sa szyfrowane at rest i redagowane w logach.
- Worker zawsze pobiera fresh session snapshot, nigdy nie trzyma stalego tokenu.
- Auth preflight musi fail-closed przy braku wymaganej identity.
- MFA/SSO nie moze wymuszac przechowywania hasel, session import jest first-class fallback.

### Weryfikacja

```bash
python -m pytest tests/unit/control_plane/test_auth_manager.py -q
python -m pytest tests/unit/api/routers/test_session.py -q
python scripts/benchmark_lab.py --full --lab auth_oauth --max-fp 0
python -m pytest tests/integration/test_scan_api.py -q
```

### TL_PROMPT

```bash
TL_PROMPT="Read ~/BreachForge/.workflow/skills/testing-lead.md and follow it.
Sprint: 65 - Enterprise Auth Recording And Identity Reliability
Changed: control_plane/auth_manager.py, api/routers/session.py, storage/db/models.py, tests/benchmark_lab/labs/auth_oauth/
Test cases:
- Session recording/import dziala dla browser/HAR/API material
- Auth readiness pokazuje reliability per identity
- Expired/revoked/logout/csrf drift sa wykrywane przed lub w trakcie skanu
- Raport ma jawne auth blind spots" bash ~/.claude/scripts/testing-lead-exec.sh < /dev/null
```

### Global acceptance criteria

- [ ] Session recording/import dziala dla browser/HAR/API material.
- [ ] Auth readiness pokazuje reliability per identity.
- [ ] Expired/revoked/logout/csrf drift sa wykrywane przed albo w trakcie skanu.
- [ ] Raport ma jawne auth blind spots.

### Podzial pracy - codex-dad

A2, B2 i C3 ida do **codex-dad**. Reszte robi **codex-main**.
