## Sprint 14 — Auth Coverage, Storage Contract & Test Corpus

**Goal:** Domknięcie brakujących elementów v1: `/auth/verify`, rozszerzone auth input (`refresh_token`, `totp_seed`), testy integration/corpus, oraz kontrakt storage (DB metadane vs pełne payloady w S3).

### Powiazanie z pelnym pokryciem atakow

Szczegolowy backlog typow atakow i globalnych gate'ow znajduje sie w:
`docs/sprints/sprint-15-security-attack-coverage.md`.

### Architektura — dokumenty referencyjne

```bash
DAD_PROMPT="Read /mnt/d/SimpliAppSec/docs/architecture/auth-architecture.md, validation-model.md, storage-infra.md. Extract missing v1 requirements: auth input types, auth verify/preflight behavior, and DB vs S3 evidence ownership. Bullets. Max 30 lines." bash ~/.claude/scripts/dad-exec.sh
```

### Dispatch table

| Plik | Worker | Skill | Uwagi |
|------|--------|-------|-------|
| `api/models/requests.py` | codex-main | `skill:safe-sensitive-change` | refresh/totp fields |
| `api/routers/auth_check.py` (new) | codex-main | `skill:scoped-implementation` | `/auth/verify` endpoint |
| `api/main.py` + router init | codex-main | `skill:scoped-implementation` | endpoint registration |
| `storage/db/models.py` + migration | codex-dad | `skill:db-migration-safe` | raw payload contract cleanup |
| `tests/integration/*` (new) | codex-dad | `skill:test-impact-check` | API + auth flow |
| `tests/corpus/*` (new) | codex-dad | `skill:test-impact-check` | validator corpus gate |

### Prompty

```bash
# codex-main — auth API completeness
codex exec --dangerously-bypass-approvals-and-sandbox \
'Read d:/SimpliAppSec/.workflow/skills/scoped-implementation.md and follow its procedure.
Do NOT use Gemini — write directly.
Goal:
1. d:/SimpliAppSec/api/models/requests.py
   - Extend AuthContextCreate with refresh_token and totp_seed (v1 partial support)
2. Add d:/SimpliAppSec/api/routers/auth_check.py
   - POST /auth/verify preflight endpoint validating supplied auth material
3. Wire router in d:/SimpliAppSec/api/main.py and d:/SimpliAppSec/api/routers/__init__.py
Done when: auth preflight route is reachable and models cover required fields.'

# codex-dad — storage contract + tests
DAD_PROMPT='Read /mnt/d/SimpliAppSec/.workflow/skills/db-migration-safe.md and /mnt/d/SimpliAppSec/.workflow/skills/test-impact-check.md.
Goal:
1. Align storage contract so DB does not become primary store for full raw request/response payloads when S3 is authoritative
2. Add integration tests under /mnt/d/SimpliAppSec/tests/integration/ for scan/report/auth endpoints
3. Add corpus tests under /mnt/d/SimpliAppSec/tests/corpus/ for validator confidence gate behavior
Done when: migrations + tests are runnable and reflect architecture boundaries.' bash ~/.claude/scripts/dad-exec.sh
```

### Weryfikacja

```bash
python -m pytest tests/unit/ -q
python -m pytest tests/integration/ -q
python -m pytest tests/corpus/ -q
```

### Acceptance criteria

- [ ] `/auth/verify` exists and validates supplied auth context before scan
- [ ] Auth input supports `refresh_token` and `totp_seed`
- [ ] Storage contract reflects S3 as source of full evidence payloads
- [ ] `tests/integration` and `tests/corpus` exist and run in CI

### Post-sprint: przegląd skillów

Czy pojawił się nowy powtarzalny pattern? Jeśli tak — zaktualizuj lub dodaj skill w `.workflow/skills/` przed zamknięciem sprintu. Reguła: pattern >= 2x -> skodyfikuj.


