## Sprint 10 — Runtime Contracts & FSM Alignment

**Goal:** Naprawa krytycznych kontraktów runtime: działające entrypointy RQ, spójny FSM skanu (`created/running/paused/complete/failed`), poprawne przejścia pause/auth-fail.

### Powiazanie z pelnym pokryciem atakow

Szczegolowy backlog typow atakow i globalnych gate'ow znajduje sie w:
`docs/sprints/sprint-15-security-attack-coverage.md`.

### Architektura — dokumenty referencyjne

```bash
DAD_PROMPT="Read /mnt/d/SimpliAppSec/ARCHITECTURE.md. Extract: ScanOrchestrator lifecycle states and required phase transitions (recon -> attack -> validate -> report), plus pause semantics on auth failure. Bullets. Max 20 lines." bash ~/.claude/scripts/dad-exec.sh
```

### Dispatch table

| Plik | Worker | Skill | Uwagi |
|------|--------|-------|-------|
| `control_plane/orchestrator.py` | codex-main | `skill:scoped-implementation` | FSM i transition guards |
| `control_plane/auth_manager.py` | codex-main | `skill:safe-sensitive-change` | auth pause/fail semantics |
| `api/routers/scans.py` | codex-dad | `skill:scoped-implementation` | status API + pause endpoint |
| `storage/db/models.py` + migration | codex-dad | `skill:db-migration-safe` | enum `ScanStatus` alignment |
| testy `tests/unit/control_plane/` | codex-main | `skill:test-impact-check` | FSM regressions |

### Prompty

```bash
# codex-main — orchestrator + auth semantics
codex exec --dangerously-bypass-approvals-and-sandbox \
'Read d:/SimpliAppSec/.workflow/skills/scoped-implementation.md and follow its procedure.
Read d:/SimpliAppSec/ARCHITECTURE.md sections: execution flow + auth architecture.
Do NOT use Gemini — write directly.
Goal:
1. d:/SimpliAppSec/control_plane/orchestrator.py
   - Ensure runtime FSM is compatible with architecture states (created/running/paused/complete/failed)
   - Keep explicit phase transitions recon -> attack -> validate -> reporting
   - pause_scan() must set paused state, not pending
2. d:/SimpliAppSec/control_plane/auth_manager.py
   - Auth failure should pause scan with explicit reason, not silently continue
   - Align pause/fail semantics with orchestrator contract
Done when: orchestration and auth pause behavior are consistent and tested.'

# codex-dad — API + DB migration
DAD_PROMPT='Read /mnt/d/SimpliAppSec/.workflow/skills/db-migration-safe.md and follow its procedure.
Goal:
1. /mnt/d/SimpliAppSec/storage/db/models.py and Alembic migration update:
   - Align ScanStatus enum with architecture lifecycle semantics
2. /mnt/d/SimpliAppSec/api/routers/scans.py:
   - Remove invalid cast-based status writes
   - Return status values consistent with DB enum and orchestrator
Done when: API pause path and DB enum are coherent and migration is valid.' bash ~/.claude/scripts/dad-exec.sh
```

### Weryfikacja

```bash
python -m pytest tests/unit/control_plane/ -q
python -m pytest tests/unit/api/ -q
```

### Acceptance criteria

- [ ] RQ jobs enqueue callable entrypoints that exist and are importable
- [ ] `pause_scan` never writes `pending` for paused flow
- [ ] API endpoint nie zapisuje statusu spoza enum
- [ ] Auth failure path is explicit and traceable in scan phase/status

### Post-sprint: przegląd skillów

Czy pojawił się nowy powtarzalny pattern? Jeśli tak — zaktualizuj lub dodaj skill w `.workflow/skills/` przed zamknięciem sprintu. Reguła: pattern >= 2x -> skodyfikuj.


