## Sprint 13 — Worker Guardrails & Scope Enforcement

**Goal:** Egzekwowanie ograniczeń execution plane: scope per domain, właściwy domain+worker rate limiting, spójny `production-safe` behavior i izolacja zachowania workerów.

### Powiazanie z pelnym pokryciem atakow

Szczegolowy backlog typow atakow i globalnych gate'ow znajduje sie w:
`docs/sprints/sprint-15-security-attack-coverage.md`.

### Architektura — dokumenty referencyjne

```bash
DAD_PROMPT="Read /mnt/d/SimpliAppSec/docs/architecture/security-constraints.md and /mnt/d/SimpliAppSec/docs/architecture/noise-reduction.md. Extract: worker isolation, scope enforcement, and rate limiting invariants. Bullets. Max 20 lines." bash ~/.claude/scripts/dad-exec.sh
```

### Dispatch table

| Plik | Worker | Skill | Uwagi |
|------|--------|-------|-------|
| `execution_plane/workers/attack_worker.py` | codex-main | `skill:safe-sensitive-change` | domain scope + limiter hookup |
| `control_plane/rate_limiter.py` | codex-main | `skill:scoped-implementation` | single source of truth |
| `execution_plane/workers/supervisor.py` | codex-dad | `skill:runtime-debug-triage` | runtime sanity & timeouts |
| `execution_plane/crawler/engine.py` | codex-dad | `skill:scoped-implementation` | scope signal handoff to planner/workers |
| testy workers/rate limiter | codex-main | `skill:test-impact-check` | guardrail coverage |

### Prompty

```bash
# codex-main — enforce scope + rate limit in worker
codex exec --dangerously-bypass-approvals-and-sandbox \
'Read d:/SimpliAppSec/.workflow/skills/scoped-implementation.md and follow its procedure.
Do NOT use Gemini — write directly.
Goal:
1. d:/SimpliAppSec/execution_plane/workers/attack_worker.py
   - Reject out-of-scope target domains for each task
   - Replace ad-hoc token pop limiter with DomainRateLimiter integration
   - Enforce method blocking in production-safe mode
2. d:/SimpliAppSec/control_plane/rate_limiter.py
   - Keep domain+scan and domain+scan+worker quota paths as canonical limiter API
Done when: worker request execution cannot bypass scope or limiter policies.'

# codex-dad — runtime guardrail pass
DAD_PROMPT='Read /mnt/d/SimpliAppSec/.workflow/skills/runtime-debug-triage.md and follow its procedure.
Goal:
1. /mnt/d/SimpliAppSec/execution_plane/workers/supervisor.py
   - Ensure crash restart and hard timeout semantics stay deterministic
2. /mnt/d/SimpliAppSec/execution_plane/crawler/engine.py
   - Keep in-scope discovery semantics explicit for downstream planner/worker use
Done when: guardrail behavior is testable and deterministic.' bash ~/.claude/scripts/dad-exec.sh
```

### Weryfikacja

```bash
python -m pytest tests/unit/execution_plane/workers/ -q
python -m pytest tests/unit/control_plane/ -q
python -m pytest tests/unit/execution_plane/crawler/ -q
```

### Acceptance criteria

- [ ] Worker never sends request outside configured target domain scope
- [ ] Worker enforces shared domain limiter + per-worker limiter
- [ ] `production-safe` blocks mutating methods in execution path
- [ ] Guardrail violations fail closed (no silent continue)

### Post-sprint: przegląd skillów

Czy pojawił się nowy powtarzalny pattern? Jeśli tak — zaktualizuj lub dodaj skill w `.workflow/skills/` przed zamknięciem sprintu. Reguła: pattern >= 2x -> skodyfikuj.


