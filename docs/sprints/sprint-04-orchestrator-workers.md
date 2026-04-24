## Sprint 4 — Orchestrator + Worker Infrastructure

**Równolegle z Sprint 3** — brak wspólnych plików.

**Goal:** ScanOrchestrator FSM; rq AttackWorker pool; WorkerSupervisor z crash detection i automatic restart.

### Architektura — dokumenty referencyjne

```bash
DAD_PROMPT="Read /mnt/d/SimpliAppSec/docs/architecture/storage-infra.md. Extract: queue setup, worker pool specs, sync vs async table, deployment notes. Bullets. Max 20 lines." bash ~/.claude/scripts/dad-exec.sh
```

### Dispatch table

| Plik | Worker | Skill | Uwagi |
|------|--------|-------|-------|
| `control_plane/orchestrator.py` | codex-main | `skill:scoped-implementation` | FSM — złożone |
| `execution_plane/workers/attack_worker.py` | codex-dad | `skill:scoped-implementation` | stateless httpx |
| `execution_plane/workers/supervisor.py` | codex-dad | `skill:scoped-implementation` | parallel z attack_worker |
| `tests/...test_attack_worker.py` | codex-main | `skill:test-impact-check` | po workerach |

### Prompty

```bash
# codex-main — Orchestrator
codex exec --dangerously-bypass-approvals-and-sandbox \
'Read d:/SimpliAppSec/.workflow/skills/scoped-implementation.md and follow its procedure.
Read d:/SimpliAppSec/storage/db/models.py for Scan model.
Do NOT use Gemini — write directly.
Goal: d:/SimpliAppSec/control_plane/orchestrator.py — ScanOrchestrator
- Manages scan lifecycle FSM: created → running → paused → complete → failed
- Phase transitions: recon → attack → validate → reporting
- on_scan_created(scan_id): queues auth_bootstrap rq job
- on_recon_complete(scan_id, asset_map): queues attack planning
- on_attack_complete(scan_id): transitions to validate phase
- on_all_validated(scan_id): transitions to reporting, calls ReportingService
- pause_scan(scan_id, reason): updates DB status
- Uses rq Queue connected to Redis from REDIS_URL env
- from __future__ import annotations
Done when: all phase transition methods exist.'

# codex-dad — Workers (batch parallel)
DAD_PROMPT='Read /mnt/d/SimpliAppSec/.workflow/skills/scoped-implementation.md and follow its procedure.
Read /mnt/d/SimpliAppSec/storage/db/models.py for AttackTask and RawProbe entities.
Goal: Create two worker files:
1. /mnt/d/SimpliAppSec/execution_plane/workers/attack_worker.py
   - AttackWorker.execute(task: AttackTask, session: SessionSnapshot) -> RawProbe
   - Uses httpx.AsyncClient with session cookies and auth headers applied
   - Captures: request (method, url, headers, body) + response (status, headers, body, latency_ms)
   - NO direct DB access, NO S3 access — writes RawProbe to Redis stream key evidence:{scan_id}
   - Rate-limit aware: reads token from Redis before each request
   - from __future__ import annotations
2. /mnt/d/SimpliAppSec/execution_plane/workers/supervisor.py
   - WorkerSupervisor: manages rq Worker processes
   - health_heartbeat() every 30s — checks worker liveness
   - on_worker_crash(worker_id): logs event, restarts worker with same queue
   - Hard timeout per task: 300s — kills and restarts if exceeded
   - from __future__ import annotations
Done when: both files exist with stated classes.' bash ~/.claude/scripts/dad-exec.sh
```

### Weryfikacja

```bash
python -m pytest tests/unit/execution_plane/workers/ -q
```

### Acceptance criteria

- [ ] `AttackWorker.execute()` writes ONLY to Redis stream — no DB/S3 calls
- [ ] Worker supervisor restarts crashed workers automatically
- [ ] Hard 300s timeout per task enforced
- [ ] FSM transitions persist to DB on each phase change

### Post-sprint: przegląd skillów

Czy pojawił się nowy powtarzalny pattern? Jeśli tak — zaktualizuj lub dodaj skill w .workflow/skills/ przed zamknięciem sprintu. Reguła: pattern >= 2x → skodyfikuj.

