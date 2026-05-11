# AGENTS.md — ProofScan

## Primary Mode: Claude as Orchestrator

Claude Code is the primary orchestrator. Codex CLI and codex-dad are delegated workers.

---

## Stack

- **Python 3.12** — type hints everywhere, `from __future__ import annotations` in every file
- **FastAPI** — async, Pydantic v2 for request/response models in `api/models/`
- **SQLAlchemy async** + **Alembic** — ORM and migrations in `storage/db/`
- **rq (Redis Queue)** — task queue, job IDs tracked in Redis
- **Playwright (Python)** — headless browser for auth + crawl (`control_plane/`, `execution_plane/crawler/`)
- **httpx** — async HTTP for attack workers (`execution_plane/workers/`)
- **boto3** — S3 evidence store (`storage/evidence/store.py`)
- **structlog** — structured JSON logging (never log credentials)
- **pytest + pytest-asyncio** — all tests

---

## Project Structure

```
proofscan/
├── api/routers/            # FastAPI route handlers
├── api/models/             # Pydantic request/response schemas
├── control_plane/          # orchestrator.py, auth_manager.py, finding_scorer.py, reporting.py
├── execution_plane/
│   ├── crawler/            # engine.py, asset_map.py
│   ├── planner/            # planner.py + rules/*.py
│   ├── workers/            # attack_worker.py, supervisor.py
│   └── validator/          # validator.py + strategies/*.py
├── storage/db/             # models.py, session.py, migrations/
├── storage/evidence/       # store.py (S3)
└── tests/
```

---

## Skills Layer

| Skill | Primary worker | Notes |
|-------|---------------|-------|
| `scoped-implementation` | codex-main | Default for all concrete coding tasks |
| `db-migration-safe` | codex-dad | All Alembic migrations |
| `safe-sensitive-change` | codex-main + Claude approval | Auth, validator, proof threshold |
| `attack-rule-authoring` | codex-main + Claude approval | New attack rule classes |
| `large-context-analysis` | codex-dad | Before planning complex tasks |
| `review-ready-diff` | codex-main | Before returning to Claude |
| `runtime-debug-triage` | codex-main | Reproduce before fixing |
| `test-impact-check` | codex-main | After every implementation |
| `parallel-work-split` | Claude | Sprint planning |

**Common sequences:**
- Normal task: `scoped-implementation` → `test-impact-check` → `review-ready-diff`
- New attack class: `attack-rule-authoring` → `safe-sensitive-change` → `test-impact-check`
- DB change: `db-migration-safe` → `scoped-implementation` → `review-ready-diff`
- Broken behavior: `runtime-debug-triage` → `scoped-implementation`

---

## Delegation Rules

| Task | Worker |
|------|--------|
| New Python file > 20 lines | codex-main |
| Second file in parallel | codex-dad |
| Alembic migrations | codex-dad |
| Playwright auth/crawler flows | codex-main |
| Attack rule + validator strategy (new class) | codex-main + Claude approval |
| Reading/summarizing files > 50 lines | codex-dad (summary mode) |
| Fix < 10 lines | Claude directly |

---

## codex-dad Operational Contract

- `codex-dad` is the WSL-backed worker running in distro `worker-dad` via `/usr/local/bin/codex-dad-exec`.
- Preferred wrapper: `DAD_PROMPT="..." bash ~/.claude/scripts/dad-exec.sh`.
- From Windows PowerShell, multiline prompts may not propagate through `DAD_PROMPT`; use the direct pipe fallback:
  ```powershell
  @'
  cd /mnt/d/BreachForge
  <bounded work package>
  '@ | wsl -d worker-dad -e bash -lc 'PROMPT=$(cat); /usr/local/bin/codex-dad-exec "$PROMPT"'
  ```
- Always set the repo path inside the prompt (`cd /mnt/d/BreachForge`) because the worker can start elsewhere.
- Use `codex-dad` when explicitly requested, for large context extraction, Alembic migrations, or bounded implementation packages where parallel worker output saves time.
- `codex-dad` must return evidence: files changed, commands run with results, and open risks/follow-ups.
- Codex-main reviews and integrates `codex-dad` output before commit/push; do not blindly ship delegated changes.

### Sprint Worker Assignments Are Binding

- When a sprint document assigns an implementation task to `codex-dad`, Codex-main MUST delegate that task to `codex-dad` as a bounded implementation package. Do not downgrade it to context extraction or analysis.
- Codex-main may only implement the tasks explicitly assigned to `codex-main`, plus small integration glue after reviewing `codex-dad` output.
- If a sprint table or workstream says `codex-dad` in the Worker column, the prompt to `codex-dad` must say that edits are expected and must list the exact files/tasks owned by `codex-dad`.
- Codex-main must collect `codex-dad` evidence, inspect the resulting diff, run verification, and report both `codex-dad` evidence and Codex-main integration evidence.
- If the sprint/user explicitly says "use codex-dad" or "codex-dad wdraza", Codex-main must start with implementation delegation to `codex-dad` before doing local implementation work.

---

## Coding Conventions

- `from __future__ import annotations` — first import in every file
- Dataclasses for internal DTOs (`RawProbe`, `SessionSnapshot`, `ProofArtifact`)
- Pydantic v2 only in `api/models/` (request/response layer)
- `async def` for all I/O-bound functions
- Early returns over nested conditionals
- No `print()` — use `structlog.get_logger()` with structured context
- Files < 300 lines — split if exceeded
- Test files mirror source structure: `tests/unit/execution_plane/validator/test_bola.py`

---

## Safety Constraints — Non-Negotiable

### Proof-gate (P1)
```python
# ALWAYS enforce before creating Finding:
if proof.confidence_score < DEFAULT_PROOF_CONFIDENCE_THRESHOLD:
    return  # discard — never bypass this check
```

### Worker isolation (P5)
- Workers write ONLY to Redis Evidence Buffer (stream key: `evidence:{scan_id}`)
- Workers have NO direct DB access, NO direct S3 access
- Workers have NO access to other scans' data

### Credential handling
- NEVER log `Authorization`, `Cookie`, `password`, `token` fields — structlog processor strips them
- Raw credentials purged from DB after scan completes
- Redaction applied ONLY in `ReportingService.export()` — not in Evidence Store

### Session management (P2)
- `AuthManager` is the ONLY component that holds session state
- Workers request fresh `SessionSnapshot` per task — never cache locally
- If `AuthManager.health_check()` fails → `scan.pause(reason="auth_expired")` — never silent continue

### Scan scope (P6)
- Workers NEVER send requests outside the target domain(s) defined in `Scan.target`
- Rate limiter keyed on `scan_id:domain` — enforced in Redis

---

## Verification

**Python environment (worker-dad WSL):** venv at `/mnt/d/SimpliAppSec/.venv`, auto-activated via `~/.bashrc`.

```bash
# After every implementation (worker-dad):
source /mnt/d/SimpliAppSec/.venv/bin/activate && pytest tests/unit/ -q

# Before ship:
source /mnt/d/SimpliAppSec/.venv/bin/activate && pytest tests/ -q

# Or via interactive bash (venv already active from .bashrc):
bash -i -c "pytest /mnt/d/SimpliAppSec/tests/unit/ -q"
```

**Add new dependency:**
```bash
# 1. Add to pyproject.toml [project.dependencies]
# 2. Reinstall in venv:
source /mnt/d/SimpliAppSec/.venv/bin/activate && pip install -e "/mnt/d/SimpliAppSec[dev]" -q
```

---

## Evidence requirement (every work package must return)

- Files changed (list of paths)
- `pytest tests/unit/ -q` result
- Open risks or follow-ups
