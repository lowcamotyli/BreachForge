## Sprint 1 — Foundation: Infra + Schema

**Goal:** Docker Compose z PostgreSQL + Redis + LocalStack S3; wszystkie SQLAlchemy models; Alembic setup; FastAPI skeleton z `/health`.

### Architektura — dokumenty referencyjne

```bash
DAD_PROMPT="Read /mnt/d/SimpliAppSec/docs/architecture/storage-infra.md. List ALL service configs, port mappings, deployment constraints. Bullets. Max 20 lines." bash ~/.claude/scripts/dad-exec.sh

DAD_PROMPT="Read /mnt/d/SimpliAppSec/docs/architecture/data-model.md. List ALL entities, fields, and relationships. Bullets. Max 30 lines." bash ~/.claude/scripts/dad-exec.sh
```

### Graf zależności

```
models.py ──────────────────────────────────┐
session.py ─────────────────────────────────┤ pipeline
                                            ↓
migrations/versions/001_initial.py ─────────┘

docker-compose.yml ─┐
pyproject.toml ─────┤ parallel z powyższym
.env.example ───────┘
api/main.py ────────┘
```

### Dispatch table

| Plik | Worker | Skill | Uwagi |
|------|--------|-------|-------|
| `storage/db/models.py` | codex-main | `skill:scoped-implementation` | Wszystkie encje z Section 6 |
| `storage/db/session.py` | codex-main | `skill:scoped-implementation` | async engine + session factory |
| `storage/db/migrations/env.py` + `001_initial.py` | codex-dad | `skill:db-migration-safe` | Alembic setup |
| `docker/docker-compose.yml` | codex-dad | `skill:scoped-implementation` | parallel |
| `pyproject.toml` + `.env.example` | codex-main | `skill:scoped-implementation` | parallel |
| `api/main.py` | codex-main | `skill:scoped-implementation` | po models |

### Prompty

```bash
# codex-main — models + session (batch)
codex exec --dangerously-bypass-approvals-and-sandbox \
'Read d:/SimpliAppSec/.workflow/skills/scoped-implementation.md and follow its procedure.
Read d:/SimpliAppSec/ARCHITECTURE.md section 6 for entity definitions.
Do NOT use Gemini — write directly.
Goal: Create SQLAlchemy async models for all ProofScan entities.
Files:
- d:/SimpliAppSec/storage/db/models.py — all entities: Target, Scan, AuthContext, AssetMap, Endpoint, AttackTask, RawProbe, ProofArtifact, Finding, AttackPath. Use SQLAlchemy 2.0 mapped_column style, UUID primary keys, proper relationships.
- d:/SimpliAppSec/storage/db/session.py — async engine from DATABASE_URL env var, AsyncSessionLocal factory, get_db() dependency.
Add: from __future__ import annotations at top of each file.
Done when: both files exist with all 10 entity classes.'

# codex-dad — Alembic migration
DAD_PROMPT='Read /mnt/d/SimpliAppSec/.workflow/skills/db-migration-safe.md and follow its procedure.
Read /mnt/d/SimpliAppSec/storage/db/models.py after codex-main creates it.
Goal: Set up Alembic and create initial migration for all tables.
Files:
- /mnt/d/SimpliAppSec/alembic.ini
- /mnt/d/SimpliAppSec/storage/db/migrations/env.py (async-aware, imports models)
- /mnt/d/SimpliAppSec/storage/db/migrations/versions/001_initial.py (creates all tables from models.py)
Done when: alembic upgrade head runs without errors.' bash ~/.claude/scripts/dad-exec.sh

# codex-main — docker + config (parallel z migration)
codex exec --dangerously-bypass-approvals-and-sandbox \
'Read d:/SimpliAppSec/.workflow/skills/scoped-implementation.md and follow its procedure.
Do NOT use Gemini — write directly.
Goal: Create project infrastructure files.
Files:
- d:/SimpliAppSec/docker/docker-compose.yml — services: postgres:16, redis:7, localstack (S3). Postgres on 5432, Redis on 6379, LocalStack on 4566. Named volumes.
- d:/SimpliAppSec/pyproject.toml — all deps: fastapi, uvicorn, sqlalchemy[asyncio], alembic, asyncpg, redis, rq, playwright, httpx, boto3, structlog, pydantic, pyotp, python-jose, cryptography. Python 3.12.
- d:/SimpliAppSec/.env.example — DATABASE_URL, REDIS_URL, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_DEFAULT_REGION, EVIDENCE_BUCKET, DEFAULT_PROOF_CONFIDENCE_THRESHOLD=0.85
- d:/SimpliAppSec/api/main.py — FastAPI app with GET /health returning {"status": "ok"}, mounts empty routers stubs for /scans /findings /reports
Done when: all 4 files exist.'
```

### Weryfikacja

```bash
docker compose -f d:/SimpliAppSec/docker/docker-compose.yml up -d
cd d:/SimpliAppSec && alembic upgrade head
python -m pytest tests/unit/ -q  # no tests yet — should collect 0
```

### Acceptance criteria

- [ ] `docker compose up` starts postgres + redis + localstack without errors
- [ ] `alembic upgrade head` creates all 10 tables
- [ ] `GET /health` returns 200
- [ ] `pyproject.toml` has all deps from ARCHITECTURE.md Section 13

### Post-sprint: przegląd skillów

Czy pojawił się nowy powtarzalny pattern? Jeśli tak — zaktualizuj lub dodaj skill w .workflow/skills/ przed zamknięciem sprintu. Reguła: pattern >= 2x → skodyfikuj.

