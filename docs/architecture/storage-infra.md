# ProofScan — Storage and Infrastructure
Source: `ARCHITECTURE.md` — Section 11, Appendix B (Config constants), Section 13 (PostgreSQL/Redis/S3/deployment/Docker-related tech stack entries).

## 11. Storage and Infrastructure Design

### Required services

| Service | Purpose | v1 deployment |
|---------|---------|---------------|
| `API Server` | REST API for scan management | FastAPI, single instance |
| `Orchestrator` | Scan lifecycle, task queue | Co-located with API server (BullMQ / rq) |
| `AuthManager` | Session management per active scan | One process per concurrent scan |
| `AttackWorkers` | Stateless attack execution | 5–10 workers per scan, horizontally scaled |
| `PostgreSQL` | Scans, AssetMaps, Findings, AttackTasks | AWS RDS |
| `Redis` | Task queue, session snapshot cache, scan state | AWS ElastiCache |
| `S3-compatible store` | Evidence Store (ProofArtifacts, raw probes) | AWS S3 |
| `Headless browser workers` | Playwright for crawl + auth | Isolated containers per scan |

### PostgreSQL schema owns

- `targets`, `scans`, `auth_contexts`, `asset_maps`, `endpoints`, `attack_tasks`, `findings`
- Relational — structured queries on finding relationships

### S3 owns

- Raw `RawProbe` bundles (request + response, gzipped JSON)
- `ProofArtifact` bundles
- Keyed: `{scan_id}/{finding_id}/{probe_id}.json.gz`
- Do NOT put raw request/response bodies in PostgreSQL

### Sync vs async

| Operation | Mode |
|-----------|------|
| API calls | Synchronous |
| Auth bootstrap | Synchronous (blocks scan start) |
| Report retrieval | Synchronous |
| Crawl tasks | Async (queue) |
| Attack tasks | Async (queue) |
| Validation | Async (queue) |
| Finding scoring | Async (queue) |

### v1 deployment target

- **Docker Compose** for local development
- **AWS ECS Fargate** for production — container-native, no Kubernetes complexity
- **RDS PostgreSQL** for structured data
- **ElastiCache Redis** for queue + cache
- **S3** for evidence
- Single-region for v1

### What to simplify for v1

- No Kubernetes — Docker Compose + ECS
- No distributed tracing — structured logs (structlog) are sufficient
- No separate caching layer beyond Redis
- No CDN for the API — not a public web app
- No multi-region — add in v1.1

---

### Task queue

**rq (Redis Queue)** if staying Python-only, or **BullMQ** (Node.js) for better visibility tooling. Default: rq.

### Database ORM

**SQLAlchemy (async) + Alembic for migrations**

### Evidence Store client

**boto3** (S3)

### Deployment

- Development: **Docker Compose**
- Production: **AWS ECS Fargate** + RDS + ElastiCache + S3

### Key Python dependencies

```
fastapi
uvicorn
sqlalchemy[asyncio]
alembic
asyncpg
redis
rq
playwright
httpx
boto3
structlog
pydantic
pyotp          # TOTP computation for MFA
python-jose    # JWT handling
cryptography   # Envelope encryption
```

---

## Appendix B — Key Configuration Values

```python
