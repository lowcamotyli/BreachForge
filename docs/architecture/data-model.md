# ProofScan — Data Model
Source: `ARCHITECTURE.md` — Section 6 (Python class definitions), Section 3 (P4), Section 4 (`FindingScorer`), Section 5 (Steps 7-8), Appendix A.

### P4 — Deduplication is a first-class system concern

Deduplication happens before a finding is written — it is not a UI filter applied after the fact.

#### `FindingScorer`

- Receives validated `ProofArtifact` objects from the Validator
- Normalizes them against existing findings (same root cause? same parameter class? same endpoint pattern?)
- Assigns severity and confidence
- Writes to the Finding Store **only when dedup passes**

### Step 7 — Deduplication and scoring

`FindingScorer`:
1. Receives `ProofArtifact`
2. Computes structural fingerprint: `(attack_class, endpoint_pattern, parameter_class)`
3. If novel → creates `Finding` entity, links to evidence, assigns severity, writes to Finding Store
4. If duplicate variant → increments evidence count on existing finding

### Step 8 — Output

On scan completion (or on-demand):
1. `ReportingService` assembles findings
2. Fetches evidence from Evidence Store
3. Produces structured output per finding: severity, description, exact request, exact response, repro steps, fix guidance
4. Exports as JSON + rendered Markdown
5. Redacts sensitive values in export (tokens, passwords from auth headers)

---

## 6. Data Model — Key Entities

```python
class Target:
    id: UUID
    url: str
    name: str
    created_at: datetime
    config: TargetConfig  # max_depth, rate_limit, scope_rules


class Scan:
    id: UUID
    target_id: UUID
    status: Literal["created", "running", "paused", "complete", "failed"]
    phase: Literal["recon", "attack", "validate", "reporting"]
    created_at: datetime
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    auth_context_id: UUID


class AuthContext:
    id: UUID
    scan_id: UUID
    type: Literal["credential", "session", "token", "none"]
    session_snapshot: SessionSnapshot  # cookies[], headers{}, refresh_material
    health: AuthHealth  # last_verified, expires_at, is_valid


class AssetMap:
    id: UUID
    scan_id: UUID
    endpoints: List[Endpoint]


class Endpoint:
    id: UUID
    asset_map_id: UUID
    url_pattern: str
    method: str
    auth_required: bool
    parameters: List[Parameter]  # name, location (query|body|path|header), type
    observed_content_type: Optional[str]
    example_response_code: Optional[int]


class AttackTask:
    id: UUID
    scan_id: UUID
    endpoint_id: UUID
    attack_class: Literal[
        "bola", "idor", "tenant_isolation", "auth_bypass",
        "injection", "privilege_escalation", "workflow_abuse",
        "sensitive_exposure"
    ]
    target_parameter: Optional[str]
    hypothesis: str
    priority_score: float
    status: Literal["queued", "running", "completed", "failed"]


class RawProbe:
    id: UUID
    attack_task_id: UUID
    worker_id: str
    timestamp: datetime
    request: HttpRequest   # method, url, headers, body
    response: HttpResponse  # status, headers, body, latency_ms
    control_probe_id: Optional[UUID]


class ProofArtifact:
    id: UUID
    attack_task_id: UUID
    proof_type: Literal["differential", "absolute", "reproduction"]
    confidence_score: float  # must be >= 0.85 to become a Finding
    attack_probe_id: UUID
    control_probe_id: Optional[UUID]
    summary: str
    evidence_notes: str


class Finding:
    id: UUID
    scan_id: UUID
    title: str
    description: str
    severity: Literal["critical", "high", "medium", "info"]
    attack_class: str
    affected_endpoint_id: UUID
    proof_artifacts: List[ProofArtifact]
    repro_steps: str
    fix_guidance: str
    deduplicated_from: Optional[UUID]


class AttackPath:
    """v1 lightweight version — full attack path reasoning is v2"""
    id: UUID
    scan_id: UUID
    steps: List[AttackPathStep]  # finding_id, order, description
    entry_point: str
    impact_description: str
```

---

## Appendix A — Directory Structure

Recommended repository layout:

```
proofscan/
├── api/                    # FastAPI application
│   ├── routers/            # scan, auth, findings, report endpoints
│   ├── models/             # Pydantic request/response models
│   └── main.py
├── control_plane/
│   ├── orchestrator.py     # ScanOrchestrator
│   ├── auth_manager.py     # AuthManager
│   ├── finding_scorer.py   # FindingScorer + dedup
│   └── reporting.py        # ReportingService
├── execution_plane/
│   ├── crawler/
│   │   ├── engine.py       # CrawlerReconEngine
│   │   └── asset_map.py    # AssetMap builder
│   ├── planner/
│   │   ├── planner.py      # AttackPlanner
│   │   └── rules/          # Attack rule classes (one file per class)
│   │       ├── base.py
│   │       ├── bola.py
│   │       ├── tenant_isolation.py
│   │       ├── auth_bypass.py
│   │       ├── privilege_escalation.py
│   │       ├── workflow_abuse.py
│   │       ├── sensitive_exposure.py
│   │       └── injection.py
│   ├── workers/
│   │   ├── attack_worker.py
│   │   └── supervisor.py
│   └── validator/
│       ├── validator.py    # ExploitValidator
│       └── strategies/     # Per-class validation logic
├── storage/
│   ├── db/
│   │   ├── models.py       # SQLAlchemy models
│   │   └── migrations/     # Alembic migrations
│   └── evidence/
│       └── store.py        # S3 evidence store client
├── tests/
│   ├── unit/
│   ├── integration/
│   └── corpus/             # Known-vulnerable app test cases
├── docker/
│   ├── docker-compose.yml
│   └── Dockerfile.*
└── infra/
    └── ecs/                # ECS task definitions
```

---
