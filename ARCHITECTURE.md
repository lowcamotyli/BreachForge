# ProofScan v1.0 — Founding Architecture Document

> **Purpose:** This document is the authoritative technical specification for implementing ProofScan v1.0. It is written for Claude Code operating in agentic/autonomous mode. Every architectural decision here is final for v1 unless explicitly marked as a v2 item. Do not invent alternatives. Implement what is specified.

---

## Table of Contents

1. [Product Thesis](#1-product-thesis)
2. [Product Architecture — One Paragraph](#2-product-architecture--one-paragraph)
3. [Core Architectural Principles](#3-core-architectural-principles)
4. [Main System Components](#4-main-system-components)
5. [End-to-End Execution Flow](#5-end-to-end-execution-flow)
6. [Data Model — Key Entities](#6-data-model--key-entities)
7. [Authentication Architecture](#7-authentication-architecture)
8. [Attack Engine Design](#8-attack-engine-design)
9. [Proof and Validation Model](#9-proof-and-validation-model)
10. [Noise-Reduction Strategy](#10-noise-reduction-strategy)
11. [Storage and Infrastructure Design](#11-storage-and-infrastructure-design)
12. [Security and Safety Constraints](#12-security-and-safety-constraints)
13. [Tech Stack](#13-tech-stack)
14. [Biggest Technical Risks](#14-biggest-technical-risks)
15. [Scope Boundaries — What Is Excluded from v1](#15-scope-boundaries--what-is-excluded-from-v1)
16. [Implementation Priorities](#16-implementation-priorities)

---

## 1. Product Thesis

ProofScan is **not** a generic AppSec scanner. It is an automated attacker for web apps and APIs that surfaces only vulnerabilities that can actually be exploited, with proof.

### Why existing tools fail

- Too much noise / false positives
- Weak authentication handling
- Poor support for modern APIs, SPAs, and multi-step workflows
- Weak developer UX
- "Security dashboard theater" — findings without evidence

### What ProofScan must be

- **Runtime-first** — tests live applications, no source code required
- **Proof-first** — every finding has exact request, exact response, reproduction path
- **Attacker-inspired** — reasons in terms of flows, state, exploit chains
- **Developer-friendly** — output developers can act on immediately

### What ProofScan must not be

- A SAST platform
- A compliance platform
- A vulnerability database UI
- An ASPM meta-dashboard
- An enterprise governance suite

### Target customer for v1

SaaS / B2B software companies with:
- API-heavy products on modern stacks
- 5–50 engineers
- No dedicated AppSec team
- Fast deployment cycles
- Need for real signal, not 500 alerts
- Willingness to provide target URL, optional credentials/session

---

## 2. Product Architecture — One Paragraph

ProofScan is a runtime attacker engine that accepts a target URL and optional auth context as input, autonomously maps the application surface like an attacker (not a generic crawler), generates targeted attack hypotheses based on discovered endpoints and state patterns, executes those attacks with full session management, validates each potential issue to a proof threshold before it ever becomes a finding, and delivers a small, high-signal report with exact request/response evidence and reproduction paths. The system has two logical planes: a **Control Plane** (scan lifecycle management, scheduling, auth bootstrap, reporting) and an **Execution Plane** (crawler, attack engine, validator, evidence store) — isolated so the execution plane runs in sandboxed workers with no access to internal infrastructure and no authority to write findings directly. Every component is biased toward producing fewer, better findings. Nothing surfaces without proof.

---

## 3. Core Architectural Principles

These are non-negotiable invariants. Do not compromise them during implementation.

### P1 — Proof-gate everything

A finding only exists if the Exploit Validator confirms it. No validator confirmation = no finding, regardless of how suspicious the signal looks. This is the single most important architectural invariant in the system.

### P2 — Auth is the product

Authenticated state is a first-class resource. It is managed centrally by the Auth Manager, refreshed proactively, and distributed to every attack worker. A scan that silently loses auth and continues is strictly worse than one that pauses and re-authenticates.

### P3 — Attack depth over attack breadth

It is better to deeply test 20 endpoints with attacker-relevant logic than to superficially ping 200 with generic checks. The engine prioritizes high-value targets: auth endpoints, resource operations, state transitions, ID-parameterized routes.

### P4 — Deduplication is a first-class system concern

Deduplication happens before a finding is written — it is not a UI filter applied after the fact.

### P5 — The execution plane does not trust itself

Workers are untrusted, rate-limited, and isolated. They cannot write findings. They produce evidence artifacts. The control plane decides what becomes a finding.

### P6 — Crawling is reconnaissance, not spidering

The goal is not to visit every page. The goal is to build an attack surface model: endpoints, parameters, state dependencies, auth-gated vs. public paths.

---

## 4. Main System Components

### Control Plane

#### `ScanOrchestrator`

- Manages scan lifecycle: `created → running → paused → complete → failed`
- Owns the task queue
- Receives partial results from workers and coordinates phase transitions: `recon → attack → validate → report`
- Single-instance, stateful process

#### `AuthManager`

- Bootstraps authenticated sessions from user-provided credentials/session material
- Holds live session state: cookies, tokens, refresh tokens
- Proactively monitors session health and re-authenticates before expiry
- Distributes valid session snapshots to workers on demand
- Long-running stateful service — not a helper function

#### `FindingScorer`

- Receives validated `ProofArtifact` objects from the Validator
- Normalizes them against existing findings (same root cause? same parameter class? same endpoint pattern?)
- Assigns severity and confidence
- Writes to the Finding Store **only when dedup passes**

#### `ReportingService`

- Assembles findings into developer-facing output
- Pulls evidence from the Evidence Store
- Renders Markdown + structured JSON
- Produces per-finding repro steps and likely fix guidance
- **Never does analysis — only assembles and formats**

---

### Execution Plane

#### `CrawlerReconEngine`

- Maps application surface using authenticated headless browser (Playwright)
- Finds endpoints, forms, API calls via XHR/fetch network interception, link extraction, OpenAPI hints if present
- Produces a structured `AssetMap`: every discovered endpoint, parameter types, auth-gated status, observed HTTP methods
- **Does not fuzz. Does not attack. Reconnaissance only.**

#### `AttackPlanner`

- Consumes the `AssetMap`
- Applies rule library to decide which attack hypotheses to generate per endpoint
- Rule-based in v1 with AI-assist for anomaly pattern detection
- Produces an ordered queue of `AttackTask` objects: endpoint + attack class + parameter target + expected proof signal

#### `AttackWorkers` (horizontally scaled pool)

- Stateless worker pool — consume `AttackTask` from queue
- Execute single attack attempts: craft request → send → capture response
- Produce `RawProbe` objects: request + response + timestamp + worker ID
- **Zero decision-making authority**
- No filesystem access
- Rate-limited per target domain
- Workers do not store anything — they stream probes to the Evidence Buffer

#### `ExploitValidator`

- **The only component that decides if something is a finding**
- Receives `RawProbe` objects
- Applies validation logic: did the response demonstrate the expected exploitable condition?
- Runs confirmation probes (re-attempt with control request, differential probe)
- Produces `ProofArtifact` if confidence threshold met; otherwise discards

#### `EvidenceStore`

- Append-only object store (S3-compatible)
- Receives `ProofArtifact` objects from Validator
- Stores full request/response pairs verbatim: headers, body, cookies, timestamps
- **Never redacted at write time** — redaction applied at read/export time
- Indexed by `scan_id` + `finding_id`

---

## 5. End-to-End Execution Flow

### Step 1 — Scan creation

User provides: target URL + optional credentials / session cookies / bearer token.

Control plane:
- Creates a `Scan` entity
- Assigns `scan_id`
- Queues auth bootstrap task

### Step 2 — Auth bootstrap

`AuthManager` takes credentials and:
1. Attempts login flow via headless Playwright browser
2. Captures resulting cookies and tokens
3. Verifies authenticated state by probing a known-auth-required endpoint
4. Stores session snapshot

**If auth fails:** scan is paused immediately with an actionable error. **Never silently continues unauthenticated.**

### Step 3 — Reconnaissance

`CrawlerReconEngine`:
1. Launches authenticated headless browser session using session snapshot from AuthManager
2. Maps reachable pages, API calls observed in network traffic, forms, link patterns
3. Builds `AssetMap`
4. Records which endpoints required auth, which accept parameters, which methods were observed
5. Time-boxed (default: 10 minutes — configurable)

### Step 4 — Attack planning

`AttackPlanner`:
1. Consumes `AssetMap`
2. Applies rule library: auth endpoints → IDOR/access control rules; state-changing endpoints → workflow abuse rules; parameterized resource IDs → BOLA checks; input-accepting endpoints → injection checks (where proof is feasible)
3. Produces ordered `AttackTask` queue, prioritizing high-value targets

### Step 5 — Attack execution

`AttackWorker` pool:
1. Fetches fresh session snapshot from AuthManager per task
2. Executes the attack
3. Captures raw probe
4. Rate-limiter enforces per-domain request budget
5. Streams `RawProbe` objects to Evidence Buffer

### Step 6 — Validation

`ExploitValidator` processes probe queue continuously:
1. For each promising probe, runs differential validation: control request (no attack) + attack request, compares outcomes
2. Applies class-specific proof criteria (see Section 9)
3. If proof threshold met → writes `ProofArtifact` to Evidence Store
4. If below threshold → discards

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

## 7. Authentication Architecture

### Input types supported (v1, in priority order)

| Type | Description | v1 Support |
|------|-------------|-----------|
| Username + password | Standard login form | ✅ Full |
| Session cookies | Pre-baked cookies from browser | ✅ Full |
| Bearer token + optional refresh | Authorization header | ✅ Full |
| TOTP/authenticator app MFA | Time-based OTP seed | ✅ Partial |
| No auth | Public surface testing | ✅ Full |
| SMS/push MFA | External MFA factor | ❌ v2 |
| SAML/SSO | Enterprise SSO flows | ❌ v2 |
| OAuth authorization code flow | Three-legged OAuth | ❌ v2 |
| Hardware key (FIDO2) | Physical security key | ❌ Out of scope |

### Headless login flow

`AuthManager` uses Playwright to drive the login UI:
1. Navigate to login URL
2. Fill credential fields
3. Handle TOTP if seed provided (compute current code via TOTP library)
4. Wait for auth-success indicator (redirect, DOM change, network response pattern)
5. Capture all resulting cookies and tokens from network responses
6. Store as `SessionSnapshot`
7. Verify by probing a known-authenticated endpoint

### Session state management

- `AuthManager` holds one canonical `AuthContext` per active scan
- Workers **never hold session state** — they request a fresh snapshot per task
- This prevents stale-session drift across parallel workers
- Session snapshots include: cookies array, Authorization header value, any CSRF tokens observed

### Session health monitoring

- `AuthManager` runs a lightweight health probe every 5 minutes (configurable)
- Probes a known-authenticated endpoint and checks response
- If health fails → triggers re-authentication before workers hit an expired session
- If re-auth fails (MFA challenge, credential expired) → scan **pauses with explicit error**

### Session expiry handling

- Each `AuthContext` has an estimated `expires_at` based on observed session timeout patterns
- If refresh token is available → proactively refreshes before expiry
- If no refresh token → re-runs full login flow before expiry

### Multi-step login flows (v1 support)

Expressed as a JSON-based login recipe:
```json
{
  "steps": [
    { "action": "navigate", "url": "https://app.example.com/login" },
    { "action": "fill", "selector": "#email", "value": "{email}" },
    { "action": "fill", "selector": "#password", "value": "{password}" },
    { "action": "click", "selector": "button[type=submit]" },
    { "action": "wait_for_url", "pattern": "/dashboard" }
  ]
}
```

Complex SSO/SAML flows → documented limitation: "provide a pre-authenticated session cookie instead."

### The escape hatch

Users can always bypass auth automation by pasting session cookies directly. This escape hatch is **strategically important** — it means complex SSO environments can still get value from ProofScan before their specific auth pattern is automated. It must be a first-class, well-documented input path.

---

## 8. Attack Engine Design

### Architecture: Rule-based core + AI-assisted anomaly layer

The primary attack generation is **deterministic and rule-based**. This is intentional:
- Rules are auditable and predictable
- Low false-positive rate
- Can be unit-tested against known-vulnerable apps

AI augmentation handles one specific task: identifying anomalous response patterns that suggest untested attack surface (unexpected fields in API responses, inconsistent authorization patterns, role-suggestive parameter names). AI does **not** generate free-form attacks in v1.

### Attack rule library structure

Rules are Python classes. No DSL. No YAML. No XML. Rules are code and must be unit-testable.

```python
class AttackRule:
    attack_class: str
    name: str
    
    def matches(self, endpoint: Endpoint, asset_map: AssetMap) -> bool:
        """Returns True if this rule applies to the given endpoint."""
        ...
    
    def generate_tasks(self, endpoint: Endpoint, context: ScanContext) -> List[AttackTask]:
        """Returns ordered list of AttackTask objects for this endpoint."""
        ...
    
    def expected_proof_signal(self) -> str:
        """Describes what a successful exploit looks like for the Validator."""
        ...
```

### v1 Rule library — required rules

| Rule | Trigger condition | Attack hypothesis |
|------|------------------|-------------------|
| `BolaBidirectional` | `GET /resource/{id}` with auth required | Substitute another user's resource ID — confirm unauthorized access |
| `PrivilegeEscalation` | Parameter named `role`, `user_id`, `account_id`, `org_id` | Substitute higher-privilege value — confirm access change |
| `TenantIsolation` | Multi-tenant patterns in URL or response body | Cross-tenant ID substitution — confirm data leakage |
| `AuthBypass` | Auth-required endpoint with session dependency | Remove/downgrade auth header — confirm access is truly enforced |
| `WorkflowAbuse` | Multi-step state chain observed in recon | Skip prerequisite step — confirm state machine enforces order |
| `SensitiveExposure` | Endpoint returns structured data | Check response for tokens, credentials, PII, cross-user identifiers |
| `InjectionSql` | String input parameter in state-changing endpoint | Error-based and response-differential probes — only where error output is feasible to capture |

### How stateful flows are handled

1. `AttackPlanner` identifies multi-step sequences from `AssetMap` (step A → step B based on redirect chains, sequential API calls observed in recon)
2. For these, `AttackTask` objects are chained — worker must execute prerequisite steps before the attack step
3. Intermediate state (tokens, IDs from step A) is captured and passed to step B

### What the engine explicitly does not do

- Random fuzzing — every task has a specific hypothesis and defined expected proof signal
- "Send 10,000 random strings to every parameter" is not in the engine
- Free-form AI-generated attack payloads
- Port scanning or infrastructure enumeration
- Exploiting third-party dependencies or CDN origins

### Attack prioritization scoring

Priority score (0.0–1.0) assigned by `AttackPlanner`:

| Factor | Weight |
|--------|--------|
| Attack class is BOLA/IDOR or tenant isolation | +0.40 |
| Endpoint is auth-required | +0.20 |
| Endpoint is state-changing (POST/PUT/DELETE) | +0.15 |
| Parameter names suggest resource ownership | +0.15 |
| Proof path is feasible (validator has a confirmation method) | +0.10 |

Tasks are processed in descending priority order.

---

## 9. Proof and Validation Model

### Confidence threshold

Default: **0.85**. Configurable per scan. A `ProofArtifact` with confidence below this threshold is stored but **never becomes a `Finding`**.

### Proof types by attack class

#### BOLA / IDOR — Differential proof required

1. Control probe: confirm requester does not own target resource (own resource returns expected data)
2. Attack probe: fetch resource with another user's resource ID
3. Validation: response bodies differ meaningfully (content comparison, not just status code)
4. Confidence HIGH: confirmed with a second test account's resource ID
5. Confidence MEDIUM: resource ID was guessed/incremented but ownership ambiguous

#### Tenant isolation — Differential proof required

1. Substitute cross-tenant ID in request
2. Response contains tenant-identifying markers from another tenant
3. Requires minimum two test accounts in different tenants OR observable tenant markers in responses

#### Auth bypass — Absolute proof required

1. Remove or downgrade auth token/cookie
2. Request reaches a resource that should require auth
3. Response must match authenticated response structurally (not just return a 200)

#### Sensitive data exposure — Absolute proof required

1. Response contains tokens, credentials, PII patterns, or secrets
2. Must confirm the requester's auth level should not have access to this data
3. Pattern matching on response body against credential/token/PII heuristics

#### Injection (SQL, command) — Absolute proof required

1. Response contains database error messages, or
2. Observable data extraction evidence, or
3. Timing differential for blind injection (requires multiple confirmations)
4. Free-form data extraction is **not claimed without visible output evidence**

#### Workflow abuse — Reproduction proof required

1. Full request chain stored as evidence
2. Demonstrates bypass of intended state machine
3. Confirms arrival at unauthorized or invalid state

### What does NOT become a finding

- Response time anomalies without corroboration
- Unexpected status codes without behavioral confirmation
- Headers that look misconfigured but cannot be shown to enable exploitation
- XSS that exists but cannot be demonstrated to execute in a controlled context (v1 limitation — flagged as "requires manual confirmation", never as a finding)
- Any potential issue where the validator has no confirmation method

### Low-confidence signals handling

Probes that pass initial validation but score below 0.85 → go into a "signals requiring manual review" store. These are **never surfaced in the main findings report**. They may be included in a separate optional section (off by default). This boundary is **architecturally enforced**, not a UI toggle.

---

## 10. Noise-Reduction Strategy

### Mechanism 1 — Proof-gate at the Validator

Nothing without a `ProofArtifact` becomes a finding. This eliminates the majority of false positives by design.

### Mechanism 2 — Structural deduplication before write

Before creating a `Finding`, the scorer computes a structural fingerprint:

```python
fingerprint = (attack_class, normalize_url_pattern(endpoint), parameter_class)
```

If a finding with the same fingerprint already exists for this scan, the new evidence is attached to the existing finding instead of creating a duplicate. This prevents the "same IDOR on 47 different resource IDs" explosion.

### Mechanism 3 — No theoretical findings

The attack engine only queues tasks with feasible proof signals. There is no "this header is missing, therefore potentially vulnerable" category. Every `AttackTask` must have a defined `expected_proof_signal`.

### Mechanism 4 — Differential probing as default

Most validators run a control probe alongside the attack probe. The system reports only the delta. This catches cases where a generic response pattern looks like a finding but is how the endpoint behaves normally.

### Mechanism 5 — Scope enforcement

The crawler respects strict scope rules: target domain(s) defined at scan creation only. No attacks are issued against third-party domains, CDN origins, or OAuth providers even if linked from the target. Out-of-scope endpoints are recorded in `AssetMap` but never queued for attack.

### Mechanism 6 — Attack class gating

Some attack classes only activate when prerequisite conditions are met:
- BOLA/IDOR: requires either a second test account or observable resource ID patterns. If neither exists → class is noted as "not tested, prerequisite unmet" in the report.
- Injection: only queued when error output or timing differential is a feasible proof path.

---

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

## 12. Security and Safety Constraints

### Scan isolation

- Each scan runs in an isolated network context
- Workers cannot reach internal ProofScan infrastructure from the target-facing network path
- Scan containers have no access to other scans' data
- Evidence Store access is scoped per scan ID at the IAM/policy level

### Credential handling

- Auth credentials encrypted at rest using envelope encryption (data key per scan, master key in KMS)
- Credentials are **never logged**
- Raw credentials are purged from the database after scan completes
- Only session snapshot (no raw passwords) retained for evidence reproduction
- API responses never return raw credentials to the client

### Evidence redaction

- Evidence Store stores **full unredacted** request/response pairs (required for valid proof)
- Redaction applied **at export time only**
- Redacted fields: `Authorization` header, `Cookie` header, request body credential fields, values matching token patterns
- Redacted values replaced with `[REDACTED]` in exported reports
- Full evidence visible to authenticated users in product UI

### Rate limiting and target safety

- Per-scan rate limits enforced at worker pool level
- Workers cannot exceed configured rates regardless of queue depth
- **Default profile (production):** 30 req/min per worker, 150 req/min total per scan
- **Fast mode:** Higher limits with explicit user acknowledgment
- `--production-safe` flag: enforces stricter limits AND excludes state-changing attack classes (no POST/PUT/DELETE attacks unless explicitly opted in)

### Safe exploitation boundaries

- Engine **never exploits to impact** — it probes to confirm exploitability
- For injection: confirms class and demonstrates extractability against controlled data, not real user PII
- For IDOR: confirms access to the resource exists — does not exfiltrate, cache, or display accessed content beyond what is needed for proof
- Response size limit: responses above 1MB are truncated for storage (head + tail captured)

### Scan authorization

- Users must affirm they are authorized to test the target (checkbox at scan creation, timestamped and stored)
- v1 does not perform automated ownership verification (DNS TXT record etc.) — v1.1 item

### No persistent footprint on target

Workers do not:
- Create accounts autonomously
- Leave injected payloads in the target
- Modify application state as a side effect of scanning
- Deposit anything in target databases

Test-account creation (for BOLA testing) is done with user-provided credentials only.

---

## 13. Tech Stack

### Backend / API

**Python + FastAPI**

Rationale: fast to write, excellent async support, great Playwright integration, mature security tooling ecosystem.

### Task queue

**rq (Redis Queue)** if staying Python-only, or **BullMQ** (Node.js) for better visibility tooling. Default: rq.

### Attack Workers

**Python + httpx** — stateless, fast, easy to test. Attack rules are plain Python classes.

### Crawler + Auth Manager

**Python + Playwright** — production-quality Python API, full browser control for auth flows, JavaScript execution, network interception.

### Validator

**Python** — pure logic, no infrastructure dependency. Runs as a separate queue consumer.

### Database ORM

**SQLAlchemy (async) + Alembic for migrations**

### Evidence Store client

**boto3** (S3)

### Frontend (reporting UI)

**Next.js (React)**

v1 beta: clean JSON API + Markdown export is acceptable. Next.js UI required for GA.

### Headless browser

**Playwright** (not Puppeteer, not Selenium)

Reasons: better network interception API, more actively maintained, better multi-browser support.

### Deployment

- Development: **Docker Compose**
- Production: **AWS ECS Fargate** + RDS + ElastiCache + S3

### Why not Go for v1

Python's security tooling ecosystem, Playwright bindings, and iteration speed are better for v1. Go is appropriate for the worker hot path in v2 if latency becomes a bottleneck.

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

## 14. Biggest Technical Risks

### Risk 1 — Auth handling breadth vs. depth (HIGH)

Login flows are highly idiosyncratic. The headless Playwright approach handles ~70% of real-world cases. The remaining 30% — custom JS-heavy login flows, redirect-heavy SSO, iframe-embedded auth — require per-customer workarounds.

**Mitigation:** Invest heavily in the "paste your session cookie" fallback path as an escape hatch. Document it prominently. Make it the first recommended path for complex SSO environments.

### Risk 2 — BOLA/IDOR proof without two test accounts (HIGH)

The highest-value attack class requires the ability to confirm cross-user access. Without a second test account or injectable IDs from recon, BOLA tests degrade to heuristic-only.

**Mitigation:** Require two test accounts as a first-class part of onboarding UX. Make the prerequisite-unmet state explicit in reports.

### Risk 3 — Playwright stability at scale (MEDIUM-HIGH)

Browser-based crawling is inherently fragile: memory leaks, rendering hangs, JavaScript errors in target apps causing worker crashes.

**Mitigation:** Worker supervision, crash detection, and automatic restart must be designed in from day one. Implement worker health heartbeats. Set hard timeouts on all Playwright operations.

### Risk 4 — Validator false negative calibration (MEDIUM)

If the validator is too strict, real findings are silently missed. If too loose, noise creeps in.

**Mitigation:** Build a corpus of deliberately vulnerable test apps (Juice Shop, DVWA, custom microservices) before GA. Treat the test corpus as a CI suite — every validator change must run against it.

### Risk 5 — Attack rule scope creep (MEDIUM)

The attack rule library will grow. Without a disciplined gating process, theoretical and noisy rules will degrade product quality.

**Mitigation:** Every rule addition requires a passing test case in a known-vulnerable app from the test corpus. Gate this in CI. "Does this rule have a defined, automatable proof signal?" is the acceptance criterion.

---

## 15. Scope Boundaries — What Is Excluded from v1

### Hard exclusions (never build these as part of v1)

| Category | Reason for exclusion |
|----------|---------------------|
| SAST | Source code not required; different product entirely |
| SCA (dependency scanning) | Different problem, different tooling |
| Secrets scanning | Out of scope |
| CSPM / CNAPP | Cloud infrastructure layer, not app layer |
| Compliance workflows | Security theater, not attacker value |
| Enterprise RBAC | Premature at target customer size |
| PTaaS service model | Human-in-the-loop defeats automation value |
| Single-pane-of-glass dashboards | Scope creep |
| OAuth authorization code flow automation | v2 auth item |
| SAML / SSO automation | v2 auth item |
| SMS / push MFA | v2 auth item |
| Full attack path chaining | v2 — build on top of existing finding dataset |
| Scheduled recurring scans | v2 — add after trust is established |
| Multi-region deployment | v1.1 |
| DNS TXT ownership verification | v1.1 |
| XSS as a confirmed finding | v1 limitation — flagged as "requires manual confirmation" |

### What to cut if scope must shrink by 30–40%

Remove in this order while preserving the core wedge:

1. **Cut attack path construction** — single validated findings with proof are the value. Attack paths are a nice-to-have for v1.
2. **Cut injection classes** — already served by existing tools, proof is hard without error output. Focus entirely on auth/access control issues.
3. **Cut the frontend UI** — deliver findings as JSON + Markdown for v1 beta. Add UI for GA.
4. **Cut multi-scan scheduling** — one scan at a time per workspace.
5. **Cut advanced MFA** — TOTP seed only. All other MFA: user provides pre-authenticated session cookie.

**What absolutely cannot be cut:**
- Proof validation (the validator)
- The AuthManager
- BOLA/IDOR attack class
- Differential probing
- Evidence Store
- Deduplication before write

---

## 16. Implementation Priorities

### Phase 1 — Foundation (implement first, block everything else)

1. `AuthManager` with Playwright-based login flow and session snapshot distribution
2. Session cookie escape hatch (paste-your-cookies path)
3. `CrawlerReconEngine` with `AssetMap` output
4. PostgreSQL schema (all entities from Section 6)
5. Task queue (rq + Redis)
6. Worker supervisor with crash detection and restart

### Phase 2 — Core attack loop

1. `AttackPlanner` with initial rule library (BOLA + tenant isolation rules first)
2. `AttackWorkers` (stateless, rate-limited, httpx-based)
3. `ExploitValidator` with differential probing for BOLA/IDOR
4. `EvidenceStore` (S3 integration)
5. Test corpus setup (Juice Shop + custom vulnerable API)

### Phase 3 — Finding output

1. `FindingScorer` with structural deduplication
2. `ReportingService` with JSON + Markdown output
3. Evidence redaction at export time
4. Scan authorization acknowledgment flow

### Phase 4 — Remaining attack classes

1. Auth bypass rules + validator
2. Privilege escalation rules + validator
3. Sensitive data exposure rules + validator
4. Workflow abuse rules + validator
5. Injection rules (SQL error-based only, where proof is feasible)

### Phase 5 — Production hardening

1. Rate limiting and `--production-safe` mode
2. Credential encryption (KMS envelope)
3. Worker isolation (network policy enforcement)
4. Structured logging (structlog)
5. ECS Fargate deployment configuration

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

## Appendix B — Key Configuration Values

```python
# Scan defaults
DEFAULT_RECON_TIMEOUT_MINUTES = 10
DEFAULT_RATE_LIMIT_RPS = 2.5          # 150/min total, 30/min per worker
DEFAULT_MAX_WORKERS_PER_SCAN = 10
DEFAULT_AUTH_HEALTH_CHECK_INTERVAL_S = 300  # 5 minutes
DEFAULT_RESPONSE_SIZE_LIMIT_BYTES = 1_048_576  # 1MB

# Validation
DEFAULT_PROOF_CONFIDENCE_THRESHOLD = 0.85
LOW_CONFIDENCE_STORE_THRESHOLD = 0.50  # below this, discard entirely

# Evidence
EVIDENCE_COMPRESSION = "gzip"
EVIDENCE_KEY_PATTERN = "{scan_id}/{finding_id}/{probe_id}.json.gz"

# Rate limiting (production-safe mode)
PRODUCTION_SAFE_RATE_LIMIT_RPS = 1.0
PRODUCTION_SAFE_EXCLUDE_METHODS = ["POST", "PUT", "PATCH", "DELETE"]
```

---

*Document version: 1.0.0 — ProofScan founding architecture*
*This document governs all v1 implementation decisions.*
*Changes to architectural invariants (Sections 3, 9, 10) require explicit revision of this document before implementation proceeds.*
