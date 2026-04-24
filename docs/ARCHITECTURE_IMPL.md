# ProofScan v1.0 — Implementation Architecture

> Dokument uzupełniający do ARCHITECTURE.md. Zawiera szczegóły implementacyjne: interfejsy modułów, grafy zależności, kontrakty między komponentami i decyzje nieoczywiste z punktu widzenia kodu. ARCHITECTURE.md jest dokumentem nadrzędnym — jeśli coś tu jest niezgodne z tam, ARCHITECTURE.md wygrywa.

---

## 1. Mapa modułów i zależności

```
api/
  main.py              ← FastAPI app, mounts routers
  routers/
    scans.py           ← POST /scans, GET /scans/{id}, PATCH /scans/{id}/pause
    findings.py        ← GET /scans/{id}/findings
    reports.py         ← GET /scans/{id}/report (JSON + Markdown)
    auth_check.py      ← POST /auth/verify (testuje dane auth przed skanem)
  models/
    requests.py        ← Pydantic request schemas (ScanCreate, AuthContextCreate)
    responses.py       ← Pydantic response schemas (ScanResponse, FindingResponse)

control_plane/
  orchestrator.py      ← ScanOrchestrator — lifecycle FSM, fazy: recon→attack→validate→report
  auth_manager.py      ← AuthManager — Playwright login, SessionSnapshot, health probe
  finding_scorer.py    ← FindingScorer — fingerprint dedup, severity assignment
  reporting.py         ← ReportingService — JSON + Markdown render, evidence fetch, redaction

execution_plane/
  crawler/
    engine.py          ← CrawlerReconEngine — headless Playwright crawl, XHR interception
    asset_map.py       ← AssetMap builder — endpoint normalization, auth-gate detection
  planner/
    planner.py         ← AttackPlanner — reguły → AttackTask queue, scoring
    rules/
      base.py          ← AttackRule ABC
      bola.py          ← BolaBidirectional rule
      tenant_isolation.py
      auth_bypass.py
      privilege_escalation.py
      workflow_abuse.py
      sensitive_exposure.py
      injection.py
  workers/
    attack_worker.py   ← AttackWorker — httpx, single-task, RawProbe output
    supervisor.py      ← WorkerSupervisor — rq job management, crash detection, restart
  validator/
    validator.py       ← ExploitValidator — queue consumer, proof threshold enforcement
    strategies/
      base.py          ← ValidationStrategy ABC
      bola.py          ← differential proof dla BOLA/IDOR
      auth_bypass.py   ← absolute proof
      privilege_escalation.py
      sensitive_exposure.py
      workflow_abuse.py
      injection.py

storage/
  db/
    models.py          ← SQLAlchemy models (wszystkie encje z sekcji 6 ARCHITECTURE.md)
    session.py         ← async engine + session factory
    migrations/        ← Alembic migrations
  evidence/
    store.py           ← EvidenceStore — S3 boto3, gzip, key pattern

tests/
  unit/                ← reguły ataku, validator strategies, dedup logic
  integration/         ← API endpoints, auth flows
  corpus/              ← Juice Shop + custom vulnerable API test cases
```

---

## 2. Kluczowe interfejsy (kontrakty między komponentami)

### SessionSnapshot (AuthManager → Workers)

```python
@dataclass
class SessionSnapshot:
    scan_id: UUID
    cookies: list[dict]          # [{name, value, domain, path, ...}]
    auth_headers: dict[str, str] # {"Authorization": "Bearer ...", ...}
    csrf_tokens: dict[str, str]  # {"X-CSRF-Token": "...", ...}
    captured_at: datetime
    expires_at: Optional[datetime]
```

Workers NIGDY nie modyfikują SessionSnapshot. Dostają kopię per task.

### RawProbe (Workers → Evidence Buffer → Validator)

```python
@dataclass
class RawProbe:
    id: UUID
    attack_task_id: UUID
    worker_id: str
    timestamp: datetime
    request: HttpRequest    # method, url, headers, body (bytes)
    response: HttpResponse  # status, headers, body (bytes), latency_ms
    control_probe_id: Optional[UUID]  # jeśli to probe kontrolny, tu None
```

### ProofArtifact (Validator → FindingScorer + EvidenceStore)

```python
@dataclass
class ProofArtifact:
    id: UUID
    attack_task_id: UUID
    proof_type: Literal["differential", "absolute", "reproduction"]
    confidence_score: float        # >= 0.85 → może stać się Finding
    attack_probe_id: UUID
    control_probe_id: Optional[UUID]
    summary: str
    evidence_notes: str
```

### AttackTask (queue payload)

```python
@dataclass
class AttackTask:
    id: UUID
    scan_id: UUID
    endpoint_id: UUID
    attack_class: str
    target_parameter: Optional[str]
    hypothesis: str
    priority_score: float
    chained_from: Optional[UUID]   # dla stateful flows
    prerequisite_state: dict       # tokeny/ID z poprzedniego kroku
```

---

## 3. Kolejność inicjalizacji (start aplikacji)

```
1. DB connection pool (SQLAlchemy async engine)
2. Redis connection (rq queue)
3. S3 client init (boto3)
4. FastAPI app mount
5. AuthManager instancja per scan (tworzona przez Orchestrator przy starcie skanu)
6. WorkerSupervisor start (rq workers)
7. ExploitValidator queue consumer start
8. FindingScorer queue consumer start
```

---

## 4. Lifecycle skanu (FSM)

```
created
  └─→ [auth_bootstrap] ─→ running/recon
        │
        ├─ auth fail → paused (error: auth_failed)
        │
        └─ success → running/recon
                       │
                       └─→ [crawl complete] → running/attack
                                               │
                                               └─→ [all tasks done] → running/validate
                                                                        │
                                                                        └─→ [queue empty] → running/reporting
                                                                                             │
                                                                                             └─→ complete
Każdy stan może przejść w → failed (nieoczekiwany błąd) lub paused (user action / auth failure)
```

---

## 5. Auth Manager — szczegóły implementacji

### Login flow strategy

```python
class AuthManager:
    async def bootstrap(self, auth_input: AuthContextCreate) -> AuthContext:
        if auth_input.type == "session":
            return self._from_cookies(auth_input.cookies)
        elif auth_input.type == "token":
            return self._from_bearer(auth_input.token, auth_input.refresh_token)
        elif auth_input.type == "credential":
            return await self._playwright_login(auth_input)
```

### Health check loop

```python
# Co DEFAULT_AUTH_HEALTH_CHECK_INTERVAL_S (300s):
async def _health_loop(self):
    while self._active:
        await asyncio.sleep(AUTH_HEALTH_CHECK_INTERVAL_S)
        ok = await self._probe_authenticated_endpoint()
        if not ok:
            refreshed = await self._attempt_refresh()
            if not refreshed:
                await self._pause_scan(reason="auth_expired")
```

### Playwright login recipe wykonanie

```python
ACTION_HANDLERS = {
    "navigate": lambda page, step: page.goto(step["url"]),
    "fill":     lambda page, step: page.fill(step["selector"], step["value"]),
    "click":    lambda page, step: page.click(step["selector"]),
    "wait_for_url": lambda page, step: page.wait_for_url(step["pattern"]),
}
```

---

## 6. Attack Worker — szczegóły implementacji

### Rate limiter (token bucket per domain)

```python
class DomainRateLimiter:
    # Trzymany w Redis — współdzielony między wszystkimi workerami tego skanu
    # Klucz: f"rate:{scan_id}:{domain}"
    # Default: 2.5 req/s (150/min total), 0.5 req/s per worker (30/min)
```

### Worker nie ma dostępu do

- Bazy danych (PostgreSQL) — tylko API
- S3 bezpośrednio — tylko przez Evidence Buffer (Redis stream)
- Innych skanów — rate limiter scoped do scan_id
- Systemu plików hosta

---

## 7. Validator — strategia per klasa ataku

### BOLA/IDOR (differential)

```
1. Sprawdź że attack_probe.response != control_probe.response
2. Sprawdź że attack_probe.response.status != 403/404
3. Sprawdź że body attack_probe zawiera dane (nie empty/error)
4. confidence = 0.90 jeśli body semantycznie różne od własnego zasobu
             = 0.70 jeśli tylko status różny (degraded — nie przechodzi 0.85)
```

### Auth bypass (absolute)

```
1. attack_probe ma usunięty/zdegradowany auth header
2. response.status == 200 (lub taki jak authenticated baseline)
3. response.body strukturalnie zbliżone do authenticated response
4. confidence = 0.95 jeśli body match > 80%, 0.60 jeśli tylko status match
```

---

## 8. Finding Scorer — fingerprint i dedup

```python
def compute_fingerprint(proof: ProofArtifact, endpoint: Endpoint) -> str:
    pattern = normalize_url_pattern(endpoint.url_pattern)
    param_class = classify_parameter(proof.attack_task.target_parameter)
    return f"{proof.attack_task.attack_class}:{pattern}:{param_class}"

def normalize_url_pattern(url: str) -> str:
    # /api/users/123/posts/456 → /api/users/{id}/posts/{id}
    return re.sub(r'/\d+', '/{id}', url)
```

Severity mapping:

| attack_class | confidence | severity |
|---|---|---|
| bola, tenant_isolation | >= 0.90 | critical |
| bola, tenant_isolation | 0.85–0.89 | high |
| auth_bypass, privilege_escalation | >= 0.85 | critical |
| sensitive_exposure | >= 0.85 | high |
| workflow_abuse | >= 0.85 | medium |
| injection | >= 0.90 | high |

---

## 9. Evidence Store — format klucza i struktura

```
S3 bucket: proofscan-evidence-{env}

Klucze:
  {scan_id}/{finding_id}/{probe_id}.json.gz      ← RawProbe bundle
  {scan_id}/{finding_id}/proof_{artifact_id}.json.gz  ← ProofArtifact

Struktura JSON wewnątrz:
{
  "probe_id": "...",
  "attack_task_id": "...",
  "request": {
    "method": "GET",
    "url": "...",
    "headers": {"Authorization": "Bearer [REDACTED]"},  // redacted już w Evidence? NIE
    "body": "..."
  },
  "response": {
    "status": 200,
    "headers": {...},
    "body": "...",
    "latency_ms": 142
  },
  "captured_at": "2024-01-01T00:00:00Z"
}
```

**WAŻNE:** Evidence Store zapisuje PEŁNE dane bez redakcji. Redakcja wyłącznie w ReportingService przy eksporcie.

---

## 10. Konfiguracja środowiskowa (.env)

```env
# Database
DATABASE_URL=postgresql+asyncpg://user:pass@localhost/proofscan

# Redis
REDIS_URL=redis://localhost:6379/0

# S3
AWS_ACCESS_KEY_ID=...
AWS_SECRET_ACCESS_KEY=...
AWS_DEFAULT_REGION=us-east-1
EVIDENCE_BUCKET=proofscan-evidence-dev

# Encryption (KMS — Sprint 9)
KMS_MASTER_KEY_ID=...

# Scan defaults (można overridować per scan)
DEFAULT_RECON_TIMEOUT_MINUTES=10
DEFAULT_RATE_LIMIT_RPS=2.5
DEFAULT_MAX_WORKERS_PER_SCAN=10
DEFAULT_PROOF_CONFIDENCE_THRESHOLD=0.85

# Auth health check
AUTH_HEALTH_CHECK_INTERVAL_S=300
```

---

## 11. Reguły, których nie można złamać (z ARCHITECTURE.md Section 3)

| Zasada | Konkretna implementacja |
|--------|------------------------|
| P1 — Proof-gate | `if proof.confidence_score < threshold: return` — nigdy omijaj |
| P2 — Auth first-class | Skan **nigdy** nie kontynuuje z expired session bez explicit re-auth |
| P3 — Depth over breadth | AttackPlanner zwraca max 50 tasków na endpoint (konfigurowalny) |
| P4 — Dedup before write | `FindingScorer.score()` sprawdza fingerprint PRZED `db.add(finding)` |
| P5 — Workers untrusted | Workers piszą tylko do Redis stream (Evidence Buffer), nigdy do DB/S3 bezpośrednio |
| P6 — Recon not spidering | CrawlerReconEngine time-boxed, nie podąża za linkami poza scope |
