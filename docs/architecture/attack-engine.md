# ProofScan — Attack Engine
Source: `ARCHITECTURE.md` — Section 8, Section 4 (`AttackPlanner`, `AttackWorkers`), Section 5 (Steps 4-5), Section 3 (P3), Section 14 (Risk 5).

### P3 — Attack depth over attack breadth

It is better to deeply test 20 endpoints with attacker-relevant logic than to superficially ping 200 with generic checks. The engine prioritizes high-value targets: auth endpoints, resource operations, state transitions, ID-parameterized routes.

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

### Risk 5 — Attack rule scope creep (MEDIUM)

The attack rule library will grow. Without a disciplined gating process, theoretical and noisy rules will degrade product quality.

**Mitigation:** Every rule addition requires a passing test case in a known-vulnerable app from the test corpus. Gate this in CI. "Does this rule have a defined, automatable proof signal?" is the acceptance criterion.

---
