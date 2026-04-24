# ProofScan — Validation Model
Source: `ARCHITECTURE.md` — Section 9, Section 4 (`ExploitValidator`), Section 5 (Step 6), Section 3 (P1), Section 14 (Risk 4), Appendix B (Validation constants).

### P1 — Proof-gate everything

A finding only exists if the Exploit Validator confirms it. No validator confirmation = no finding, regardless of how suspicious the signal looks. This is the single most important architectural invariant in the system.

#### `ExploitValidator`

- **The only component that decides if something is a finding**
- Receives `RawProbe` objects
- Applies validation logic: did the response demonstrate the expected exploitable condition?
- Runs confirmation probes (re-attempt with control request, differential probe)
- Produces `ProofArtifact` if confidence threshold met; otherwise discards

### Step 6 — Validation

`ExploitValidator` processes probe queue continuously:
1. For each promising probe, runs differential validation: control request (no attack) + attack request, compares outcomes
2. Applies class-specific proof criteria (see Section 9)
3. If proof threshold met → writes `ProofArtifact` to Evidence Store
4. If below threshold → discards

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

### Risk 4 — Validator false negative calibration (MEDIUM)

If the validator is too strict, real findings are silently missed. If too loose, noise creeps in.

**Mitigation:** Build a corpus of deliberately vulnerable test apps (Juice Shop, DVWA, custom microservices) before GA. Treat the test corpus as a CI suite — every validator change must run against it.

```python
# Validation
DEFAULT_PROOF_CONFIDENCE_THRESHOLD = 0.85
LOW_CONFIDENCE_STORE_THRESHOLD = 0.50  # below this, discard entirely
```
