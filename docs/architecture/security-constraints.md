# ProofScan — Security Constraints
Source: `ARCHITECTURE.md` — Section 12 (all subsections), Section 3 (P5), Appendix B (Rate limit constants).

### P5 — The execution plane does not trust itself

Workers are untrusted, rate-limited, and isolated. They cannot write findings. They produce evidence artifacts. The control plane decides what becomes a finding.

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

```python
# Rate limiting (production-safe mode)
PRODUCTION_SAFE_RATE_LIMIT_RPS = 1.0
PRODUCTION_SAFE_EXCLUDE_METHODS = ["POST", "PUT", "PATCH", "DELETE"]
```
