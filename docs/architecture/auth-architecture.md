# ProofScan — Auth Architecture
Source: `ARCHITECTURE.md` — Section 7, Section 3 (P2), Section 5 (Steps 1-2), Section 4 (`AuthManager`), Section 14 (Risk 1).

### P2 — Auth is the product

Authenticated state is a first-class resource. It is managed centrally by the Auth Manager, refreshed proactively, and distributed to every attack worker. A scan that silently loses auth and continues is strictly worse than one that pauses and re-authenticates.

#### `AuthManager`

- Bootstraps authenticated sessions from user-provided credentials/session material
- Holds live session state: cookies, tokens, refresh tokens
- Proactively monitors session health and re-authenticates before expiry
- Distributes valid session snapshots to workers on demand
- Long-running stateful service — not a helper function

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

### Risk 1 — Auth handling breadth vs. depth (HIGH)

Login flows are highly idiosyncratic. The headless Playwright approach handles ~70% of real-world cases. The remaining 30% — custom JS-heavy login flows, redirect-heavy SSO, iframe-embedded auth — require per-customer workarounds.

**Mitigation:** Invest heavily in the "paste your session cookie" fallback path as an escape hatch. Document it prominently. Make it the first recommended path for complex SSO environments.
