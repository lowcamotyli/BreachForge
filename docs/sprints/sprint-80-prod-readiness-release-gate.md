## Sprint 80 — PROD_READINESS.md + Release Gate

**Goal:** Stworzyć formalną, weryfikowalną checklistę release gate i przeprowadzić końcowy security sweep.
Po tym sprincie mamy dokument który blokuje lub odblokowuje ship.

### Scope

**Tworzymy:**
- `PROD_READINESS.md` w root projektu — checklist blokujący release, każdy punkt weryfikowalny poleceniem
- Końcowy Gemini invariants check na auth/RBAC/secrets/audit ścieżkach
- Końcowy security sweep: grep na anti-patterns
- Decyzja SHIP / NO-SHIP z przyjętymi ryzykami

### Architektura — dokumenty referencyjne

```bash
{
  echo "=== FILE: security-constraints.md ==="; cat ~/Projects/BreachForge/docs/architecture/security-constraints.md
  echo "=== FILE: data-model.md ==="; cat ~/Projects/BreachForge/docs/architecture/data-model.md
} | gemini --output-format text \
  -p "Files above. List ALL production readiness requirements: security, data isolation, auth, encryption, deployment. PASS/FAIL format for each. Max 30 lines." \
  2>&1 | grep -v "^Warning:" | grep -v "^Ripgrep"
```

### Workstream A — PROD_READINESS.md

Jedyny plik tworzony w tym sprincie przez Claude bezpośrednio (jest to dokument decyzyjny, nie kod).

Struktura `PROD_READINESS.md`:

```markdown
# ProofScan Production Readiness Gate

## Instrukcja użycia
Każdy punkt ma polecenie weryfikacji. Uruchom przed każdym release.
SHIP = wszystkie punkty PASS. Każde FAIL blokuje release do naprawy.

## 1. Auth & Identity
- [ ] Brak in-memory role stores: `grep -rn "^_[A-Z].*= {}" api/ --include="*.py"` → 0
- [ ] API key verification aktywne: `grep -rn "get_verified_actor\|VerifiedActor" api/dependencies/auth.py` → min 2
- [ ] Dev mode gate: `grep -rn "PROOFSCAN_DEV_MODE" api/dependencies/auth.py` → min 1
- [ ] X-Actor-Email bez tokenu → 401: `python -m pytest tests/unit/api/dependencies/test_auth.py -q` → passed

## 2. Persistent State
- [ ] Brak module-level dict stores: `grep -rn "^_[A-Z].*= {}" api/routers/ api/middleware/ --include="*.py"` → 0
- [ ] Org store używa DB: `grep -rn "_ORG_STORE" api/routers/orgs.py` → 0
- [ ] API keys używają DB: `grep -rn "_API_KEYS" api/routers/api_keys.py` → 0
- [ ] RBAC używa DB: `grep -rn "RoleStore._roles\|self._roles" api/middleware/rbac.py` → 0

## 3. Secrets & Encryption
- [ ] XOR encryption usunięte: `grep -rn "token_bytes.*zip\|key.hex()" storage/secrets/vault.py` → 0
- [ ] Fernet używany: `grep -rn "Fernet\|VAULT_ENCRYPTION_KEY" storage/secrets/vault.py` → min 2
- [ ] Secrets table istnieje: weryfikacja przez `alembic upgrade head` + `\dt secrets`
- [ ] VAULT_ENCRYPTION_KEY wymagany: `grep -rn "RuntimeError.*VAULT_ENCRYPTION_KEY" storage/secrets/vault.py` → min 1

## 4. Audit Log
- [ ] In-memory audit usunięte: `grep -rn "_AUDIT_EVENTS\|_AUDIT_EXPORTS" api/routers/audit.py` → 0
- [ ] Audit table istnieje w migracji: `grep -rn "audit_events" storage/db/migrations/versions/` → min 1
- [ ] Tenant scoping audit: `grep -rn "org_id" api/routers/audit.py` → min 2

## 5. Invariants (z CLAUDE.md)
- [ ] Proof-gate: `grep -rn "0.85" execution_plane/validator/` → min 1, bez bypasses
- [ ] Auth-first: `grep -rn "auth_fail\|expired_session\|pause" control_plane/orchestrator.py` → min 1
- [ ] Worker isolation: `grep -rn "direct.*db\|session.*db\|AsyncSession" execution_plane/workers/` → 0
- [ ] Dedup before write: `grep -rn "fingerprint.*before\|dedup" control_plane/finding_scorer.py` → min 1
- [ ] No credentials in logs: `grep -rn "strip.*Authorization\|strip.*Cookie" control_plane/` → min 1
- [ ] Redaction at export: `grep -rn "redact" control_plane/reporting.py` → min 2

## 6. Deploy
- [ ] Production compose bez LocalStack: `grep -n "localstack\|AWS_ENDPOINT_URL" docker/docker-compose.prod.yml` → 0
- [ ] Non-root user: `grep -n "USER appuser" docker/Dockerfile.api` → min 1
- [ ] .env.example kompletny: `cat .env.example | grep -c "="` → min 8 zmiennych
- [ ] Alembic fresh start: `python -m pytest tests/integration/test_alembic_fresh.py -v` → passed

## 7. Test Suite
- [ ] Zero collection errors: `python -m pytest tests/ --collect-only -q 2>&1 | grep "ERROR"` → 0
- [ ] Unit tests zielone: `python -m pytest tests/unit/ -q` → 0 failed
- [ ] Integration tests: `python -m pytest tests/integration/ -q` → 0 failed
- [ ] Tenant isolation: `python -m pytest tests/integration/test_tenant_isolation.py -v` → passed

## 8. Security Anti-patterns
- [ ] Brak hardcoded secrets: `grep -rn "password.*=.*['\"]proofscan\|secret.*=.*['\"]dev" control_plane/ api/ storage/ --include="*.py"` → 0
- [ ] Brak SQL string concat: `grep -rn "f\"SELECT\|f'SELECT\|\"SELECT.*{" control_plane/ api/ storage/ --include="*.py"` → 0
- [ ] Brak dangerouslySetInnerHTML (N/A — brak frontendu)

## Accepted Risks (wypełnij przed ship)
- [ ] ...

## SHIP / NO-SHIP
**Status:** SHIP / NO-SHIP
**Data weryfikacji:** ...
**Weryfikujący:** ...
**Zaakceptowane ryzyka:** ...
```

### Workstream B — Końcowy security sweep (Claude direct)

Claude wykonuje bezpośrednio (nie deleguje — to jest ship/no-ship decision):

```bash
# Invariants check:
{
  echo "=== FILE: control_plane/auth_manager.py ==="; cat control_plane/auth_manager.py
  echo "=== FILE: execution_plane/validator/validator.py ==="; cat execution_plane/validator/validator.py
  echo "=== FILE: control_plane/finding_scorer.py ==="; cat control_plane/finding_scorer.py
  echo "=== FILE: control_plane/reporting.py ==="; cat control_plane/reporting.py
  echo "=== FILE: storage/secrets/vault.py ==="; cat storage/secrets/vault.py
  echo "=== FILE: api/dependencies/auth.py ==="; cat api/dependencies/auth.py
} | gemini --output-format text -p \
"Files above. Check each invariant. PASS/FAIL with file:line.
INVARIANTS:
1. ProofArtifact.confidence_score >= 0.85 before Finding write — zero exceptions
2. Auth fail → scan paused with explicit error (not silent skip)
3. Workers write only to Redis buffer — never direct DB or S3
4. FindingScorer checks fingerprint BEFORE db.add()
5. structlog strips Authorization, Cookie, password from all log records
6. Evidence Store writes full data — redaction ONLY in ReportingService
7. X-Actor-Email header alone does not grant access — Bearer token required
8. SecretsVault uses real encryption (not XOR/OTP) — key is not stored alongside ciphertext
9. All API endpoints filter by org_id from VerifiedActor — not from request body
Format: PASS/FAIL: [N] — [file:line or 'not applicable']" 2>&1 | grep -v "^Warning:" | grep -v "^Ripgrep"
```

### Dispatch pattern

**Phase 1:** Claude pisze `PROD_READINESS.md` bezpośrednio (dokument decyzyjny)
**Phase 2:** Claude uruchamia security sweep (Gemini invariants)
**Phase 3:** Claude uruchamia każdy grep z checklisty i wypełnia PASS/FAIL
**Phase 4:** Claude wpisuje SHIP / NO-SHIP decyzję

### Guardrails

- `PROD_READINESS.md` jest git-committed — staje się częścią merge requirements
- Każdy FAIL przed ship musi mieć issue + sprint naprawczy
- "Accepted risks" muszą być opisane — brak pustej sekcji w SHIP decyzji
- Ten sprint jest TYLKO dla Claude'a (orchestrator) — brak dispatchów do codex

### Weryfikacja

```bash
# Uruchom każdy grep z checklisty PROD_READINESS.md
# Każdy FAIL → otwórz issue → plan fix sprint → nie ship

python -m pytest tests/ -q 2>&1 | tail -3
```

### Global acceptance criteria

- [ ] `PROD_READINESS.md` istnieje w root projektu
- [ ] Każdy punkt w checkliście ma polecenie weryfikacji
- [ ] Claude przeprowadził Gemini invariants check (9 invariantów) i wyniki są w WORK.md
- [ ] Wszystkie punkty checklisty wypełnione PASS lub FAIL z uzasadnieniem
- [ ] Decyzja SHIP lub NO-SHIP z datą i zaakceptowanymi ryzykami jest wpisana
