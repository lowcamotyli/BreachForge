# ProofScan Production Readiness Gate

## Instrukcja użycia

Każdy punkt ma polecenie weryfikacji. Uruchom przed każdym release.
SHIP = wszystkie punkty PASS lub ACCEPTED_RISK z udokumentowanym uzasadnieniem.
Każde FAIL blokuje release do naprawy lub udokumentowanego accepted risk.

---

## 1. Auth & Identity

- [x] Brak in-memory role stores: `grep -rn "^_[A-Z].*= {}" api/ --include="*.py"` → 0
  **Wynik 2026-05-29:** 0 — PASS

- [x] API key verification aktywne: `grep -rn "get_verified_actor\|VerifiedActor" api/dependencies/auth.py` → min 2
  **Wynik 2026-05-29:** 5 — PASS

- [x] Dev mode gate: `grep -rn "PROOFSCAN_DEV_MODE" api/dependencies/auth.py` → min 1
  **Wynik 2026-05-29:** 1 — PASS

- [x] X-Actor-Email bez tokenu → 401: `python -m pytest tests/unit/api/dependencies/test_auth.py -q` → passed
  **Wynik 2026-05-29:** PASS (included in 1009 total)

- [x] Org-scoped endpoints mają auth boundary: `grep -rn "get_verified_actor" api/routers/ --include="*.py"` → min 5
  **Wynik 2026-05-29:** api_keys.py (3 endpoints), audit.py (3), runners.py (3), secrets.py (4) — PASS
  Weryfikacja: `python -m pytest tests/unit/api/routers/test_auth_boundary.py -q` → 10/10 passed

- [x] Org member RBAC sprawdza tenant boundary: `python -m pytest tests/unit/api/routers/test_orgs.py tests/unit/api/middleware/test_rbac.py -q` → passed
  **Wynik 2026-05-29:** 11 passed — PASS

---

## 2. Persistent State

- [x] Brak module-level dict stores: `grep -rn "^_[A-Z].*= {}" api/routers/ api/middleware/ --include="*.py"` → 0
  **Wynik 2026-05-29:** 0 — PASS

- [x] Org store używa DB: `grep -rn "_ORG_STORE" api/routers/orgs.py` → 0
  **Wynik 2026-05-29:** 0 — PASS

- [x] API keys używają DB: `grep -rn "_API_KEYS" api/routers/api_keys.py` → 0
  **Wynik 2026-05-29:** 0 — PASS

- [x] RBAC używa DB: `grep -rn "RoleStore._roles\|self._roles" api/middleware/rbac.py` → 0
  **Wynik 2026-05-29:** 0 — PASS

---

## 3. Secrets & Encryption

- [x] XOR encryption usunięte: `grep -rn "token_bytes.*zip\|key.hex()" storage/secrets/vault.py` → 0
  **Wynik 2026-05-29:** 0 — PASS

- [x] Fernet używany: `grep -rn "Fernet\|VAULT_ENCRYPTION_KEY" storage/secrets/vault.py` → min 2
  **Wynik 2026-05-29:** 4 — PASS

- [x] Secrets table istnieje w migracji: `grep -rn "secrets" storage/db/migrations/versions/` → min 1
  **Wynik 2026-05-29:** 20260529000000_add_secrets_table.py — PASS

- [x] VAULT_ENCRYPTION_KEY wymagany: `grep -rn "RuntimeError.*VAULT_ENCRYPTION_KEY" storage/secrets/vault.py` → min 1
  **Wynik 2026-05-29:** 1 — PASS

- [x] Secrets router async/await poprawny: `grep -rn "await vault\." api/routers/secrets.py` → min 4
  **Wynik 2026-05-29:** await na store, list_for_org, rotate, delete — PASS (naprawione w tym sprincie)

---

## 4. Audit Log

- [x] In-memory audit usunięte: `grep -rn "_AUDIT_EVENTS\|_AUDIT_EXPORTS" api/routers/audit.py` → 0
  **Wynik 2026-05-29:** 0 — PASS

- [x] Audit table istnieje w migracji: `grep -rn "audit_events" storage/db/migrations/versions/` → min 1
  **Wynik 2026-05-29:** 20260529010000_add_org_audit_events.py — PASS

- [x] Tenant scoping audit: `grep -rn "org_id" api/routers/audit.py` → min 2
  **Wynik 2026-05-29:** 16 — PASS

---

## 5. Invariants (z CLAUDE.md)

- [x] Proof-gate: `grep -rn "0.85" execution_plane/validator/` → min 1, bez bypasses
  **Wynik 2026-05-29:** 45 hits. Słowo "bypass" to nazwy klas podatności, nie obejścia progu — PASS

- [x] Auth-first: `grep -rn "_pause_with_error\|auth_fail\|expired_session" control_plane/orchestrator.py` → min 1
  **Wynik 2026-05-29:** 3 — PASS

- [x] Worker isolation — attack workers nie piszą Finding/ProofArtifact do DB:
  `grep -rn "db\.add.*Finding\|db\.add.*ProofArtifact" execution_plane/workers/ --include="*.py"` → 0
  **Wynik 2026-05-29:** 0 — PASS

- [x] Dedup before write: `grep -rn "fingerprint\|dedup" control_plane/finding_scorer.py` → min 1
  **Wynik 2026-05-29:** 60 — PASS

- [x] No credentials in logs: `grep -rn "CredentialStripper" api/middleware/logging.py` → min 1
  **Wynik 2026-05-29:** CredentialStripper globalny procesor structlog (logging.py:62) — PASS

- [x] Redaction at export: `grep -rn "redact" control_plane/reporting.py` → min 2
  **Wynik 2026-05-29:** 54 — PASS

---

## 6. Deploy

- [x] Production compose bez LocalStack: `grep -n "localstack\|AWS_ENDPOINT_URL" docker/docker-compose.prod.yml` → 0
  **Wynik 2026-05-29:** 0 — PASS

- [x] Non-root user: `grep -n "USER appuser" docker/Dockerfile.api` → min 1
  **Wynik 2026-05-29:** 1 — PASS

- [x] .env.example kompletny: `cat .env.example | grep -c "="` → min 8 zmiennych
  **Wynik 2026-05-29:** 12 — PASS

- [x] Postgres i Redis nie wystawione na hosta w prod:
  `grep -n "5432:5432\|6379:6379" docker/docker-compose.prod.yml` → 0
  **Wynik 2026-05-29:** 0 — PASS (naprawione w tym sprincie)

- [x] CI wymusza Python 3.12: `grep -rn "python-version: \"3.12\"" .github/workflows/ && cat .python-version` → 3.12
  **Wynik 2026-05-29:** `.python-version` + `.github/workflows/tests.yml` — PASS

- [x] Alembic fresh start: `python -m pytest tests/integration/test_alembic_fresh.py -v` → passed
  **Wynik 2026-05-29:** 1 passed. Używa `sys.executable -m alembic` dla pewności PYTHONPATH — PASS

---

## 7. Test Suite

- [x] Zero collection errors: `python -m pytest tests/ --collect-only -q 2>&1 | grep "ERROR"` → 0
  **Wynik 2026-05-29:** 0 errors — PASS

- [x] Full suite: `python -m pytest tests/ -q` → 0 failed
  **Wynik 2026-05-29:** **1013 passed, 0 failed, 5 warnings** — PASS

- [x] Auth boundary tests: `python -m pytest tests/unit/api/routers/test_auth_boundary.py -v` → 10/10 passed
  **Wynik 2026-05-29:** 10 passed — PASS

---

## 8. Security Anti-patterns

- [x] Brak hardcoded secrets: `grep -rn "password.*=.*['\"]proofscan\|secret.*=.*['\"]dev" control_plane/ api/ storage/ --include="*.py"` → 0
  **Wynik 2026-05-29:** 0 — PASS

- [x] Brak SQL string concat: `grep -rn "f\"SELECT\|f'SELECT\|\"SELECT.*{" control_plane/ api/ storage/ --include="*.py"` → 0
  **Wynik 2026-05-29:** 0 — PASS

- [x] Org-scoped endpoints używają VerifiedActor (nie path/body org_id):
  `grep -rn "actor\.org_id" api/routers/ --include="*.py"` → min 10
  **Wynik 2026-05-29:** api_keys (3), audit (3), runners (3), secrets (4) = 13 — PASS

- [x] Runner heartbeat wymaga runner tokenu:
  `python -m pytest tests/unit/api/routers/test_auth_boundary.py -k runner_heartbeat -q` → passed
  **Wynik 2026-05-29:** 3 passed — PASS

---

## Accepted Risks

1. **Validator write pattern** — Validator w execution_plane pisze RawProbe do DB i artefakty do S3. To celowy design: attack workers → Redis stream → validator (buffer processor) → DB/S3. Brak bezpośrednich zapisów Finding z attack workerów.

2. **Python 3.12 vs lokalne 3.14.5** — lokalny `.venv` nadal używa 3.14.5, ale repo ma `.python-version=3.12`, a `.github/workflows/tests.yml` wymusza Python 3.12 dla release verification.

---

## Gemini Invariants Check — wyniki (2026-05-29)

```
PASS: 1 — confidence_score >= 0.85 enforced (finding_scorer.py:171)
PASS: 2 — auth failure → _pause_with_error (auth_manager.py)
ACCEPTED: 3 — validator writes to DB/S3 as buffer processor (see Accepted Risk #1)
PASS: 4 — dedup fingerprint before db.add (finding_scorer.py)
PASS: 5 — CredentialStripper global structlog processor (logging.py:62)
PASS: 6 — EvidenceStore full data; redaction only in ReportingService
PASS: 7 — DEV_MODE gate; production requires Bearer token
PASS: 8 — Fernet encryption; key from env var
PASS: 9 — org_id from API key in DB, not request body
```

8/9 PASS, 1 ACCEPTED_RISK.

---

## SHIP / NO-SHIP

**Status: SHIP ✅**

**Data weryfikacji:** 2026-05-29

**Weryfikujący:** Claude (Orchestrator) + Gemini CLI invariants check + full test suite

**Uzasadnienie:**
- 1013 testów, 0 failed
- Auth boundary: 13 `actor.org_id` checks na 4 routerach, 10 auth boundary tests zielone
- Org member RBAC sprawdza `actor.org_id` względem path/header org context
- Runner heartbeat wymaga bearer tokenu runnera zgodnego z `token_hash`
- Secrets router: async/await naprawiony, vault._secrets usunięty
- Docker prod: postgres i redis nie wystawione na hosta
- Alembic test: sys.executable gwarantuje PYTHONPATH
- Wszystkie PROD_READINESS punkty PASS lub ACCEPTED_RISK z uzasadnieniem

**Naprawy wykonane w Sprint 80:**
1. `tests/integration/test_alembic_fresh.py` — `["alembic"...]` → `[sys.executable, "-m", "alembic"...]`
2. `tests/integration/test_alembic_fresh.py` — REQUIRED_TABLES `"org_runners"` → `"runners"`
3. `api/routers/secrets.py` — dodano `await` na wszystkich vault calls; usunięto `vault._secrets` (nie istnieje w DB-backed vault); dodano VerifiedActor auth boundary
4. `api/routers/api_keys.py` — dodano VerifiedActor auth boundary (3 endpointy)
5. `api/routers/audit.py` — dodano VerifiedActor auth boundary (3 endpointy)
6. `api/routers/runners.py` — dodano VerifiedActor; register_runner używa actor.org_id; deregister_runner sprawdza runner.org_id == actor.org_id
7. `docker/docker-compose.prod.yml` — usunięto port bindings 5432 i 6379 (postgres/redis nie wystawione na hosta)
8. `tests/unit/api/routers/test_auth_boundary.py` — 10 testów weryfikujących wrong org_id i runner heartbeat token boundary
9. `api/middleware/rbac.py` — `require_role()` sprawdza `actor.org_id` przeciw org context z path/header
10. `api/routers/runners.py` — heartbeat wymaga bearer tokenu runnera i porównuje hash w stałym czasie
11. `.python-version`, `.github/workflows/tests.yml` — release verification na Pythonie 3.12

**Zaakceptowane ryzyka:** Validator write pattern, lokalny Python 3.14.5 poza CI — opisano powyżej.
