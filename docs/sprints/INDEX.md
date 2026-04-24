# ProofScan v1.0 - Sprint Plan

## Jak uzywac tego dokumentu

1. Przed kazdym sprintem: odczytaj wskazany plik `docs/architecture/` przez dad - hook blokuje bezposredni Read.
2. Dispatch rownoleglych taskow z `run_in_background: true`.
3. Weryfikacja: `python -m pytest tests/unit/ -q` po kazdym sprincie.
4. Ship gate: Claude sprawdza proof-gate, worker isolation, brak credentials w logach - przed kazdym `alembic upgrade head` lub merge wrazliwego kodu.

## Krytyczna sciezka

```
S1 (Infra+Schema) -> S2 (AuthManager) -> S3 (Crawler) ----->
                           \-> S4 (Orchestrator) -----------> S5 (Planner) -> S6 (Validator) -> S7 (Reporting)
                                                           \-> S8 (Remaining rules) --------------->
                                                                                     S9 (Hardening)
                                                                                         |
                                                            S10 (Runtime Contracts/FSM) -> S11 (Planner/Validator Contract)
                                                                                         |
                                                            S12 (Credential/Evidence Security) -> S13 (Worker Guardrails)
                                                                                         |
                                                            S14 (Auth Coverage + Storage Contract + Test Corpus)
                                                                                         |
                                                            S15 (Security Attack Coverage Matrix)
                                                                                         |
                                                            S16 (Attacker Intelligence System)
                                                                                         |
                                                            S17 (Secret Intelligence Core)
                                                                                         |
                                                            S18 (Safe Blast Radius Mapper) -> S19 (Privilege Fingerprint)
                                                                                         |
                                                            S20 (Secret Leak Source) -> S21 (Secret Lifecycle)
                                                                                         |
                                                            S22 (Secret Correlation) -> S23 (Secret Reporting Pack)
```

## Sprinty

| Sprint | Cel | Plik |
|---|---|---|
| Sprint 1 | Docker Compose z PostgreSQL + Redis + LocalStack S3; wszystkie SQLAlchemy models; Alembic setup; FastAPI skeleton z `/health`. | [sprint-01-foundation.md](./sprint-01-foundation.md) |
| Sprint 2 | AuthManager z Playwright login flows, session cookie escape hatch, scan creation endpoint. | [sprint-02-auth.md](./sprint-02-auth.md) |
| Sprint 3 | CrawlerReconEngine mapuje powierzchnie ataku przez Playwright (XHR interception + link extraction), produkuje AssetMap. | [sprint-03-crawler.md](./sprint-03-crawler.md) |
| Sprint 4 | ScanOrchestrator FSM; rq AttackWorker pool; WorkerSupervisor z crash detection i automatic restart. | [sprint-04-orchestrator-workers.md](./sprint-04-orchestrator-workers.md) |
| Sprint 5 | `AttackRule` ABC; `BolaBidirectional` + `TenantIsolation` rules; `AttackPlanner` z priority scoring. | [sprint-05-planner-bola-tenant.md](./sprint-05-planner-bola-tenant.md) |
| Sprint 6 | `ExploitValidator` z differential probing dla BOLA/IDOR; S3 `EvidenceStore`; proof-gate 0.85 enforced. | [sprint-06-validator-evidence.md](./sprint-06-validator-evidence.md) |
| Sprint 7 | Structural dedup przed zapisem; JSON + Markdown report; redakcja credentials wylacznie przy eksporcie. | [sprint-07-finding-reporting.md](./sprint-07-finding-reporting.md) |
| Sprint 8 | 5 pozostalych klas ataku + validator strategies (auth_bypass, privilege_escalation, sensitive_exposure, workflow_abuse, injection). | [sprint-08-remaining-rules.md](./sprint-08-remaining-rules.md) |
| Sprint 9 | Rate limiter (Redis token bucket); KMS envelope encryption; structlog credential stripping; Docker production images; ECS task definitions. | [sprint-09-hardening.md](./sprint-09-hardening.md) |
| Sprint 10 | Krytyczne kontrakty runtime: dzialajace entrypointy RQ, spojny FSM/statusy, poprawne semantics pause/auth-fail. | [sprint-10-runtime-contracts-fsm.md](./sprint-10-runtime-contracts-fsm.md) |
| Sprint 11 | Kontrakt planner/validator/scorer: pelna rejestracja strategii i spojne attack_class end-to-end. | [sprint-11-planner-validator-contract.md](./sprint-11-planner-validator-contract.md) |
| Sprint 12 | Security data path: brak plaintext credentials, purge po skanie, EvidenceStore write unredacted, redaction only at export. | [sprint-12-credential-evidence-security.md](./sprint-12-credential-evidence-security.md) |
| Sprint 13 | Worker guardrails: scope enforcement per domain, wlasciwy domain+worker limiter, production-safe enforcement. | [sprint-13-worker-guardrails-scope.md](./sprint-13-worker-guardrails-scope.md) |
| Sprint 14 | Domkniecie v1: `/auth/verify`, refresh/TOTP input, storage contract cleanup, testy integration + corpus. | [sprint-14-auth-storage-tests.md](./sprint-14-auth-storage-tests.md) |
| Sprint 15 | Pelna matryca wdrozeniowa 10 typow atakow (task-by-task): rules, worker path, validator, scorer, testy integration i corpus. | [sprint-15-security-attack-coverage.md](./sprint-15-security-attack-coverage.md) |
| Sprint 16 | Pelny plan 10 capability "top attacker system" + integracja Codex CLI jako advisory analyst podczas wykonywania atakow. | [sprint-16-attacker-intelligence-system.md](./sprint-16-attacker-intelligence-system.md) |
| Sprint 17 | Secret Intelligence Core: klasyfikacja sekretow, JWT metadata, TTL hints i redaction guarantees. | [sprint-17-secret-intelligence-core.md](./sprint-17-secret-intelligence-core.md) |
| Sprint 18 | Safe Blast Radius Mapper: bounded read-only replay na wybranych endpointach i status matrix. | [sprint-18-safe-blast-radius-mapper.md](./sprint-18-safe-blast-radius-mapper.md) |
| Sprint 19 | Privilege Fingerprint: observed vs inferred access level dla aktywnego sekretu. | [sprint-19-privilege-fingerprint.md](./sprint-19-privilege-fingerprint.md) |
| Sprint 20 | Secret Leak Source Diagnosis: klasyfikacja zrodla wycieku i remediation per source type. | [sprint-20-secret-leak-source-diagnosis.md](./sprint-20-secret-leak-source-diagnosis.md) |
| Sprint 21 | Secret Lifecycle Assessment: expiration, revocation posture, active-during-scan i TTL guidance. | [sprint-21-secret-lifecycle-assessment.md](./sprint-21-secret-lifecycle-assessment.md) |
| Sprint 22 | Secret Correlation & Severity Upgrade: korelacja active replay, blast radius, CORS/cache i severity factors. | [sprint-22-secret-correlation-severity.md](./sprint-22-secret-correlation-severity.md) |
| Sprint 23 | Secret Exposure Reporting & Evidence Pack: finalny Markdown/JSON raport i corpus secret exposure. | [sprint-23-secret-exposure-reporting-pack.md](./sprint-23-secret-exposure-reporting-pack.md) |

