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
                                                                                         |
                                                            S24 (Attack Playbook DSL) -> S25 (Hypothesis Engine)
                                                                                         |
                                                            S26 (Multi-Identity Differential Lab)
                                                                                         |
                                                            S27 (Behavioral Attack Scenarios) -> S28 (Attack Chain Scoring & Corpus)
                                                                                         |
                    S29 (JWT Attack Suite) -> S30 (SSRF) -> S31 (Mass Assignment/BOPLA) -> S32 (BFLA)
                                                                                         |
                    S33 (GraphQL Attacks) -> S34 (OAuth Exploitation) -> S35 (Advanced Injection)
                                                                                         |
                    S36 (XXE & Deserialization) -> S37 (HTTP-Level Attacks) -> S38 (CSRF & Cookie)
                                                                                         |
                    S39 (Business Logic Advanced) -> S40 (Shadow API/Inventory) -> S41 (Security Headers/TLS)
                                                                                         |
                    S42 (Advanced Race/Concurrency) -> S43 (OOB Callback Infrastructure)
                                                                                         |
                                                            S44 (Pre-Auth Recon Pack: HAR/OpenAPI/session import) -> S45 (Unauth Scan Mode)
                                                                                         |
                    S46 (Unauth Mode Core: chirurgiczne zmiany dispatcher/worker/planner) -> S47 (Runtime Wiring)
                                                                                         |
                    S48 (Finding Metadata Persistence) -> S49 (Session Import Hardening) -> S50 (Multi-Identity Matrix)
                                                                                         |
                    S51 (State Model Differential) -> S52 (Adaptive Replanning) -> S53 (Business Logic Pack)
                                                                                         |
                    S54 (Race Engine v2) -> S55 (Benchmark Lab) -> S56 (Operator Safety)
                                                                                         |
                    S57 (Full Benchmark Scan Loop) -> S58 (Benchmark Detection Lift) -> S59 (Multi-Lab Coverage)
                                                                                         |
                    S60 (Operator-Grade Auth/Discovery) -> S61 (Autonomous Stateful Loop) -> S62 (Scale/Reliability Gates)
                                                                                         |
                    S63 (Provider Sandbox/HexStrike) -> S64 (Competitive Benchmark Harness) -> S65 (Enterprise Auth)
                                                                                         |
                    S66 (Full Multi-Lab Live Corpus) -> S67 (Developer Evidence Workflow) -> S68 (Safe Active Policy)
                                                                                         |
                    S69 (SaaS Control Plane/Private Runners) -> S70 (CI/CD Gates) -> S71 (Inventory/Ownership Graph)
                                                                                         |
                    S72 (Buyer-Grade Reporting) -> S73 (Public Benchmark Trust Program)
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
| Sprint 24 | Attack Playbook DSL: kontrolowane scenariusze preconditions -> probes -> validators -> evidence -> safety budget. | [sprint-24-attack-playbook-dsl.md](./sprint-24-attack-playbook-dsl.md) |
| Sprint 25 | Hypothesis Engine: generowanie i ranking hipotez ataku z AssetMap, signals i runtime feedback. | [sprint-25-hypothesis-engine.md](./sprint-25-hypothesis-engine.md) |
| Sprint 26 | Multi-Identity Differential Lab: porownania anon/user/admin/tenantA/tenantB dla BOLA, privilege i tenant isolation. | [sprint-26-multi-identity-differential-lab.md](./sprint-26-multi-identity-differential-lab.md) |
| Sprint 27 | Behavioral Attack Scenarios: step skipping, replay, race, cache/auth drift i forced browsing z guardrails. | [sprint-27-behavioral-attack-scenarios.md](./sprint-27-behavioral-attack-scenarios.md) |
| Sprint 28 | Attack Chain Scoring & Corpus: scoring, dedup, raportowanie i corpus dla calych lancuchow ataku. | [sprint-28-attack-chain-scoring-corpus.md](./sprint-28-attack-chain-scoring-corpus.md) |
| Sprint 29 | JWT Attack Suite: alg:none bypass, RS256/HS256 confusion, kid injection, claim escalation, expired token acceptance. | [sprint-29-jwt-attack-suite.md](./sprint-29-jwt-attack-suite.md) |
| Sprint 30 | SSRF: cloud metadata probes, internal service discovery, protocol SSRF, blind SSRF (low confidence bez OOB). | [sprint-30-ssrf.md](./sprint-30-ssrf.md) |
| Sprint 31 | Mass Assignment & BOPLA (API3): hidden privilege field injection, excessive data exposure, property-level auth diff. | [sprint-31-mass-assignment-bopla.md](./sprint-31-mass-assignment-bopla.md) |
| Sprint 32 | BFLA (API5): admin function access przez non-admin identity, HTTP verb escalation, cross-role function probing. | [sprint-32-bfla.md](./sprint-32-bfla.md) |
| Sprint 33 | GraphQL Attack Surface: introspection w produkcji, batch amplification, query depth, field suggestion, alias bypass. | [sprint-33-graphql-attacks.md](./sprint-33-graphql-attacks.md) |
| Sprint 34 | OAuth 2.0 Exploitation: redirect_uri manipulation, state CSRF, token reuse post-logout, client credential confusion. | [sprint-34-oauth-exploitation.md](./sprint-34-oauth-exploitation.md) |
| Sprint 35 | Advanced Injection: NoSQL ($gt/$ne/$regex), SSTI (Jinja2/Twig/ERB), LDAP, XPath, HTTP header injection. | [sprint-35-advanced-injection.md](./sprint-35-advanced-injection.md) |
| Sprint 36 | XXE & Deserialization: XML external entity (classic, error, blind), Java/Python/YAML deserialization probes. | [sprint-36-xxe-deserialization.md](./sprint-36-xxe-deserialization.md) |
| Sprint 37 | HTTP-Level Attacks: request smuggling (CL.TE/TE.CL), web cache deception, cache poisoning, HPP, method override. | [sprint-37-http-level-attacks.md](./sprint-37-http-level-attacks.md) |
| Sprint 38 | CSRF & Cookie Analysis: CSRF token absence/weakness, double-submit bypass, HttpOnly/Secure/SameSite flags audit. | [sprint-38-csrf-cookie-analysis.md](./sprint-38-csrf-cookie-analysis.md) |
| Sprint 39 | Business Logic Advanced: negative values, integer overflow, price manipulation, timing oracle, inventory reservation. | [sprint-39-business-logic-advanced.md](./sprint-39-business-logic-advanced.md) |
| Sprint 40 | Shadow API & Inventory (API9): deprecated versions, admin endpoint fuzz, API docs exposure, JS endpoint mining. | [sprint-40-shadow-api-inventory.md](./sprint-40-shadow-api-inventory.md) |
| Sprint 41 | Security Headers & TLS: HSTS/CSP/X-Frame-Options audit, CORS deep analysis (null origin, wildcard+credentials), TLS 1.0/1.1. | [sprint-41-security-headers-tls.md](./sprint-41-security-headers-tls.md) |
| Sprint 42 | Advanced Race Conditions: limit override, double-spend, idempotency bypass, distributed lock evasion. | [sprint-42-advanced-race-concurrency.md](./sprint-42-advanced-race-concurrency.md) |
| Sprint 43 | OOB Callback Infrastructure: HTTP listener + DNS monitor dla blind SSRF/XXE — podniesie confidence z 0.65 do 0.92. | [sprint-43-oob-callback-infrastructure.md](./sprint-43-oob-callback-infrastructure.md) |
| Sprint 44 | Pre-Auth Recon Pack: browser session import (bez hasła), HAR import, OpenAPI/Postman/Insomnia import, JS sourcemap mining, public baseline differential, secret-to-impact bez credentials. | [sprint-44-preauth-recon-pack.md](./sprint-44-preauth-recon-pack.md) |
| Sprint 45 | Unauth Scan Mode: `unauth_mode: true` flag, requires_auth matrix dla wszystkich rules, wordlist-guided forced browsing, unauth injection na publicznych formach, JS secret scanner. | [sprint-45-unauth-scan-mode.md](./sprint-45-unauth-scan-mode.md) |
| Sprint 46 | Unauth Mode Core Integration: chirurgiczne zmiany dispatcher.py (L121), attack_worker.py (L166-169), 8 rules z requires_auth=False, anonymous identity selector, 5 playbookow unauth-native. | [sprint-46-unauth-mode-core.md](./sprint-46-unauth-mode-core.md) |
| Sprint 47 | Runtime Wiring Stabilization: podpiecie recon routera, packaging execution_plane, lazy DB init, unauth scan API lifecycle i crawler bez AuthContext. | [sprint-47-runtime-wiring-stabilization.md](./sprint-47-runtime-wiring-stabilization.md) |
| Sprint 48 | Finding Metadata Persistence: trwale metadata findingow, Alembic migration, scorer/reporting consistency i reload regression. | [sprint-48-finding-metadata-persistence.md](./sprint-48-finding-metadata-persistence.md) |
| Sprint 49 | Session Import Hardening: SSRF guardrails, headless/timeout limits, TTL session store i audit bez sekretow. | [sprint-49-session-import-hardening.md](./sprint-49-session-import-hardening.md) |
| Sprint 50 | Multi-Identity Auth Matrix: realne sesje user/admin/tenant, identity-aware worker, planner i validator differential. | [sprint-50-multi-identity-auth-matrix.md](./sprint-50-multi-identity-auth-matrix.md) |
| Sprint 51 | State Model And Differential Engine: formalny state snapshot, read-after-write verifier i structural comparators. | [sprint-51-state-model-differential-engine.md](./sprint-51-state-model-differential-engine.md) |
| Sprint 52 | Adaptive Replanning v1: runtime outcome contract, feedback queue, bounded follow-up tasks i trzy adaptive scenarios. | [sprint-52-adaptive-replanning-v1.md](./sprint-52-adaptive-replanning-v1.md) |
| Sprint 53 | Business Logic Attack Pack: coupon/negative/price/inventory/approval abuse z state-proof guardrails. | [sprint-53-business-logic-attack-pack.md](./sprint-53-business-logic-attack-pack.md) |
| Sprint 54 | Race And Concurrency Engine v2: barrier start, race evidence grouping, rate-limit integration i final state reconciliation. | [sprint-54-race-concurrency-engine-v2.md](./sprint-54-race-concurrency-engine-v2.md) |
| Sprint 55 | Realistic Benchmark Lab: vulnerable SaaS lab, ground truth manifest, benchmark runner i metrics TP/FP/FN. | [sprint-55-realistic-benchmark-lab.md](./sprint-55-realistic-benchmark-lab.md) |
| Sprint 56 | Operator Safety And Auditability: formal scan policy, kill switch, immutable audit log i transparent reporting. | [sprint-56-operator-safety-auditability.md](./sprint-56-operator-safety-auditability.md) |
| Sprint 57 | Full Benchmark Scan Loop: `--full` uruchamia realny lokalny scan, zbiera findings i liczy TP/FP/FN bez placeholdera. | [sprint-57-full-benchmark-scan-loop.md](./sprint-57-full-benchmark-scan-loop.md) |
| Sprint 58 | Benchmark Detection Lift: podniesienie labu z 0/7 do minimum 5/7 TP przy 0 FP i proof artifacts. | [sprint-58-benchmark-detection-lift.md](./sprint-58-benchmark-detection-lift.md) |
| Sprint 59 | Multi-Lab Coverage Suite: wiele realistycznych labow i coverage per attack class/discovery. | [sprint-59-multi-lab-coverage-suite.md](./sprint-59-multi-lab-coverage-suite.md) |
| Sprint 60 | Operator Grade Auth And Discovery: auth reliability, discovery completeness i jawne blind spots. | [sprint-60-operator-grade-auth-discovery.md](./sprint-60-operator-grade-auth-discovery.md) |
| Sprint 61 | Autonomous Stateful Attack Loop: bounded replanning, stateful proof paths i adaptive benchmark scenarios. | [sprint-61-autonomous-stateful-attack-loop.md](./sprint-61-autonomous-stateful-attack-loop.md) |
| Sprint 62 | Scale Reliability And Quality Gates: duza powierzchnia, failure injection, evidence consistency i release scorecard. | [sprint-62-scale-reliability-quality-gates.md](./sprint-62-scale-reliability-quality-gates.md) |
| Sprint 63 | Execution Provider Sandbox And HexStrike Adapter: HexStrike i toolchain jako sandboxed providers, nie zrodlo findingow. | [sprint-63-execution-provider-sandbox-hexstrike-adapter.md](./sprint-63-execution-provider-sandbox-hexstrike-adapter.md) |
| Sprint 64 | Competitive Scanner Benchmark Harness: porownanie native/HexStrike/ZAP/Nuclei/importow przez TP/FP/FN, proof depth i blind spots. | [sprint-64-competitive-scanner-benchmark-harness.md](./sprint-64-competitive-scanner-benchmark-harness.md) |
| Sprint 65 | Enterprise Auth Recording And Identity Reliability: session recording/import, identity matrix health i auth preflight. | [sprint-65-enterprise-auth-recording-identity-reliability.md](./sprint-65-enterprise-auth-recording-identity-reliability.md) |
| Sprint 66 | Full Multi-Lab Live Corpus v1: wszystkie laby dzialaja w `--full`, bez quick-only placeholderow. | [sprint-66-full-multi-lab-live-corpus-v1.md](./sprint-66-full-multi-lab-live-corpus-v1.md) |
| Sprint 67 | Developer Evidence And Remediation Workflow: replay bundles, owner mapping, GitHub/Jira handoff i suppression lifecycle. | [sprint-67-developer-evidence-remediation-workflow.md](./sprint-67-developer-evidence-remediation-workflow.md) |
| Sprint 68 | Safe Active Testing Policy Engine: formalna polityka scope/destrukcyjnosci, rollback-safe state probes, kill switch i authorization pack. | [sprint-68-safe-active-testing-policy-engine.md](./sprint-68-safe-active-testing-policy-engine.md) |
| Sprint 69 | SaaS Control Plane And Private Runners: org/project tenancy, RBAC, private runner protocol, secrets vault i telemetry. | [sprint-69-saas-control-plane-private-runners.md](./sprint-69-saas-control-plane-private-runners.md) |
| Sprint 70 | CI/CD And PR Quality Gates: CLI, GitHub/GitLab/Jenkins, diff-aware scans i deterministic gates. | [sprint-70-ci-cd-pr-quality-gates.md](./sprint-70-ci-cd-pr-quality-gates.md) |
| Sprint 71 | API Inventory Code-To-Runtime Ownership Graph: inventory z runtime/spec/HAR/JS/code, owner graph i coverage truth views. | [sprint-71-api-inventory-code-to-runtime-ownership-graph.md](./sprint-71-api-inventory-code-to-runtime-ownership-graph.md) |
| Sprint 72 | Buyer Grade Reporting Compliance And Trust Pack: executive/developer/auditor reports, standards mapping i signed evidence. | [sprint-72-buyer-grade-reporting-compliance-trust-pack.md](./sprint-72-buyer-grade-reporting-compliance-trust-pack.md) |
| Sprint 73 | Public Benchmark Trust Program: publiczny reprodukowalny corpus, anti-gaming mode, scorecard i claims policy. | [sprint-73-public-benchmark-trust-program.md](./sprint-73-public-benchmark-trust-program.md) |

---

## Production Hardening Track (S74–S80)

**Zamrożenie feature sprintów.** Sprinty 57–73 pozostają w kolejce jako `frozen_feature_queue`.
Każdy z poniższych sprintów jest blokerem release. Cel: usunąć atrapy, nie dodać funkcje.

| Sprint | Cel | Plik |
|---|---|---|
| Sprint 74 | Persistent State: podłączenie `orgs`, `api_keys`, `org_members`, `runners` do istniejącego schematu DB (migracja 20260528100000 już istnieje, kod jej nie używa). Usuwa 4 in-memory stores. | [sprint-74-persistent-state-db-wiring.md](./sprint-74-persistent-state-db-wiring.md) |
| Sprint 75 | Real Auth: zastąpienie `X-Actor-Email` header trust realną weryfikacją `Authorization: Bearer <key>` przeciwko `api_keys` w DB. `VerifiedActor` zamiast fałszowalnego headera. | [sprint-75-real-auth-api-key-verification.md](./sprint-75-real-auth-api-key-verification.md) |
| Sprint 76 | SecretsVault Real Encryption: zastąpienie XOR fake-encryption Fernetem (AES-128-CBC+HMAC) z `VAULT_ENCRYPTION_KEY` env var + persystencja vault w tabeli `secrets`. | [sprint-76-secrets-vault-real-encryption.md](./sprint-76-secrets-vault-real-encryption.md) |
| Sprint 77 | Audit Log Persistence: zastąpienie `_AUDIT_EVENTS: list` (in-memory) tabelą `audit_events` w DB z tenant scoping i append-only enforcement. | [sprint-77-audit-log-persistence.md](./sprint-77-audit-log-persistence.md) |
| Sprint 78 | Production Docker Config: `docker-compose.prod.yml` bez LocalStack, non-root Dockerfile, `.env.example`, weryfikacja `alembic upgrade head` od pustej DB. | [sprint-78-production-docker-config.md](./sprint-78-production-docker-config.md) |
| Sprint 79 | Test Suite Green: naprawa 3 broken collection errors, integration test pełnego scan lifecycle, tenant isolation test. Cel: `python -m pytest tests/ -q` → 0 errors/failures. | [sprint-79-test-suite-green-integration.md](./sprint-79-test-suite-green-integration.md) |
| Sprint 80 | PROD_READINESS.md + Release Gate: formalna checklista blokcyjna (26 poleceń weryfikacyjnych), Gemini invariants sweep (9 invariantów), decyzja SHIP/NO-SHIP. | [sprint-80-prod-readiness-release-gate.md](./sprint-80-prod-readiness-release-gate.md) |

---

## Unauth Coverage Matrix (po Sprint 46)

| Klasa ataku | Bez kredencjali | Wymaga sesji | Najlepszy input unauth |
|---|---|---|---|
| misconfiguration | **100%** | nie | crawler / HAR |
| security_headers | **100%** | nie | 1 GET request |
| sensitive_exposure | **90%** | nie | crawler / JS mining |
| shadow_api / api_inventory | **90%** | nie | JS + robots.txt + wordlist |
| rate_limit_abuse | **70%** | nie (public endpoints) | path-hints |
| graphql_introspection | **95%** | nie | endpoint discovery |
| injection (public forms) | **50%** | nie | crawler + AssetMap |
| workflow_abuse | **40%** | czesc flow wymaga sesji | HAR / OpenAPI |
| race_conditions | **60%** | nie (public endpoints) | path-hints |
| bola / idor | **20%** | sesja dla baseline | HAR cookies |
| tenant_isolation | **15%** | potrzebny kontekst | HAR session |
| auth_bypass | **10%** | wymaga auth baseline | — |
| privilege_escalation | **10%** | wymaga multi-identity | — |
| jwt_attack | **5%** | wymaga tokenu | JS leak / HAR |

**Droga do 80% coverage bez credentials:** Sprint 44 (HAR/OpenAPI input) + Sprint 46 (unauth mode core).
