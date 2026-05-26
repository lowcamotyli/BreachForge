## Sprint 59 - Multi-Lab Coverage Suite

**Goal:** Z jednego benchmarku przejsc na zestaw realistycznych labow, ktory mierzy coverage dla auth, API, GraphQL, business logic, race i discovery.

### Architektura - dokumenty referencyjne

```bash
DAD_PROMPT="cd /mnt/d/BreachForge && Read docs/process/incident-to-corpus.md and docs/architecture/attack-engine.md. Propose lab taxonomy for API-heavy SaaS security benchmarks. Bullets. Max 30 lines." bash ~/.claude/scripts/dad-exec.sh
```

### Workstream A - Lab taxonomy

| ID | Zadanie | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| A1 | Lab manifest schema: lab_id, attack_classes, identities, expected_surface, expected_findings | `tests/benchmark_lab/`, `scripts/benchmark_lab.py` | codex-main | schema tests | wiele labow w jednym runnerze |
| A2 | API SaaS lab v2: OpenAPI/spec import + hidden admin endpoints + multi-tenant flows | `tests/benchmark_lab/labs/api_saas/` | codex-dad | lab smoke | realistyczna API powierzchnia |
| A3 | SPA/HAR lab: JS endpoint discovery, session import, public/private baseline | `tests/benchmark_lab/labs/spa_har/` | codex-dad | lab smoke | discovery mierzone niezaleznie od attack TP |

### Workstream B - Specialized labs

| ID | Zadanie | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| B1 | GraphQL lab: introspection, batch, depth, field-level auth | `tests/benchmark_lab/labs/graphql/` | codex-main | lab + benchmark | GraphQL coverage osobno raportowane |
| B2 | Business/race lab: coupons, idempotency, inventory, approval workflow | `tests/benchmark_lab/labs/business_race/` | codex-main | lab + benchmark | stateful bugs maja ground truth |
| B3 | Auth/OAuth lab: expired token, logout reuse, state CSRF, redirect manipulation | `tests/benchmark_lab/labs/auth_oauth/` | codex-dad | lab + benchmark | auth robustness mierzone powtarzalnie |

### Workstream C - Coverage reporting

| ID | Zadanie | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| C1 | Metrics per lab i aggregate: coverage_by_attack_class, discovery_coverage, FP/FN | `scripts/benchmark_lab.py` | codex-main | metrics tests | raport wskazuje konkretne slabsze klasy |
| C2 | Golden snapshots per lab | `tests/benchmark_lab/golden/` | codex-main | golden tests | regresje widoczne per lab |
| C3 | Nightly command: all labs, fail budgets, markdown summary | `scripts/benchmark_lab.py`, `docs/BENCHMARK_README.md` | codex-main | smoke | jedna komenda do porownania jakosci |

### Guardrails

- Laby sa deterministic i bez zewnetrznych sekretow.
- Lab nie moze wymagac internetu.
- Nie mieszac discovery coverage z confirmed finding coverage.

### Weryfikacja

```bash
python -m pytest tests/benchmark_lab/ -q
python scripts/benchmark_lab.py --full --lab all --output .runtime/benchmark-all.json
python -m pytest tests/integration/test_benchmark_smoke.py -q
python -m pytest tests/unit/ -q
```

### Global acceptance criteria

- [ ] Runner obsluguje wiele labow.
- [ ] Raport pokazuje coverage per attack class.
- [ ] Discovery coverage jest mierzony osobno.
- [ ] Nightly benchmark ma golden baseline.

### Podzial pracy - codex-dad

A2, A3 i B3 ida do **codex-dad** jako lab implementation packages. A1, B1, B2 i C robi **codex-main**.
