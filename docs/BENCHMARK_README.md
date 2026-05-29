# ProofScan Benchmark Labs

## Quick Start
```bash
# Run legacy lab (quick mock)
python scripts/benchmark_lab.py --quick

# Run legacy lab (full HTTP scan)
python scripts/benchmark_lab.py --full

# Override discovery gate threshold (default 0.80 / 80%)
python scripts/benchmark_lab.py --full --discovery-threshold 0.90

# List all discovered labs
python scripts/benchmark_lab.py --quick --lab all

# Run all labs nightly summary
python scripts/benchmark_lab.py --quick --all-labs --summary-output .runtime/nightly-summary.md
```

## Lab Corpus
| lab_id | attack_classes | vuln_count | OWASP API Top 10 mapping |
|---|---|---:|---|
| api_saas | BOLA, BFLA, TENANT_ISOLATION, MASS_ASSIGNMENT, HIDDEN_ENDPOINT | 5 | BOLA->API1, BFLA->API5, TENANT_ISOLATION->API1, MASS_ASSIGNMENT->API3, HIDDEN_ENDPOINT->API9 |
| graphql | GRAPHQL_INTROSPECTION, GRAPHQL_BATCH, GRAPHQL_DEPTH, GRAPHQL_FIELD_AUTH | 4 | GRAPHQL_INTROSPECTION->API8, GRAPHQL_BATCH->API4, GRAPHQL_DEPTH->API4, GRAPHQL_FIELD_AUTH->API1 |
| spa_har | BFLA, HIDDEN_ENDPOINT, DISCOVERY | 3 | BFLA->API5, HIDDEN_ENDPOINT->API9, DISCOVERY->API9 |
| business_race | RACE_CONDITION, IDEMPOTENCY, NEGATIVE_QUANTITY, APPROVAL_WORKFLOW_SKIP, STATE_INCONSISTENCY | 5 | RACE_CONDITION->API4, IDEMPOTENCY->API4, NEGATIVE_QUANTITY->API3, APPROVAL_WORKFLOW_SKIP->API6, STATE_INCONSISTENCY->API4 |
| auth_oauth | EXPIRED_TOKEN_REUSE, LOGOUT_REUSE, OAUTH_STATE_CSRF, REDIRECT_MANIPULATION | 4 | EXPIRED_TOKEN_REUSE->API2, LOGOUT_REUSE->API2, OAUTH_STATE_CSRF->API2, REDIRECT_MANIPULATION->API2 |

## Running the Benchmark
```bash
# Quick legacy benchmark
python scripts/benchmark_lab.py --quick

# Quick all-labs benchmark
python scripts/benchmark_lab.py --quick --lab all

# Quick per-lab benchmark
python scripts/benchmark_lab.py --quick --lab api_saas

# Full legacy benchmark
python scripts/benchmark_lab.py --full

# Full per-lab benchmark
python scripts/benchmark_lab.py --full --lab api_saas

# Full all-labs benchmark
python scripts/benchmark_lab.py --full --lab all --min-coverage 0.80 --max-fp 0
```

## Metrics
Each lab reports: discovery_coverage_pct, discovery_blind_spots, coverage, tp, fp, fn, coverage_by_attack_class, ground_truth_count.
Discovery coverage gates before finding coverage in full mode. The threshold defaults to 0.80 and can be set with `--discovery-threshold` or `DISCOVERY_COVERAGE_THRESHOLD`.

## Guardrails
- All labs are deterministic and offline (no external HTTP)
- Labs do not require internet access
- Discovery coverage is tracked separately from confirmed finding coverage

## Release Scorecard
| Dimension | Metric | Gate | How to check |
|---|---|---|---|
| Effectiveness | TP/total >= 0.80, FP == 0 | CI smoke Gate 3 + Nightly Stage 2 | benchmark_lab.py --full --min-coverage 0.80 --max-fp 0 |
| Reliability | Worker crash test PASS, idempotent finalize PASS | CI smoke Gate 1 | pytest tests/unit/execution_plane/test_rq_failure.py tests/integration/test_worker_crash.py |
| Safety | No unsafe_block anomaly >10%, P5 invariants pass | Nightly Stage 4 | nightly_gates.sh Stage 4 |
| Blind spots | FN report items listed | Nightly Stage 2 | benchmark_lab.py --full (fn_report in JSON) |

## CI/Nightly Quick Reference
```bash
# CI smoke: all gates
bash scripts/ci_smoke.sh

# CI smoke Gate 1: unit tests
python -m pytest tests/unit/ -q --tb=short

# CI smoke Gate 2: quick scale
python scripts/benchmark_lab.py --scale 100 --output /tmp/smoke-scale.json

# CI smoke Gate 3: selected lab
python scripts/benchmark_lab.py --full --min-coverage 0.80 --max-fp 0

# Nightly: all stages
bash scripts/nightly_gates.sh

# Nightly Stage 1: all tests
python -m pytest tests/ -q --tb=short

# Nightly Stage 2: all full labs
python scripts/benchmark_lab.py --full --lab all --min-coverage 0.80 --max-fp 0

# Nightly Stage 3: scale benchmark
python scripts/benchmark_lab.py --scale 500 --output .runtime/nightly-scale.json

# Nightly Stage 4: safety anomaly check
python -c 'import json; p=json.load(open(".runtime/nightly-scale.json", encoding="utf-8")); raise SystemExit(1 if p["requests_blocked"] / p["requests_total"] > 0.1 else 0)'
```
