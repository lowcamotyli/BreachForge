# Corpus Contribution Guide

This guide defines how to add public benchmark corpus material under `tests/benchmark_lab/`.
Every contribution must be reproducible, deterministic, and tied to explicit ground truth.

## 1. Adding a New Lab

A lab lives under:

```text
tests/benchmark_lab/labs/{lab_id}/
```

Use a short snake_case `lab_id` such as `api_saas`, `graphql`, `business_race`, `auth_oauth`, or `spa_har`.
The directory must contain:

```text
tests/benchmark_lab/labs/{lab_id}/
├── __init__.py
├── manifest.json
├── ground_truth.json
├── lab_app.py
└── test_lab_smoke.py
```

`manifest.json` is the public corpus contract for the lab.
It must include these fields:

```json
{
  "lab_id": "api_saas",
  "lab_version": "1.0.0",
  "attack_classes": ["BOLA", "BFLA", "TENANT_ISOLATION", "MASS_ASSIGNMENT", "HIDDEN_ENDPOINT"],
  "identities": [
    {"username": "alice", "role": "user", "tenant": "tenant_a"},
    {"username": "bob", "role": "admin", "tenant": "tenant_a"},
    {"username": "carol", "role": "user", "tenant": "tenant_b"}
  ],
  "expected_surface": [
    "/api/v1/resources/{resource_id}",
    "/api/v1/admin/bulk-export",
    "/api/v1/internal/debug",
    "/api/v1/workspaces/{workspace_id}/data",
    "/api/v1/users/me"
  ],
  "expected_endpoints": [
    "/api/v1/resources/{resource_id}",
    "/api/v1/admin/bulk-export",
    "/api/v1/internal/debug",
    "/api/v1/workspaces/{workspace_id}/data",
    "/api/v1/users/me"
  ],
  "vulnerabilities": [
    {
      "id": "as-vuln-001",
      "type": "BOLA",
      "endpoint": "/api/v1/resources/{resource_id}",
      "method": "GET",
      "severity": "HIGH",
      "description": "Resource accessible without ownership check"
    }
  ],
  "discovery_surface": [
    "/api/v1/openapi-spec",
    "/api/v1/internal/debug"
  ]
}
```

`ground_truth.json` must use the same lab identifiers, endpoint templates, attack class names, and vulnerability IDs as `manifest.json`.
The benchmark loader reads the schema represented by `tests/benchmark_lab/lab_manifest.py`: `lab_id`, `lab_version`, `attack_classes`, `identities`, `expected_surface`, `expected_endpoints`, `vulnerabilities`, and optional `discovery_surface`.
Do not add fields that require custom parsing unless the loader and tests are updated in the same pull request.

`lab_app.py` must expose deterministic HTTP routes that implement the benchmark behavior.
Current labs use FastAPI decorators, but the public route contract is intentionally Flask-style: simple route handlers, explicit methods, deterministic in-memory state, and no external services.
The existing `api_saas` lab is the reference pattern:

```python
app = FastAPI(title="Benchmark Lab A2 - API SaaS")

@app.get("/api/v1/resources/{resource_id}")
def get_resource(resource_id: str, current_user: dict[str, Any] = Depends(get_current_user)) -> dict[str, Any]:
    _ = current_user
    resource = RESOURCES.get(resource_id)
    if resource is None:
        raise HTTPException(status_code=404, detail="Resource not found")
    return resource
```

The route intentionally omits the ownership check so the manifest entry `as-vuln-001` can be discovered as `BOLA`.
The same lab includes `/api/v1/admin/bulk-export` for `BFLA`, `/api/v1/internal/debug` for `HIDDEN_ENDPOINT`, `/api/v1/workspaces/{workspace_id}/data` for `TENANT_ISOLATION`, and `/api/v1/users/me` for `MASS_ASSIGNMENT`.

Every lab app must also include a reset path or reset helper used by smoke tests.
For `api_saas`, `reset_state()` restores `USERS`, `RESOURCES`, and `WORKSPACES`, and `/reset` returns `{"status": "ok"}`.
Stateful labs such as `business_race` must reset coupons, inventory, orders, approvals, and carts before each test run.

The ground truth format is a JSON object with a `vulnerabilities` list.
Each vulnerability entry must include:

```json
{
  "id": "as-vuln-005",
  "type": "MASS_ASSIGNMENT",
  "endpoint": "/api/v1/users/me",
  "method": "PATCH",
  "severity": "HIGH",
  "description": "is_admin field can be set via PATCH /api/v1/users/me"
}
```

Endpoint templates must match scanner findings exactly.
Use `/api/v1/resources/{resource_id}`, not a concrete example such as `/api/v1/resources/res-2`, unless the scanner reports the concrete path for that class.

## 2. Adding a New Vulnerability Class

Add planner support under:

```text
execution_plane/planner/rules/
```

Use the existing rule files as naming examples:

```text
execution_plane/planner/rules/bola.py
execution_plane/planner/rules/bfla.py
execution_plane/planner/rules/mass_assignment.py
execution_plane/planner/rules/graphql.py
execution_plane/planner/rules/oauth.py
execution_plane/planner/rules/race_advanced.py
```

The attack class string in the lab must match the planner and validator naming.
Examples already used by the corpus include `BOLA`, `BFLA`, `TENANT_ISOLATION`, `MASS_ASSIGNMENT`, `HIDDEN_ENDPOINT`, `GRAPHQL_INTROSPECTION`, `GRAPHQL_BATCH`, `GRAPHQL_DEPTH`, `GRAPHQL_FIELD_AUTH`, `RACE_CONDITION`, `BUSINESS_LOGIC`, and `AUTH_BYPASS`.

When a new class needs a new rule module, add the rule, register it wherever the planner collects rules, and add validator coverage under:

```text
execution_plane/validator/strategies/
```

The validator strategy must declare or return the expected proof type for the class.
Use existing proof types as examples:

```text
response_diff
state_diff
access_control_bypass
hidden_endpoint
auth_bypass
graphql_response_diff
race_condition
```

Choose a proof type that describes the evidence, not the route name.
For example, `api_saas` BOLA on `/api/v1/resources/{resource_id}` should produce a response or access-control proof showing one identity can read another identity's resource.
The `api_saas` hidden debug route should produce a discovery proof showing `/api/v1/internal/debug` is accessible even though `/api/v1/openapi-spec` does not list it.

After planner and validator support exists, update the lab manifest `attack_classes` list.
For example:

```json
"attack_classes": ["BOLA", "BFLA", "TENANT_ISOLATION", "MASS_ASSIGNMENT", "HIDDEN_ENDPOINT"]
```

The `attack_classes` list is a declaration of what the lab is meant to exercise.
Do not include a class just because the application contains adjacent behavior.
If there is no ground truth vulnerability and no expected proof for the class, leave it out.

## 3. Adding Expected Proof

Every finding in the benchmark must be backed by a `ProofArtifact`.
The database model in `storage/db/models.py` defines these fields:

```text
id
attack_task_id
finding_id
proof_type
confidence_score
attack_probe_id
control_probe_id
identity_role
state_diff
summary
evidence_notes
```

A proof is eligible to become a finding only when:

```python
proof.confidence_score >= 0.85
```

This threshold is non-negotiable for corpus contributions.
Do not add golden findings, manifest vulnerabilities, or expected proof examples that require accepting `confidence_score < 0.85`.
Weak or ambiguous evidence belongs in tests that assert no finding is created.

Expected proof must explain what changed between the attack probe and the control probe.
For `api_saas`, acceptable proof examples include:

```json
{
  "proof_type": "access_control_bypass",
  "confidence_score": 0.90,
  "identity_role": "user",
  "state_diff": {
    "attack_status": 200,
    "control_status": 403,
    "resource_owner": "bob",
    "attacker": "alice"
  },
  "summary": "alice can read bob's resource through /api/v1/resources/{resource_id}",
  "evidence_notes": "attack_identity=alice control_identity=bob endpoint=/api/v1/resources/{resource_id}"
}
```

For the `api_saas` mass-assignment route, expected proof should show that a normal user can set `is_admin` through `PATCH /api/v1/users/me`:

```json
{
  "proof_type": "state_diff",
  "confidence_score": 0.92,
  "identity_role": "user",
  "state_diff": {
    "field": "is_admin",
    "before": false,
    "after": true
  },
  "summary": "PATCH /api/v1/users/me accepts privileged is_admin assignment",
  "evidence_notes": "field=is_admin method=PATCH"
}
```

Add the corresponding vulnerability to `manifest.json` under `vulnerabilities`:

```json
{
  "id": "as-vuln-005",
  "type": "MASS_ASSIGNMENT",
  "endpoint": "/api/v1/users/me",
  "method": "PATCH",
  "severity": "HIGH",
  "description": "is_admin field can be set via PATCH /api/v1/users/me"
}
```

The vulnerability entry and proof must agree on attack class, endpoint template, method, and affected identity context.
If the route is stateful, the lab reset function must make the proof reproducible on every run.

## 4. Adding a Golden Baseline

Golden baselines live under:

```text
tests/benchmark_lab/golden/
```

Add one golden file per lab:

```text
tests/benchmark_lab/golden/{lab_id}_metrics.json
```

For public corpus snapshots, use this JSON shape:

```json
{
  "lab_id": "api_saas",
  "corpus_version": "1.0.0",
  "findings": [
    {
      "id": "as-vuln-001",
      "type": "BOLA",
      "endpoint": "/api/v1/resources/{resource_id}",
      "method": "GET",
      "proof_type": "access_control_bypass",
      "confidence_score": 0.90
    }
  ],
  "metrics": {
    "tp": 1,
    "fp": 0,
    "fn": 4,
    "coverage": 0.20
  }
}
```

The `findings` array records expected scanner output for the lab.
Each item must map back to exactly one entry in `manifest.json` or `ground_truth.json`.
The `metrics` object uses the benchmark definitions from `scripts/benchmark_lab.py`:

```text
tp = ground truth vulnerability matched by a finding with the same type and endpoint
fp = finding that does not match any ground truth vulnerability
fn = ground truth vulnerability not matched by any finding
coverage = tp / (tp + fn)
```

Regenerate the golden baseline after changing lab routes, ground truth, attack class coverage, or expected proof:

```bash
python scripts/benchmark_lab.py --full --lab api_saas --update-golden
```

For all labs:

```bash
python scripts/benchmark_lab.py --full --lab all --update-golden
```

Commit the regenerated file with the lab change.
Do not hand-edit golden metrics to make a failing regression pass.
If coverage changes intentionally, explain the reason in the pull request.

Current internal golden files may also include threshold fields such as `min_coverage`, `max_fp`, `coverage_by_attack_class`, `ground_truth_count`, and `mode`.
Those fields are acceptable for CI thresholds, but public corpus contributions must still preserve the snapshot fields `lab_id`, `corpus_version`, `findings`, and `metrics`.

## 5. Pull Request Checklist

- [ ] Manifest valid: `manifest.json` includes `lab_id`, `lab_version`, `attack_classes`, `identities`, `expected_surface`, `expected_endpoints`, `vulnerabilities`, and `discovery_surface`.
- [ ] Ground truth hash unchanged unless the pull request intentionally changes benchmark truth data and explains the diff.
- [ ] Tests pass: run `pytest tests/benchmark_lab/ -q` and the relevant unit tests for planner or validator changes.
- [ ] Golden updated: run `python scripts/benchmark_lab.py --full --lab {lab_id} --update-golden` and commit the regenerated file under `tests/benchmark_lab/golden/`.
- [ ] Doc updated: update this guide or the benchmark README when adding a new lab pattern, proof type, attack class, or golden snapshot field.
