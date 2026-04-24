## Sprint 5 — Attack Planner + BOLA/Tenant Rules

**Goal:** `AttackRule` ABC; `BolaBidirectional` + `TenantIsolation` rules; `AttackPlanner` z priority scoring.

### Architektura — dokumenty referencyjne

```bash
DAD_PROMPT="Read /mnt/d/SimpliAppSec/docs/architecture/attack-engine.md. Extract: rule library structure, all 7 required rules with trigger conditions, priority scoring weights table, what engine must NOT do. Bullets. Max 25 lines." bash ~/.claude/scripts/dad-exec.sh
```

### Graf zależności

```
execution_plane/planner/rules/base.py ─────────────┐ pipeline
                                                    ↓
execution_plane/planner/rules/bola.py ──────────────┤ parallel
execution_plane/planner/rules/tenant_isolation.py ──┘
                                                    ↓
execution_plane/planner/planner.py ─────────────────┘ po rules
tests/ ─────────────────────────────────────────────── po planner
```

### Dispatch table

| Plik | Worker | Skill | Uwagi |
|------|--------|-------|-------|
| `planner/rules/base.py` | codex-main | `skill:scoped-implementation` | ABC — blokuje resztę |
| `planner/rules/bola.py` | codex-main | `skill:attack-rule-authoring` | po base.py |
| `planner/rules/tenant_isolation.py` | codex-dad | `skill:attack-rule-authoring` | parallel z bola |
| `planner/planner.py` | codex-dad | `skill:scoped-implementation` | po rules |
| `tests/unit/...test_bola_rule.py` + `test_planner.py` | codex-main | `skill:test-impact-check` | na końcu |

### Prompty

```bash
# codex-main — base.py (blokuje resztę)
codex exec --dangerously-bypass-approvals-and-sandbox \
'Read d:/SimpliAppSec/.workflow/skills/scoped-implementation.md and follow its procedure.
Read d:/SimpliAppSec/storage/db/models.py for Endpoint and AttackTask entities.
Do NOT use Gemini — write directly.
Goal: d:/SimpliAppSec/execution_plane/planner/rules/base.py — AttackRule ABC
from abc import ABC, abstractmethod. AttackRule has:
- attack_class: str (class variable)
- name: str (class variable)
- matches(endpoint: Endpoint, asset_map: AssetMap) -> bool
- generate_tasks(endpoint: Endpoint, context: ScanContext) -> list[AttackTask]
- expected_proof_signal() -> str
Also define ScanContext dataclass: scan_id, target_url, asset_map.
from __future__ import annotations. Done when: ABC with 3 abstract methods.'

# codex-main — bola.py (po base.py)
codex exec --dangerously-bypass-approvals-and-sandbox \
'Read d:/SimpliAppSec/.workflow/skills/attack-rule-authoring.md and follow its procedure.
Read d:/SimpliAppSec/execution_plane/planner/rules/base.py.
Read d:/SimpliAppSec/ARCHITECTURE.md section 8 rule table (BolaBidirectional row only).
Do NOT use Gemini — write directly.
Goal: d:/SimpliAppSec/execution_plane/planner/rules/bola.py — BolaBidirectional(AttackRule)
- attack_class = "bola"
- matches(): True if endpoint has path parameter that looks like resource ID ({id}, numeric segment) AND auth_required=True AND method=GET
- generate_tasks(): creates AttackTask for each ID parameter, hypothesis="Substitute another users resource ID to confirm unauthorized access"
- expected_proof_signal(): "Response body contains data not belonging to authenticated user"
from __future__ import annotations.'

# codex-dad — tenant_isolation.py + planner.py (parallel z bola)
DAD_PROMPT='Read /mnt/d/SimpliAppSec/.workflow/skills/attack-rule-authoring.md and follow its procedure.
Read /mnt/d/SimpliAppSec/execution_plane/planner/rules/base.py.
Read /mnt/d/SimpliAppSec/ARCHITECTURE.md section 8 for TenantIsolation rule and priority scoring weights.
Goal: Create two files:
1. /mnt/d/SimpliAppSec/execution_plane/planner/rules/tenant_isolation.py — TenantIsolation(AttackRule)
   - attack_class = "tenant_isolation"
   - matches(): True if URL or response body contains tenant-identifying patterns (org_id, tenant_id, company_id, account_id in params)
   - generate_tasks(): cross-tenant ID substitution tasks
   - expected_proof_signal(): "Response contains tenant-identifying markers from another tenant"
2. /mnt/d/SimpliAppSec/execution_plane/planner/planner.py — AttackPlanner
   - Consumes AssetMap, loads all AttackRule subclasses
   - For each endpoint: runs each rule.matches() -> if True: generate_tasks()
   - Assigns priority_score per Section 8 table: +0.40 bola/tenant, +0.20 auth-required, +0.15 state-changing, +0.15 ownership params, +0.10 feasible proof
   - Returns ordered list of AttackTask (descending priority)
   - Max 50 tasks per endpoint (configurable)
from __future__ import annotations in both files. Done when: both files exist.' bash ~/.claude/scripts/dad-exec.sh
```

### Weryfikacja

```bash
python -m pytest tests/unit/execution_plane/planner/ -q
```

### Acceptance criteria

- [ ] `AttackRule` ABC enforces `expected_proof_signal()` — no theoretical rules possible
- [ ] `BolaBidirectional.matches()` only fires on auth-required GET endpoints with ID params
- [ ] Priority scoring matches Section 8 weight table
- [ ] `AttackPlanner` returns tasks in descending priority order

### Post-sprint: przegląd skillów

Czy pojawił się nowy powtarzalny pattern? Jeśli tak — zaktualizuj lub dodaj skill w .workflow/skills/ przed zamknięciem sprintu. Reguła: pattern >= 2x → skodyfikuj.

