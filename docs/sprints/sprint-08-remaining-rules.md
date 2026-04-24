## Sprint 8 — Remaining Attack Classes

**Równolegle z Sprint 7** — brak wspólnych plików.

**Goal:** 5 pozostałych klas ataku + validator strategies (auth_bypass, privilege_escalation, sensitive_exposure, workflow_abuse, injection).

### Architektura — dokumenty referencyjne

```bash
DAD_PROMPT="Read /mnt/d/SimpliAppSec/docs/architecture/attack-engine.md. Extract: all remaining rules trigger conditions (auth_bypass, privilege_escalation, sensitive_exposure, workflow_abuse, injection). Bullets. Max 20 lines." bash ~/.claude/scripts/dad-exec.sh

DAD_PROMPT="Read /mnt/d/SimpliAppSec/docs/architecture/validation-model.md. Extract: proof requirements for auth_bypass (absolute), sensitive_exposure (absolute), injection (absolute), workflow_abuse (reproduction). Bullets. Max 20 lines." bash ~/.claude/scripts/dad-exec.sh
```

### Dispatch table — pełny split codex-main ∥ codex-dad

| Plik | Worker | Skill | Uwagi |
|------|--------|-------|-------|
| `rules/auth_bypass.py` | codex-main | `skill:attack-rule-authoring` | batch codex-main |
| `rules/privilege_escalation.py` | codex-main | `skill:attack-rule-authoring` | batch codex-main |
| `strategies/auth_bypass.py` | codex-main | `skill:safe-sensitive-change` | validator strategy |
| `strategies/privilege_escalation.py` | codex-main | `skill:safe-sensitive-change` | validator strategy |
| `tests/unit/.../test_auth_bypass_rule.py` | codex-main | `skill:test-impact-check` | na końcu |
| `rules/sensitive_exposure.py` | codex-dad | `skill:attack-rule-authoring` | batch codex-dad |
| `rules/workflow_abuse.py` | codex-dad | `skill:attack-rule-authoring` | batch codex-dad |
| `rules/injection.py` | codex-dad | `skill:attack-rule-authoring` | batch codex-dad |
| `strategies/sensitive_exposure.py` | codex-dad | `skill:safe-sensitive-change` | validator strategy |
| `strategies/workflow_abuse.py` | codex-dad | `skill:safe-sensitive-change` | validator strategy |

### Prompty

```bash
# codex-main — auth_bypass + privilege_escalation rules + strategies (batch)
codex exec --dangerously-bypass-approvals-and-sandbox \
'Read d:/SimpliAppSec/.workflow/skills/attack-rule-authoring.md and follow its procedure.
Read d:/SimpliAppSec/execution_plane/planner/rules/base.py and d:/SimpliAppSec/execution_plane/validator/strategies/base.py.
Do NOT use Gemini — write directly.
Goal: 4 files following existing patterns:
1. d:/SimpliAppSec/execution_plane/planner/rules/auth_bypass.py — AuthBypass(AttackRule): matches auth-required endpoints, generates tasks that remove/downgrade auth header
2. d:/SimpliAppSec/execution_plane/planner/rules/privilege_escalation.py — PrivilegeEscalation(AttackRule): matches params named role/user_id/account_id/org_id, generates substitution tasks
3. d:/SimpliAppSec/execution_plane/validator/strategies/auth_bypass.py — AuthBypassStrategy: absolute proof — response with no auth must match authenticated response structurally (body match > 80% = confidence 0.95)
4. d:/SimpliAppSec/execution_plane/validator/strategies/privilege_escalation.py — absolute proof — confirms access level changed
from __future__ import annotations in all. Done when: all 4 files exist.'

# codex-dad — sensitive_exposure + workflow_abuse + injection (batch parallel)
DAD_PROMPT='Read /mnt/d/SimpliAppSec/.workflow/skills/attack-rule-authoring.md and follow its procedure.
Read /mnt/d/SimpliAppSec/execution_plane/planner/rules/base.py and /mnt/d/SimpliAppSec/execution_plane/validator/strategies/base.py.
Goal: 5 files:
1. /mnt/d/SimpliAppSec/execution_plane/planner/rules/sensitive_exposure.py — SensitiveExposure(AttackRule): matches endpoints returning structured data, checks for tokens/credentials/PII patterns
2. /mnt/d/SimpliAppSec/execution_plane/planner/rules/workflow_abuse.py — WorkflowAbuse(AttackRule): matches multi-step sequences from AssetMap, generates tasks skipping prerequisite steps
3. /mnt/d/SimpliAppSec/execution_plane/planner/rules/injection.py — InjectionSql(AttackRule): matches string params in state-changing endpoints, error-based probes only
4. /mnt/d/SimpliAppSec/execution_plane/validator/strategies/sensitive_exposure.py — absolute proof: response contains credential/token/PII patterns (regex heuristics)
5. /mnt/d/SimpliAppSec/execution_plane/validator/strategies/workflow_abuse.py — reproduction proof: full request chain stored, confirms bypass of state machine
from __future__ import annotations in all. Done when: all 5 files exist.' bash ~/.claude/scripts/dad-exec.sh
```

### Weryfikacja

```bash
python -m pytest tests/unit/execution_plane/planner/ -q
python -m pytest tests/unit/execution_plane/validator/ -q
```

### Acceptance criteria

- [ ] Wszystkie 7 klas ataku zarejestrowane w AttackPlanner
- [ ] `AuthBypassStrategy` wymaga body match > 80% dla confidence 0.95
- [ ] `InjectionSql` produkuje tylko error-based probes — nie random fuzzing
- [ ] Każda strategia ma zdefiniowany `expected_proof_type()`

### Post-sprint: przegląd skillów

Czy pojawił się nowy powtarzalny pattern? Jeśli tak — zaktualizuj lub dodaj skill w `.workflow/skills/` przed zamknięciem sprintu. Reguła: pattern >= 2x → skodyfikuj.

