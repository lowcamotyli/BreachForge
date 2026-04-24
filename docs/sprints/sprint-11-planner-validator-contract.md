## Sprint 11 — Planner/Validator Contract Fix

**Goal:** Ujednolicenie kontraktu między plannerem, walidatorem i scoringiem: wszystkie klasy ataku są obsługiwane, nazwy `attack_class` są spójne end-to-end, a planner jest gotowy na tryb dynamicznego replanningu.

### Powiazanie z pelnym pokryciem atakow

Szczegolowy backlog typow atakow i globalnych gate'ow znajduje sie w:
`docs/sprints/sprint-15-security-attack-coverage.md`.

### Architektura — dokumenty referencyjne

```bash
DAD_PROMPT="Read /mnt/d/SimpliAppSec/docs/architecture/attack-engine.md and /mnt/d/SimpliAppSec/docs/architecture/validation-model.md. Extract: required v1 attack classes and proof-type mapping per class. Bullets. Max 25 lines." bash ~/.claude/scripts/dad-exec.sh
```

### Dispatch table

| Plik | Worker | Skill | Uwagi |
|------|--------|-------|-------|
| `execution_plane/validator/validator.py` | codex-main | `skill:safe-sensitive-change` | strategy registry |
| `execution_plane/planner/rules/injection.py` | codex-main | `skill:attack-rule-authoring` | `attack_class` naming |
| `control_plane/finding_scorer.py` | codex-main | `skill:scoped-implementation` | severity mapping for final names |
| `execution_plane/validator/strategies/*.py` | codex-dad | `skill:safe-sensitive-change` | registration compatibility |
| testy planner/validator/scorer | codex-main | `skill:test-impact-check` | regression suite |

### Prompty

```bash
# codex-main — registry + naming consistency
codex exec --dangerously-bypass-approvals-and-sandbox \
'Read d:/SimpliAppSec/.workflow/skills/scoped-implementation.md and follow its procedure.
Do NOT use Gemini — write directly.
Goal:
1. d:/SimpliAppSec/execution_plane/validator/validator.py
   - Register all required strategies by attack_class (bola, tenant_isolation, auth_bypass, privilege_escalation, sensitive_exposure, workflow_abuse, injection)
   - Remove silent drop for classes that should be supported
2. d:/SimpliAppSec/execution_plane/planner/rules/injection.py
   - Align attack_class naming with scorer/validator contract
3. d:/SimpliAppSec/control_plane/finding_scorer.py
   - Severity matrix must match final canonical attack_class names
Done when: generated tasks are always routable to validator strategy and scorer.'

# codex-dad — strategy compatibility pass
DAD_PROMPT='Read /mnt/d/SimpliAppSec/.workflow/skills/safe-sensitive-change.md and follow its procedure.
Goal: review and patch strategy modules under /mnt/d/SimpliAppSec/execution_plane/validator/strategies/
- Ensure proof_type and expected attack_class routing are consistent
- Ensure no strategy returns below-threshold proof artifact
Done when: strategies are consistent with validator registry and planner outputs.' bash ~/.claude/scripts/dad-exec.sh
```

### Weryfikacja

```bash
python -m pytest tests/unit/execution_plane/planner/ -q
python -m pytest tests/unit/execution_plane/validator/ -q
python -m pytest tests/unit/control_plane/ -q
```

### Acceptance criteria

- [ ] Validator obsługuje wszystkie klasy ataku wymagane przez v1
- [ ] `injection` class name jest spójna planner -> validator -> scorer
- [ ] Brak utraty artefaktów przez błędne mapowanie klasy ataku
- [ ] Severity mapping działa dla finalnych canonical names

### Post-sprint: przegląd skillów

Czy pojawił się nowy powtarzalny pattern? Jeśli tak — zaktualizuj lub dodaj skill w `.workflow/skills/` przed zamknięciem sprintu. Reguła: pattern >= 2x -> skodyfikuj.


