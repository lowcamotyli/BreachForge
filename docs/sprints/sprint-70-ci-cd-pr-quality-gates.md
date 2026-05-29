## Sprint 70 - CI/CD And PR Quality Gates

**Goal:** BreachForge ma wejsc w workflow developera: szybkie PR checks, diff-aware scan planning, baseline suppressions, actionable comments i jasne gates bez karania zespolow za szerokie uzycie.

### Architektura - dokumenty referencyjne

```bash
# sprint-67, sprint-69 → Claude: Read docs/sprints/sprint-{67,69}-*.md bezposrednio
{
  echo "=== FILE: attack-engine.md ==="; cat ~/BreachForge/docs/architecture/attack-engine.md
} | gemini --output-format text \
  -p "File above. Extract CI/CD integration contracts and fast-feedback constraints: scan budget, diff-aware planning, gate semantics, artifact requirements. Bullets. Max 40 lines." \
  2>&1 | grep -v "^Warning:" | grep -v "^Ripgrep"
```

### Workstream A - CI entrypoints

| ID | Zadanie | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| A1 | BreachForge CLI: scan create, preflight, wait, export report, exit gates | `cli/`, pyproject entrypoint | codex-main | CLI tests | CI moze uzyc jednej komendy |
| A2 | GitHub Action and GitLab CI templates with private runner support | `.github/actions/`, docs | codex-main | smoke | setup w repo klienta jest prosty |
| A3 | Jenkins/generic webhook mode for enterprise pipelines | API/CLI docs | codex-dad | integration smoke | starsze CI nie sa blokada sprzedazy |

### Workstream B - Diff-aware scan planning

| ID | Zadanie | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| B1 | Changed endpoint inference from OpenAPI diff, route diff, gateway spec diff | crawler/importers/planner | codex-main | diff tests | PR scan jest szybki i celowany |
| B2 | Baseline comparison: new, fixed, unchanged, resurfaced findings | storage/reporting/scorer | codex-dad | lifecycle tests | PR pokazuje tylko istotne zmiany |
| B3 | Fast scan budget: high-signal attack classes only, auth/discovery gates still enforced | planner/policy | codex-main | planner tests | szybki tryb nie udaje pelnego skanu |

### Workstream C - Developer feedback gates

| ID | Zadanie | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| C1 | Gate policies: max_new_critical, max_new_high, no_auth_failure, discovery_regression, no_new_fp_budget | API/CLI/reporting | codex-main | gate tests | pipeline exit code jest deterministyczny |
| C2 | PR comments with proof summary, owner, replay command and suppress link | integrations/github/gitlab | codex-main | snapshot tests | developer nie musi otwierac dashboardu |
| C3 | Local dev mode against ephemeral URL with redacted artifact upload | CLI/runners | codex-dad | CLI smoke | dev moze odtworzyc problem przed merge |

### Dispatch pattern

**Phase 1 (parallel):** main → A1, A2, B1, B3; dad → (brak — A3 zalezy od A1, B2 od B1)
**Phase 2 (parallel, po verify):** main → C1, C2; dad → A3 → B2 → C3
**Dad sequence:** A3 (po A1 CLI) → B2 (po B1 planera) → C3 (po A1+B1)
**Kluczowe zaleznosci:** A3 wymaga A1 (webhook po CLI); B2 wymaga B1 (baseline po diff plannerze); C3 wymaga A1+B1

### Guardrails

- PR mode nie moze obnizac proof threshold.
- Auth/discovery failure moze zablokowac gate zamiast dawac false clean.
- Suppression w PR musi miec reason, owner i expiry.
- CI logs nie zawieraja auth material ani full request bodies z sekretami.

### Weryfikacja

```bash
python -m pytest tests/unit/cli/ -q
python -m pytest tests/unit/control_plane/test_quality_gates.py -q
python -m pytest tests/integration/test_ci_scan.py -q
breachforge scan --target http://127.0.0.1:8000 --gate .breachforge.yml
```

### TL_PROMPT

```bash
TL_PROMPT="Read ~/BreachForge/.workflow/skills/testing-lead.md and follow it.
Sprint: 70 - CI/CD And PR Quality Gates
Changed: cli/, .github/actions/, execution_plane/crawler/, storage/reporting/, execution_plane/planner/
Test cases:
- CLI i GitHub/GitLab templates dzialaja (jedna komenda startuje scan)
- Diff-aware planner skraca PR scans bez utraty gate semantics
- PR comments sa actionable i proof-backed
- Quality gates maja deterministyczne exit codes" bash ~/.claude/scripts/testing-lead-exec.sh < /dev/null
```

### Global acceptance criteria

- [ ] CLI i GitHub/GitLab templates dzialaja.
- [ ] Diff-aware planner skraca PR scans bez utraty gate semantics.
- [ ] PR comments sa actionable i proof-backed.
- [ ] Quality gates maja deterministyczne exit codes.

### Podzial pracy - codex-dad

A3, B2 i C3 ida do **codex-dad**. Reszte robi **codex-main**.
