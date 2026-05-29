## Sprint 68 - Safe Active Testing Policy Engine

**Goal:** Umozliwic sprzedaz do prawdziwych firm bez strachu przed aktywnym testowaniem: policy engine musi kontrolowac scope, destrukcyjnosc, okna czasowe, rate limits, rollback i kill switch.

### Architektura - dokumenty referencyjne

```bash
# sprint-56, sprint-61 → Claude: Read docs/sprints/sprint-{56,61}-*.md bezposrednio
{
  echo "=== FILE: security-constraints.md ==="; cat ~/BreachForge/docs/architecture/security-constraints.md
} | gemini --output-format text \
  -p "File above. Extract safety policy gaps for enterprise active scanning: scope control, destructive action classification, kill switch requirements, audit trail requirements. Bullets. Max 40 lines." \
  2>&1 | grep -v "^Warning:" | grep -v "^Ripgrep"
```

### Workstream A - Policy model v2

| ID | Zadanie | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| A1 | Formal scan policy schema: scope, allowed domains, denied paths, method classes, destructive budget, windows | `api/models/requests.py`, storage models | codex-main | schema tests | policy jest jawna i wersjonowana |
| A2 | Policy compiler: maps policy -> planner caps, worker caps, provider caps, rate limiter caps | policy/planner/dispatcher | codex-dad | policy tests | wszystkie warstwy egzekwuja te same ograniczenia |
| A3 | Policy diff and preflight: what will be tested, skipped and blocked before run | API/reporting | codex-main | API tests | klient widzi zakres przed startem |

### Workstream B - Destructive action control

| ID | Zadanie | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| B1 | Action classifier: read, write-safe, write-reversible, destructive, credential-sensitive | planner/rules/workers | codex-main | classifier tests | ryzykowne akcje sa klasyfikowane przed execution |
| B2 | Synthetic account and rollback-safe state change protocols | validator/state_diff/workers | codex-dad | state tests | stateful proof nie zostawia smieci w target app |
| B3 | Required confirmation for destructive-class probes with default deny | API/orchestrator | codex-main | guardrail tests | destrukcyjne testy sa opt-in |

### Workstream C - Runtime controls and audit

| ID | Zadanie | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| C1 | Global kill switch: scan, project, org and runner-level stop | orchestrator/workers/API | codex-main | lifecycle tests | operator moze natychmiast zatrzymac ruch |
| C2 | Immutable audit trail: policy decisions, blocked probes, identity usage, provider execution | storage/reporting | codex-main | audit tests | mozna wyjasnic kazdy request |
| C3 | Authorization pack: signed scope, contact, maintenance window, emergency stop metadata | reporting/API | codex-dad | reporting tests | enterprise buyer ma compliance artifact |

### Dispatch pattern

**Phase 1 (parallel):** main → A1, A3, B1, B3; dad → (brak — A2 zalezy od A1, B2 od B1)
**Phase 2 (parallel, po verify):** main → C1, C2; dad → A2 → B2 → C3
**Dad sequence:** A2 (po A1 schema) → B2 (po B1 classifier) → C3 (po A2+B2)
**Kluczowe zaleznosci:** A2 wymaga A1 (compiler po schemie); B2 wymaga B1 (rollback po classifierze); C3 wymaga A2+B2

### Guardrails

- Default policy jest conservative: no destructive active tests bez opt-in.
- Policy bypass przez provider/HexStrike jest krytycznym test failure.
- Audit nie przechowuje plaintext credentials.
- Kill switch ma pierwszenstwo nad retry/replan.

### Weryfikacja

```bash
python -m pytest tests/unit/execution_plane/test_policy_engine.py -q
python -m pytest tests/unit/execution_plane/workers/ -q
python -m pytest tests/unit/control_plane/test_reporting.py -q
python scripts/benchmark_lab.py --full --policy tests/fixtures/policies/conservative.json
```

### TL_PROMPT

```bash
TL_PROMPT="Read ~/BreachForge/.workflow/skills/testing-lead.md and follow it.
Sprint: 68 - Safe Active Testing Policy Engine
Changed: api/models/requests.py, storage/db/models.py, execution_plane/policy/, control_plane/reporting.py
Test cases:
- Policy v2 kontroluje planner, worker i provider runner
- Destructive actions sa default deny i audytowalne
- Kill switch dziala na aktywnych workerach
- Authorization pack jest generowany per scan" bash ~/.claude/scripts/testing-lead-exec.sh < /dev/null
```

### Global acceptance criteria

- [ ] Policy v2 kontroluje planner, worker i provider runner.
- [ ] Destructive actions sa default deny i audytowalne.
- [ ] Kill switch dziala na aktywnych workerach.
- [ ] Authorization pack jest generowany per scan.

### Podzial pracy - codex-dad

A2, B2 i C3 ida do **codex-dad**. Reszte robi **codex-main**.
