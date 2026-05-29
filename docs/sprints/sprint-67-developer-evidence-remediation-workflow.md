## Sprint 67 - Developer Evidence And Remediation Workflow

**Goal:** Findings maja byc nie tylko prawdziwe, ale naprawialne: kazdy confirmed issue dostaje replay bundle, wlasciciela, konkretne kroki reprodukcji, fix hint i integracje z workflow developera.

### Architektura - dokumenty referencyjne

```bash
{
  echo "=== FILE: validation-model.md ==="; cat ~/BreachForge/docs/architecture/validation-model.md
  echo "=== FILE: data-model.md ==="; cat ~/BreachForge/docs/architecture/data-model.md
  echo "=== FILE: reporting.py ==="; cat ~/BreachForge/control_plane/reporting.py
} | gemini --output-format text \
  -p "Files above. Extract proof artifact fields missing for developer handoff: replay chain, ownership, export format, suppression lifecycle. Bullets. Max 40 lines." \
  2>&1 | grep -v "^Warning:" | grep -v "^Ripgrep"
```

### Workstream A - Replayable evidence bundles

| ID | Zadanie | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| A1 | Evidence bundle schema: request chain, control request, attack request, state diff, identity context, redacted secrets | `storage/db/models.py`, `storage/evidence/store.py` | codex-main | model tests | proof da sie odtworzyc bez czytania logow |
| A2 | Export formats: cURL, HTTPie, Postman collection, HAR subset | `control_plane/reporting.py`, exporters | codex-dad | snapshot tests | developer moze replayowac lokalnie |
| A3 | Replay safety labels: read-only, state-changing, destructive-blocked, requires synthetic account | scorer/reporting | codex-main | safety tests | repro nie niszczy produkcji przez przypadek |

### Workstream B - Ownership mapping

| ID | Zadanie | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| B1 | Service ownership sources: CODEOWNERS, service catalog YAML, OpenAPI `x-owner`, manual overrides | `control_plane/ownership.py`, API models | codex-main | ownership tests | finding ma team/service owner |
| B2 | Endpoint-to-repo hints from route patterns and asset source attribution | crawler/asset_map/reporting | codex-dad | mapping tests | owner confidence jest jawne |
| B3 | Dedup lifecycle by owner/service/endpoint/attack_class/proof_hash | finding_scorer/storage | codex-main | dedup tests | ten sam bug nie robi spamu |

### Workstream C - Delivery integrations

| ID | Zadanie | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| C1 | GitHub issue/PR comment adapter with evidence summary and replay link | `control_plane/integrations/github.py` | codex-main | adapter tests | dev dostaje actionable task |
| C2 | Jira adapter with severity, owner, due date and proof bundle link | `control_plane/integrations/jira.py` | codex-dad | adapter tests | AppSec moze pracowac w istniejacym procesie |
| C3 | Suppression/accepted-risk workflow with expiry, approver and proof_hash binding | API/storage/reporting | codex-main | lifecycle tests | false-positive/accepted-risk nie ukrywa nowych dowodow |

### Dispatch pattern

**Phase 1 (parallel):** main → A1, A3, B1, B3; dad → (brak — A2/B2 zaleza od A1/B1)
**Phase 2 (parallel, po verify):** main → C1, C3; dad → A2 → B2 → C2
**Dad sequence:** A2 (po A1 schema) → B2 (po B1 ownership) → C2 (po B1+A2)
**Kluczowe zaleznosci:** A2 wymaga A1 (export uzywa schematu); B2 wymaga B1 (route hints po ownership sources); C2 wymaga B1+A2

### Guardrails

- Exporty redaguja sekrety, ale zachowuja techniczny kontekst repro.
- Suppression musi miec expiry i byc zwiazany z proof_hash.
- Fix hints nie moga obiecywac automatycznej naprawy bez pewnosci frameworka.
- Developer workflow nie moze obnizac proof threshold.

### Weryfikacja

```bash
python -m pytest tests/unit/control_plane/test_reporting.py -q
python -m pytest tests/unit/control_plane/test_ownership.py -q
python -m pytest tests/unit/control_plane/test_integrations.py -q
python scripts/benchmark_lab.py --full --output .runtime/evidence-report.json
```

### TL_PROMPT

```bash
TL_PROMPT="Read ~/BreachForge/.workflow/skills/testing-lead.md and follow it.
Sprint: 67 - Developer Evidence And Remediation Workflow
Changed: storage/db/models.py, storage/evidence/store.py, control_plane/reporting.py, control_plane/ownership.py, control_plane/integrations/
Test cases:
- Kazdy finding ma replay bundle i owner metadata
- GitHub/Jira adapters tworza zadania z proof summary
- Suppression lifecycle jest audytowalny i wygasa
- Raport jest uzyteczny dla developera bez dodatkowego manual triage" bash ~/.claude/scripts/testing-lead-exec.sh < /dev/null
```

### Global acceptance criteria

- [ ] Kazdy finding ma replay bundle i owner metadata.
- [ ] GitHub/Jira adapters tworza zadania z proof summary.
- [ ] Suppression lifecycle jest audytowalny i wygasa.
- [ ] Raport jest uzyteczny dla developera bez dodatkowego manual triage.

### Podzial pracy - codex-dad

A2, B2 i C2 ida do **codex-dad**. Reszte robi **codex-main**.
