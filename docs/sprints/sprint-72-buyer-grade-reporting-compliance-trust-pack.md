## Sprint 72 - Buyer Grade Reporting Compliance And Trust Pack

**Goal:** Zrobic raportowanie na poziomie enterprise incumbents, ale bez utraty unikalnosci: nie dashboard theater, tylko signed evidence, coverage truth, compliance mappings i jasny business risk.

### Architektura - dokumenty referencyjne

```bash
# sprint-67 → Claude: Read docs/sprints/sprint-67-developer-evidence-remediation-workflow.md bezposrednio
{
  echo "=== FILE: validation-model.md ==="; cat ~/BreachForge/docs/architecture/validation-model.md
  echo "=== FILE: noise-reduction.md ==="; cat ~/BreachForge/docs/architecture/noise-reduction.md
} | gemini --output-format text \
  -p "Files above. Extract reporting gaps for buyer-grade trust: evidence integrity, signed manifests, compliance mapping constraints, persona-specific output requirements. Bullets. Max 40 lines." \
  2>&1 | grep -v "^Warning:" | grep -v "^Ripgrep"
```

### Workstream A - Report personas

| ID | Zadanie | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| A1 | Executive summary: exploitable risk, coverage truth, trend, top service owners, release gate status | `control_plane/reporting.py` | codex-main | reporting snapshots | CTO/AppSec lead widzi decyzje, nie tylko alerty |
| A2 | Developer report: proof, replay, owner, fix hint, affected endpoint, state diff | reporting/exporters | codex-main | snapshot tests | dev moze naprawic bez rozmowy z analitykiem |
| A3 | Auditor report: policy, auth reliability, scope, evidence hashes, blocked/skipped classes | reporting/exporters | codex-dad | snapshot tests | compliance review ma dowody |

### Workstream B - Standards mapping

| ID | Zadanie | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| B1 | Mapping registry: OWASP API Top 10, WSTG, ASVS, CWE, CVSS hints | `control_plane/taxonomy.py` | codex-main | taxonomy tests | findings i coverage mapuja sie do standardow |
| B2 | Per-attack-class remediation templates with framework-neutral guidance | reporting/templates | codex-dad | content tests | fix guidance jest konkretna, ale nie zmysla frameworka |
| B3 | Risk model v2: proof confidence, blast radius, auth level, exploit repeatability, business impact | finding_scorer/reporting | codex-main | scorer tests | severity jest wyjasnialna |

### Workstream C - Trust artifacts

| ID | Zadanie | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| C1 | Signed evidence manifest: hashes for raw probes, proof artifacts, report bundle | storage/evidence/reporting | codex-main | integrity tests | raport mozna zweryfikowac po eksporcie |
| C2 | Export formats: JSON, Markdown, SARIF, PDF-ready HTML | reporting/exporters | codex-dad | golden exports | klient moze uzyc raportu w swoich narzedziach |
| C3 | Report API versioning and backward-compatible schema contracts | API/responses/reporting | codex-main | API contract tests | integracje nie pekaja przy zmianach |

### Dispatch pattern

**Phase 1 (parallel):** main → A1, A2, B1, B3; dad → (brak — A3 zalezy od A1/A2, B2 od B1)
**Phase 2 (parallel, po verify):** main → C1, C3; dad → A3 → B2 → C2
**Dad sequence:** A3 (po A1+A2 exporterach) → B2 (po B1 taxonomy) → C2 (po A3+B2)
**Kluczowe zaleznosci:** A3 wymaga A1+A2 (auditor exportuje z exec/dev); B2 wymaga B1 (templates po taxonomy); C2 wymaga A3+B2 (eksport uzywa wszystkich persona+templates)

### Guardrails

- Report nie moze ukrywac auth/discovery blind spots.
- Compliance mapping nie moze sugerowac pelnej zgodnosci, tylko tested evidence.
- SARIF export nie moze emitowac unproven signals jako confirmed findings.
- Signed manifest nie podpisuje redacted preview zamiast raw evidence hash.

### Weryfikacja

```bash
python -m pytest tests/unit/control_plane/test_reporting.py -q
python -m pytest tests/unit/control_plane/test_taxonomy.py -q
python scripts/benchmark_lab.py --full --output .runtime/report-source.json
python -m pytest tests/integration/test_reports_api.py -q
```

### TL_PROMPT

```bash
TL_PROMPT="Read ~/BreachForge/.workflow/skills/testing-lead.md and follow it.
Sprint: 72 - Buyer Grade Reporting Compliance And Trust Pack
Changed: control_plane/reporting.py, control_plane/taxonomy.py, control_plane/finding_scorer.py, storage/evidence/
Test cases:
- Sa osobne raporty dla executive, developer i auditor personas
- Findings i coverage mapuja sie do OWASP/API/WSTG/ASVS/CWE
- Evidence bundle ma signed manifest i integrity checks
- Export JSON/Markdown/SARIF/HTML jest stabilny kontraktowo" bash ~/.claude/scripts/testing-lead-exec.sh < /dev/null
```

### Global acceptance criteria

- [ ] Sa osobne raporty dla executive, developer i auditor personas.
- [ ] Findings i coverage mapuja sie do OWASP/API/WSTG/ASVS/CWE.
- [ ] Evidence bundle ma signed manifest i integrity checks.
- [ ] Export JSON/Markdown/SARIF/HTML jest stabilny kontraktowo.

### Podzial pracy - codex-dad

A3, B2 i C2 ida do **codex-dad**. Reszte robi **codex-main**.
