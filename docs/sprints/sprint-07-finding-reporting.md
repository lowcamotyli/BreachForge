## Sprint 7 — FindingScorer + ReportingService

**Równolegle z Sprint 8** — brak wspólnych plików.

**Goal:** Structural dedup przed zapisem; JSON + Markdown report; redakcja credentials wyłącznie przy eksporcie.

### Architektura — dokumenty referencyjne

```bash
DAD_PROMPT="Read /mnt/d/SimpliAppSec/docs/architecture/noise-reduction.md. Extract: dedup fingerprint formula, structural fingerprint fields, how duplicate variants handled. Bullets. Max 15 lines." bash ~/.claude/scripts/dad-exec.sh
```

### Dispatch table

| Plik | Worker | Skill | Uwagi |
|------|--------|-------|-------|
| `control_plane/finding_scorer.py` | codex-main | `skill:scoped-implementation` | dedup — wrażliwe, Claude review |
| `control_plane/reporting.py` | codex-dad | `skill:scoped-implementation` | JSON + Markdown + redakcja |
| `api/routers/findings.py` | codex-dad | `skill:scoped-implementation` | parallel z reporting |
| `api/routers/reports.py` | codex-dad | `skill:scoped-implementation` | parallel |
| testy | codex-main | `skill:test-impact-check` | na końcu |

### Prompty

```bash
# codex-main — FindingScorer
codex exec --dangerously-bypass-approvals-and-sandbox \
'Read d:/SimpliAppSec/.workflow/skills/scoped-implementation.md and follow its procedure.
Read d:/SimpliAppSec/storage/db/models.py for Finding, ProofArtifact entities.
Do NOT use Gemini — write directly.
Goal: d:/SimpliAppSec/control_plane/finding_scorer.py — FindingScorer
- score(artifact: ProofArtifact, endpoint: Endpoint) -> Finding | None
- compute_fingerprint(): (attack_class, normalize_url_pattern(endpoint.url_pattern), parameter_class)
- normalize_url_pattern(): replace /123/ with /{id}/ using regex
- Check fingerprint against existing findings for this scan_id in DB
- If novel: create Finding, set severity per matrix (bola+confidence>=0.90=critical, auth_bypass>=0.85=critical, etc.)
- If duplicate: increment evidence count on existing finding, return None
- DEDUP CHECK MUST HAPPEN BEFORE db.add(finding) — never after
from __future__ import annotations. Done when: file exists with dedup enforced before write.'

# codex-dad — Reporting + API routers (batch parallel)
DAD_PROMPT='Read /mnt/d/SimpliAppSec/.workflow/skills/scoped-implementation.md and follow its procedure.
Read /mnt/d/SimpliAppSec/storage/db/models.py and /mnt/d/SimpliAppSec/api/models/responses.py.
Goal: Three files:
1. /mnt/d/SimpliAppSec/control_plane/reporting.py — ReportingService
   - assemble_report(scan_id) -> dict: fetches all Findings from DB, fetches ProofArtifacts from EvidenceStore
   - render_markdown(report: dict) -> str: one section per finding, severity, description, repro_steps, fix_guidance, exact request/response
   - render_json(report: dict) -> str: structured JSON
   - export(): applies redaction — replaces Authorization header value, Cookie header value, password fields with [REDACTED]
   - NEVER does analysis — only assembles and formats
2. /mnt/d/SimpliAppSec/api/routers/findings.py — GET /scans/{id}/findings returns list[FindingResponse]
3. /mnt/d/SimpliAppSec/api/routers/reports.py — GET /scans/{id}/report?format=json|markdown calls ReportingService.export()
from __future__ import annotations in all files. Done when: all 3 files exist.' bash ~/.claude/scripts/dad-exec.sh
```

### Weryfikacja

```bash
python -m pytest tests/unit/control_plane/ -q
```

### Acceptance criteria

- [ ] Fingerprint dedup check happens BEFORE `db.add(finding)`
- [ ] Duplicate variant increments evidence count, does NOT create new Finding
- [ ] Redaction applies ONLY in `export()` — not in EvidenceStore write
- [ ] Markdown output has: severity, exact request, exact response, repro steps, fix guidance

### Post-sprint: przegląd skillów

Czy pojawił się nowy powtarzalny pattern? Jeśli tak — zaktualizuj lub dodaj skill w `.workflow/skills/` przed zamknięciem sprintu. Reguła: pattern >= 2x → skodyfikuj.

