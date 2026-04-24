## Sprint 6 — ExploitValidator + Evidence Store

**Goal:** `ExploitValidator` z differential probing dla BOLA/IDOR; S3 `EvidenceStore`; proof-gate 0.85 enforced.

### Architektura — dokumenty referencyjne

```bash
DAD_PROMPT="Read /mnt/d/SimpliAppSec/docs/architecture/validation-model.md. Extract: ALL proof types, confidence thresholds, BOLA differential proof steps, what does NOT become a finding, low-confidence handling. Bullets. Max 25 lines." bash ~/.claude/scripts/dad-exec.sh

DAD_PROMPT="Read /mnt/d/SimpliAppSec/docs/architecture/noise-reduction.md. Extract: all 6 noise reduction mechanisms. Bullets. Max 15 lines." bash ~/.claude/scripts/dad-exec.sh
```

### Dispatch table

| Plik | Worker | Skill | Uwagi |
|------|--------|-------|-------|
| `validator/strategies/base.py` | codex-main | `skill:safe-sensitive-change` | ABC — blokuje resztę |
| `validator/strategies/bola.py` | codex-main | `skill:safe-sensitive-change` | differential proof |
| `validator/validator.py` | codex-dad | `skill:safe-sensitive-change` | queue consumer |
| `storage/evidence/store.py` | codex-dad | `skill:scoped-implementation` | S3 client — parallel |
| testy | codex-main | `skill:test-impact-check` | na końcu |

### Prompty

```bash
# codex-main — validator base + bola strategy (batch, pipeline)
codex exec --dangerously-bypass-approvals-and-sandbox \
'Read d:/SimpliAppSec/.workflow/skills/safe-sensitive-change.md and follow its procedure.
Read d:/SimpliAppSec/storage/db/models.py for ProofArtifact, RawProbe entities.
Do NOT use Gemini — write directly.
Goal: Two validator files:
1. d:/SimpliAppSec/execution_plane/validator/strategies/base.py — ValidationStrategy ABC
   - validate(attack_probe: RawProbe, control_probe: RawProbe | None) -> ProofArtifact | None
   - expected_proof_type() -> str
2. d:/SimpliAppSec/execution_plane/validator/strategies/bola.py — BolaStrategy(ValidationStrategy)
   - Differential proof: compares attack_probe.response vs control_probe.response
   - confidence = 0.90 if bodies semantically different (not just status)
   - confidence = 0.70 if only status differs (below threshold — returns None, not artifact)
   - Returns ProofArtifact only if confidence >= 0.85
   - NEVER bypass the 0.85 threshold check
from __future__ import annotations in both. Done when: both files exist.'

# codex-dad — validator + evidence store (parallel batch)
DAD_PROMPT='Read /mnt/d/SimpliAppSec/.workflow/skills/safe-sensitive-change.md and follow its procedure.
Read /mnt/d/SimpliAppSec/execution_plane/validator/strategies/base.py after codex-main creates it.
Read /mnt/d/SimpliAppSec/storage/db/models.py for ProofArtifact entity.
Goal: Two files:
1. /mnt/d/SimpliAppSec/execution_plane/validator/validator.py — ExploitValidator
   - Consumes Redis stream evidence:{scan_id} for RawProbe objects
   - For each probe: selects appropriate ValidationStrategy by attack_class
   - Runs strategy.validate() — if returns ProofArtifact: writes to EvidenceStore + publishes to finding_scorer queue
   - If below threshold: discards (low-confidence store if >= 0.50, else drop entirely)
   - THE ONLY COMPONENT THAT DECIDES IF SOMETHING IS A FINDING
   - from __future__ import annotations
2. /mnt/d/SimpliAppSec/storage/evidence/store.py — EvidenceStore
   - S3 boto3 client initialized from AWS env vars + EVIDENCE_BUCKET
   - write_probe(scan_id, finding_id, probe: RawProbe): gzip JSON, key pattern {scan_id}/{finding_id}/{probe_id}.json.gz
   - write_artifact(scan_id, finding_id, artifact: ProofArtifact): gzip JSON, key pattern {scan_id}/{finding_id}/proof_{artifact_id}.json.gz
   - NEVER redact at write time — full unredacted data stored
   - from __future__ import annotations
Done when: both files exist.' bash ~/.claude/scripts/dad-exec.sh
```

### Weryfikacja

```bash
python -m pytest tests/unit/execution_plane/validator/ -q
python -m pytest tests/unit/storage/ -q
```

### Acceptance criteria

- [ ] `BolaStrategy` returns `None` for confidence < 0.85 — no bypass possible
- [ ] `ExploitValidator` is the ONLY component writing to finding scorer queue
- [ ] `EvidenceStore` stores full unredacted data
- [ ] Key pattern matches `{scan_id}/{finding_id}/{probe_id}.json.gz`

### Post-sprint: przegląd skillów

Czy pojawił się nowy powtarzalny pattern? Jeśli tak — zaktualizuj lub dodaj skill w `.workflow/skills/` przed zamknięciem sprintu. Reguła: pattern >= 2x → skodyfikuj.

