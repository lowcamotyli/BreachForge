## Sprint 12 — Credential & Evidence Security Corrections

**Goal:** Naprawa ścieżki danych bezpieczeństwa: brak plaintext credentials, purge po skanie, EvidenceStore zapisuje pełne dane bez redakcji, redakcja tylko w eksporcie.

### Powiazanie z pelnym pokryciem atakow

Szczegolowy backlog typow atakow i globalnych gate'ow znajduje sie w:
`docs/sprints/sprint-15-security-attack-coverage.md`.

### Architektura — dokumenty referencyjne

```bash
DAD_PROMPT="Read /mnt/d/SimpliAppSec/docs/architecture/security-constraints.md. Extract: credential lifecycle, purge requirements, and evidence redaction boundary (write vs export). Bullets. Max 25 lines." bash ~/.claude/scripts/dad-exec.sh
```

### Dispatch table

| Plik | Worker | Skill | Uwagi |
|------|--------|-------|-------|
| `api/routers/scans.py` | codex-main | `skill:safe-sensitive-change` | input path credential handling |
| `control_plane/auth_manager.py` | codex-main | `skill:safe-sensitive-change` | decrypt/use/purge lifecycle |
| `execution_plane/workers/attack_worker.py` | codex-main | `skill:safe-sensitive-change` | stop pre-write redaction |
| `control_plane/reporting.py` | codex-dad | `skill:safe-sensitive-change` | full export-time redaction set |
| `storage/db/encryption.py` + integration points | codex-dad | `skill:safe-sensitive-change` | envelope encryption wiring |
| testy security path | codex-main | `skill:test-impact-check` | no-secret-in-logs + purge |

### Prompty

```bash
# codex-main — secure write path
codex exec --dangerously-bypass-approvals-and-sandbox \
'Read d:/SimpliAppSec/.workflow/skills/safe-sensitive-change.md and follow its procedure.
Do NOT use Gemini — write directly.
Goal:
1. d:/SimpliAppSec/api/routers/scans.py + d:/SimpliAppSec/control_plane/auth_manager.py
   - Never persist raw credentials/plain bearer in cleartext session_snapshot
   - Use encryption helper for secret-at-rest path
   - Implement purge step after scan complete/failed
2. d:/SimpliAppSec/execution_plane/workers/attack_worker.py
   - Evidence payload must contain full request/response values (no pre-write redaction)
Done when: evidence write path is unredacted and credential-at-rest path is encrypted.'

# codex-dad — export redaction boundary
DAD_PROMPT='Read /mnt/d/SimpliAppSec/.workflow/skills/safe-sensitive-change.md and follow its procedure.
Goal:
1. /mnt/d/SimpliAppSec/control_plane/reporting.py
   - Redact only at export
   - Include Authorization, Cookie, password fields, token patterns, secret patterns
2. Wire /mnt/d/SimpliAppSec/storage/db/encryption.py into runtime usage points
Done when: architecture rule "write raw, redact on export" is preserved end-to-end.' bash ~/.claude/scripts/dad-exec.sh
```

### Weryfikacja

```bash
python -m pytest tests/unit/control_plane/ -q
python -m pytest tests/unit/execution_plane/workers/ -q
python -m pytest tests/unit/storage/ -q
```

### Acceptance criteria

- [ ] Raw credentials are never persisted plaintext at rest
- [ ] Credentials are purged after scan terminal state
- [ ] EvidenceStore receives full unredacted request/response payload
- [ ] Report export applies comprehensive redaction (headers + body + token patterns)

### Post-sprint: przegląd skillów

Czy pojawił się nowy powtarzalny pattern? Jeśli tak — zaktualizuj lub dodaj skill w `.workflow/skills/` przed zamknięciem sprintu. Reguła: pattern >= 2x -> skodyfikuj.


