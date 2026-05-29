## Sprint 77 — Audit Log Persistence + Tenant Scoping

**Goal:** Zastąpić `_AUDIT_EVENTS: list[AuditEvent] = []` (in-memory) persistent audit log w DB.
Audit trail który ginie po restarcie jest bezwartościowy z perspektywy compliance.

### Problem

```python
# api/routers/audit.py — aktualne zachowanie
_AUDIT_EVENTS: list[AuditEvent] = []
_AUDIT_EXPORTS: dict[tuple[UUID, UUID], AuditExportRecord] = {}
```

Restart API = utracony audit trail. Brak tenant scoping — jedno org widzi eventy innego.
Enterprise compliance (SOC 2, ISO 27001) wymaga niemodyfikowalnego, trwałego logu.

### Scope

**Zmieniamy:**
- Nowa migracja: tabela `audit_events`
- `api/routers/audit.py`: `_AUDIT_EVENTS` i `_AUDIT_EXPORTS` → async DB writes
- Każdy audit event ma `org_id` (tenant scoping) — query filtruje po org_id
- `append_audit_event()` helper → DB insert (nie list append)

**Nie zmieniamy:**
- Kształt `AuditEvent` dataclass (pola: `event_id`, `event_type`, `actor_email`, `org_id`, `resource_type`, `resource_id`, `details`, `timestamp`)
- API contract audit exportu (shape responsów)
- Inne routery — tylko audit.py

### Architektura — dokumenty referencyjne

```bash
cat ~/Projects/BreachForge/docs/architecture/security-constraints.md \
  | gemini --output-format text \
  -p "Extract: audit log requirements, retention rules, tenant isolation for audit data, immutability requirements. Bullets. Max 20 lines." \
  2>&1 | grep -v "^Warning:" | grep -v "^Ripgrep"
```

### Workstream A — Migracja i model

| ID | Zadanie | Pliki | Worker |
|---|---|---|---|
| A1 | Nowa migracja: tabela `audit_events` (id UUID PK, org_id FK → organizations, event_type, actor_email, resource_type, resource_id, details JSONB, timestamp, immutable=true) | `storage/db/migrations/versions/20260529010000_add_audit_events.py` | codex-dad |
| A2 | ORM model `AuditEvent` w `storage/db/models.py` | `storage/db/models.py` | codex-dad |

### Workstream B — Router update

| ID | Zadanie | Pliki | Worker |
|---|---|---|---|
| B1 | `api/routers/audit.py`: `append_audit_event()` → async DB insert (nie list append); usunąć `_AUDIT_EVENTS` i `_AUDIT_EXPORTS` | `api/routers/audit.py` | codex-dad |
| B2 | `api/routers/audit.py`: query audit events → `SELECT * FROM audit_events WHERE org_id = ?` (tenant scoping) | `api/routers/audit.py` | codex-dad |

### Workstream C — Testy

| ID | Zadanie | Pliki | Worker |
|---|---|---|---|
| C1 | Test: `append_audit_event()` wywołuje DB insert z poprawnym `org_id` | `tests/unit/api/routers/test_audit.py` (nowy) | codex-main |
| C2 | Test: listing audit events filtruje po `org_id` — org A nie widzi eventów org B | `tests/unit/api/routers/test_audit.py` | codex-main |

### Dispatch pattern

**Phase 1:** dad → A1, A2
**Phase 2 (po A1/A2):** dad → B1, B2; main → C1, C2

### Guardrails

- Audit events są **append-only** — brak UPDATE ani DELETE na `audit_events` (immutable log)
- Każdy event musi mieć `org_id` — brak eventu bez tenant context
- Export audit zwraca tylko eventy dla `org_id` z `VerifiedActor` (nie query all)
- `details` pole: JSONB, bez sekretów — processor redakcji przed insertem

### Weryfikacja

```bash
python -m pytest tests/unit/api/routers/test_audit.py -q

# Sprawdź że in-memory stores są usunięte:
grep -rn "_AUDIT_EVENTS\|_AUDIT_EXPORTS" api/routers/audit.py
# Wynik: 0 linii
```

### TL_PROMPT

```bash
TL_PROMPT="Read ~/Projects/BreachForge/.workflow/skills/testing-lead.md and follow it.
Sprint: 77 - Audit Log Persistence
Changed: api/routers/audit.py, storage/db/models.py, nowa migracja audit_events
Test cases:
- append_audit_event() zapisuje do DB z poprawnym org_id
- Listing audit events zwraca tylko eventy dla danego org_id (tenant isolation)
- Brak _AUDIT_EVENTS i _AUDIT_EXPORTS list w module audit.py" bash ~/.claude/scripts/testing-lead-exec.sh < /dev/null
```

### Global acceptance criteria

- [ ] `grep -rn "_AUDIT_EVENTS\|_AUDIT_EXPORTS" api/routers/audit.py` → 0 wyników
- [ ] Tabela `audit_events` w migracji Alembic z `org_id FK`
- [ ] Query audit events filtruje po `org_id`
- [ ] Brak UPDATE/DELETE operacji na `audit_events` w kodzie (append-only)
- [ ] Testy tenant isolation dla audit log zielone
