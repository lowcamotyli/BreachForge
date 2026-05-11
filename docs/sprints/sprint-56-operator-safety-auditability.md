## Sprint 56 - Operator Safety And Auditability

**Goal:** Narzedzie ma byc bezpieczne operacyjnie: jasna polityka skanu, kill switch, immutable audit log i raport "co zrobiono / czego nie zrobiono / dlaczego".

### Architektura - dokumenty referencyjne

```bash
DAD_PROMPT="cd /mnt/d/BreachForge && Read docs/architecture/security-constraints.md and docs/architecture/storage-infra.md. Extract: scope, rate, credential, evidence and audit invariants. Bullets. Max 25 lines." bash ~/.claude/scripts/dad-exec.sh
```

### Workstream A - Scan policy

| ID | Zadanie | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| A1 | Formalny `ScanPolicy`: allowed domains, max requests, mutating allowed, replay allowed, OOB allowed | `api/models/requests.py`, `storage/db/models.py` | codex-dad | policy tests | policy zapisana per scan |
| A2 | Worker egzekwuje policy w jednym miejscu | `execution_plane/workers/attack_worker.py` | codex-dad | guardrail tests | brak rozproszonych bypassow |
| A3 | Planner filtruje tasks wedlug policy przed dispatch | `execution_plane/planner/planner.py` | codex-main | planner tests | unsafe tasks sa oznaczone/skipped |

### Workstream B - Kill switch and audit log

| ID | Zadanie | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| B1 | Global/per-scan kill switch sprawdzany przed requestem i przed enqueue | `attack_worker.py`, `dispatcher.py`, `api/routers/scans.py` | codex-dad | lifecycle tests | scan mozna natychmiast zatrzymac |
| B2 | Immutable audit event model/store | `storage/db/models.py`, `control_plane/orchestrator.py` | codex-dad | audit tests | kazdy istotny krok ma event |
| B3 | Audit redaction processor: zero raw credentials | `api/middleware/logging.py`, audit helpers | codex-main | redaction tests | Authorization/Cookie/token nie wystepuja |

### Workstream C - Reporting transparency

| ID | Zadanie | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| C1 | Report sekcja "Actions Performed" z licznikami requestow i klas | `control_plane/reporting.py` | codex-main | reporting tests | klient widzi zakres dzialan |
| C2 | Report sekcja "Skipped/Blocked" z powodami policy/safety/auth | `control_plane/reporting.py` | codex-main | reporting tests | brak cichych pominięc |
| C3 | Evidence links do audit events | `control_plane/reporting.py`, `storage/evidence/store.py` | codex-main | tests | traceability od findingu do action |

### Guardrails

- Fail-closed defaults: mutations, replay i OOB domyslnie wylaczone.
- Kill switch ma pierwszenstwo przed rate limiterem i worker retry.
- Audit log nie moze zawierac raw credentials.

### Weryfikacja

```bash
python -m pytest tests/unit/execution_plane/workers/ -q
python -m pytest tests/unit/control_plane/test_reporting.py -q
python -m pytest tests/unit/api/ -q
python -m pytest tests/unit/ -q
```

### Global acceptance criteria

- [ ] Scan policy jest jawna i egzekwowana.
- [ ] Kill switch zatrzymuje requesty i enqueue.
- [ ] Audit log pokazuje akcje bez sekretow.
- [ ] Report wyjasnia wykonane i pominiete testy.

### Podzial pracy - codex-dad

A1-A2 i B1-B2 ida do **codex-dad** jako sensitive/runtime package. A3, B3 i C robi **codex-main**.
