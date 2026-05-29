## Sprint 79 — Test Suite Green + Integration Lifecycle Test

**Goal:** Osiągnąć 0 błędów kolekcji testów, wszystkie testy zielone,
i dodać integration test pełnego lifecycle skanu.

### Problem

Aktualne błędy kolekcji (blokują `python -m pytest tests/ -q`):
```
ERROR tests/unit/scripts/test_benchmark_cli.py
ERROR tests/unit/scripts/test_benchmark_importers.py
ERROR tests/unit/scripts/test_miss_classifier.py
```

Brak integration testu end-to-end: scan create → queue → process (mocked) → report.
Brak testu tenant isolation: org A nie może dostać zasobów org B przez API.

### Scope

**Naprawiamy:**
- 3 broken test collection errors w `tests/unit/scripts/`

**Dodajemy:**
- `tests/integration/test_scan_lifecycle.py`: pełny flow od API create scan → przez queued state → completion → get report (worker zmockowany)
- `tests/integration/test_tenant_isolation.py`: org A nie może GET scans/findings/reports org B nawet z ważnym API key

**Nie zmieniamy:**
- Kodu aplikacji (tylko testy)
- Istniejących test fixtures

### Diagnoza błędów kolekcji

Przed dispatchem — sprawdź przyczynę każdego błędu:
```bash
python -m pytest tests/unit/scripts/test_benchmark_cli.py --collect-only 2>&1 | head -30
python -m pytest tests/unit/scripts/test_benchmark_importers.py --collect-only 2>&1 | head -30
python -m pytest tests/unit/scripts/test_miss_classifier.py --collect-only 2>&1 | head -30
```

Typowe przyczyny: brakujący import (moduł przeniesiony), missing fixture, syntax error po sprint.

### Workstream A — Fix broken tests

| ID | Zadanie | Pliki | Worker |
|---|---|---|---|
| A1 | Zdiagnozuj i napraw błąd kolekcji `test_benchmark_cli.py` | `tests/unit/scripts/test_benchmark_cli.py` | codex-dad |
| A2 | Zdiagnozuj i napraw błąd kolekcji `test_benchmark_importers.py` | `tests/unit/scripts/test_benchmark_importers.py` | codex-dad |
| A3 | Zdiagnozuj i napraw błąd kolekcji `test_miss_classifier.py` | `tests/unit/scripts/test_miss_classifier.py` | codex-dad |

### Workstream B — Integration tests

| ID | Zadanie | Pliki | Worker |
|---|---|---|---|
| B1 | `tests/integration/test_scan_lifecycle.py`: FastAPI TestClient, mock AsyncSession, mock rq queue — create scan → verify queued → mock complete → GET report | `tests/integration/test_scan_lifecycle.py` (nowy) | codex-main |
| B2 | `tests/integration/test_tenant_isolation.py`: dwie org, dwa API keys — org A API key → GET /orgs/{org_B_id}/scans → 403/404 | `tests/integration/test_tenant_isolation.py` (nowy) | codex-main |

### Dispatch pattern

**Phase 1 (parallel):** dad → A1, A2, A3 (niezależne fix-y)
**Phase 2 (po A1-A3, bo B1/B2 mogą zależeć od fixów):** main → B1, B2

### Guardrails

- Fix musi być minimalny: napraw import/fixture, nie refaktoryzuj testu
- Integration test używa FastAPI `TestClient` (nie startuje prawdziwego serwera)
- Tenant isolation test musi symulować `VerifiedActor` z org_id org A, próbujący dostęp do org B zasobów
- Żaden integration test nie łączy się z prawdziwą DB (mock AsyncSession)
- Cel: `python -m pytest tests/ -q` bez żadnych błędów kolekcji

### Weryfikacja

```bash
# Zero collection errors:
python -m pytest tests/ --collect-only -q 2>&1 | grep "ERROR"
# Wynik: 0 linii

# Wszystkie testy zielone:
python -m pytest tests/unit/ -q --ignore=tests/unit/scripts  # musi być zielone
python -m pytest tests/unit/scripts/ -q                       # po fixach musi być zielone
python -m pytest tests/integration/ -q                        # lifecycle + tenant isolation

# Finalne:
python -m pytest tests/ -q 2>&1 | tail -3
# Wynik: X passed, 0 failed, 0 errors
```

### TL_PROMPT

```bash
TL_PROMPT="Read ~/Projects/BreachForge/.workflow/skills/testing-lead.md and follow it.
Sprint: 79 - Test Suite Green
Changed: tests/unit/scripts/ (3 fix-y), tests/integration/test_scan_lifecycle.py, tests/integration/test_tenant_isolation.py
Test cases:
- python -m pytest tests/ --collect-only zwraca 0 ERROR linii
- test_benchmark_cli.py, test_benchmark_importers.py, test_miss_classifier.py przechodzą
- test_scan_lifecycle.py: scan create → queue → complete → report flow działa
- test_tenant_isolation.py: org A API key nie może dostać zasobów org B" bash ~/.claude/scripts/testing-lead-exec.sh < /dev/null
```

### Global acceptance criteria

- [ ] `python -m pytest tests/ --collect-only -q 2>&1 | grep "ERROR"` → 0 linii
- [ ] `python -m pytest tests/unit/scripts/ -q` → wszystkie zielone
- [ ] `tests/integration/test_scan_lifecycle.py` istnieje i przechodzi
- [ ] `tests/integration/test_tenant_isolation.py` istnieje i przechodzi (org isolation)
- [ ] `python -m pytest tests/ -q` → 0 failed, 0 errors
