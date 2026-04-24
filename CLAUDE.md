# ProofScan — CLAUDE.md

> Instrukcje projektowe dla Claude Code. Supplement do globalnego `~/.claude/CLAUDE.md` — tamto ma pierwszeństwo w regułach workflow. Tu są reguły specyficzne dla ProofScan.

---

## Stack

| Warstwa | Technologia |
|---------|-------------|
| API | Python 3.12 + FastAPI + uvicorn |
| Task queue | rq (Redis Queue) |
| Crawler / Auth | Playwright (Python) |
| Attack workers | httpx (stateless) |
| ORM | SQLAlchemy async + Alembic |
| DB | PostgreSQL (asyncpg driver) |
| Cache / Queue | Redis |
| Evidence store | AWS S3 (boto3) |
| Encryption | cryptography + KMS |
| Structured logs | structlog |
| Tests | pytest + pytest-asyncio |

Brak frontendu w v1 beta — output: JSON + Markdown.

---

## Podział pracy — ProofScan

Identyczny podział jak w globalnym CLAUDE.md. Różnice projektowe:

| Zadanie | Worker | Uwagi |
|---------|--------|-------|
| Nowy plik Python > 20 linii | codex-main | Default |
| Drugi plik równolegle | codex-dad | Split od 2 plików |
| Migracje Alembic | codex-dad | Zna schemat przez AGENTS.md |
| Playwright flows (auth, crawler) | codex-main | Złożone, wymaga kontekstu |
| Attack rules (nowa klasa) | codex-main + Claude approve | Wymaga proof signal spec |
| Validator strategies | codex-main + Claude approve | Proof-gate = krytyczne |
| Fixy < 10 linii | Claude | Edit tool |

### Ścieżki worker-dad

```bash
# codex-dad (WSL worker-dad)
DAD_PROMPT="..." bash ~/.claude/scripts/dad-exec.sh
# Ścieżki zawsze: /mnt/d/SimpliAppSec/...
```

---

## Weryfikacja po każdym tasku

```bash
# Minimalna weryfikacja (zawsze):
cd d:/SimpliAppSec && python -m pytest tests/unit/ -q

# Pełna weryfikacja (przed close):
python -m pytest tests/ -q
docker compose build --no-cache   # jeśli zmiany w Dockerfile
```

Analogia do `npx tsc --noEmit` w Simpli → tu: `pytest tests/unit/ -q`.

**WAŻNE — Python w bash shell:** Git bash nie rozwiązuje `python`/`python3` jako `.exe`. Zawsze używaj pełnej ścieżki:

```bash
"/c/Program Files/Python312/python.exe" -m pytest tests/unit/ -q
"/c/Program Files/Python312/python.exe" -m pytest tests/ -q
```

---

## Architektura — zasady odczytu

**NIGDY** nie czytaj `docs/architecture/` bezpośrednio przez Read — hook blokuje.
Zawsze przez dad summary:

```bash
DAD_PROMPT="Read /mnt/d/SimpliAppSec/docs/architecture/[plik].md. List ALL constraints and rules relevant to [feature]. Bullets. Max 20 lines." bash ~/.claude/scripts/dad-exec.sh
```

### Która doc do którego tematu

| Temat | Plik |
|-------|------|
| Auth, session, login flows | `auth-architecture.md` |
| Attack rules, scoring, planner | `attack-engine.md` |
| Validator, proof, confidence | `validation-model.md` |
| Data model, SQLAlchemy | `data-model.md` |
| PostgreSQL, Redis, S3, deployment | `storage-infra.md` |
| Scan isolation, credentials, rate limits | `security-constraints.md` |
| Dedup, proof-gate, noise | `noise-reduction.md` |

---

## Nienaruszalne invarianty (z ARCHITECTURE.md Section 3)

Te reguły muszą być sprawdzone przez Claude przed każdym ship/no-ship:

1. **Proof-gate** — `ProofArtifact.confidence_score >= 0.85` PRZED zapisem Finding. Zero wyjątków.
2. **Auth-first** — skan nie kontynuuje z expired session. Auth fail → pause z explicit error.
3. **Worker isolation** — workers piszą tylko do Redis Evidence Buffer. Nigdy bezpośrednio do DB lub S3.
4. **Dedup before write** — `FindingScorer` sprawdza fingerprint PRZED `db.add()`.
5. **No credentials in logs** — structlog musi mieć processor stripujący `Authorization`, `Cookie`, `password`.
6. **Redaction at export** — Evidence Store zapisuje pełne dane. Redakcja TYLKO w `ReportingService`.

---

## Wrażliwe domeny — Claude approves before ship

- `control_plane/auth_manager.py` — każda zmiana w session handling
- `execution_plane/validator/` — każda zmiana w proof threshold lub validation logic
- `control_plane/finding_scorer.py` — każda zmiana w dedup lub severity
- `storage/db/encryption.py` — envelope encryption (Sprint 9+)
- Każda zmiana `DEFAULT_PROOF_CONFIDENCE_THRESHOLD`

---

## Konwencje kodu (Python)

- Type hints wszędzie — `from __future__ import annotations` w każdym pliku
- Dataclasses dla data transfer objects (nie Pydantic wewnątrz execution plane)
- Pydantic tylko w `api/models/` (request/response schemas)
- `async def` wszędzie gdzie I/O
- Early returns, no deep nesting
- Pliki < 300 linii — sygnał do podziału
- Brak komentarzy opisujących CO — tylko DLACZEGO (nieoczywiste decyzje)

---

## Struktura projektu (skrócona)

```
proofscan/
├── api/                    # FastAPI app
├── control_plane/          # Orchestrator, AuthManager, FindingScorer, Reporting
├── execution_plane/
│   ├── crawler/            # Playwright recon
│   ├── planner/rules/      # Attack rule classes
│   ├── workers/            # Stateless httpx workers + supervisor
│   └── validator/strategies/  # Per-class proof validation
├── storage/
│   ├── db/                 # SQLAlchemy models + Alembic migrations
│   └── evidence/           # S3 store client
└── tests/
    ├── unit/
    ├── integration/
    └── corpus/             # Known-vulnerable app test cases
```

Pełna mapa modułów: `docs/ARCHITECTURE_IMPL.md`

---

## Sprint Plan

Szczegóły i gotowe prompty: `docs/SPRINT_PLAN.md`
