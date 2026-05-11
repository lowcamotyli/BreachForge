## Sprint 48 - Finding Metadata Persistence

**Goal:** Utrwalic metadata findingow: severity factors, privilege fingerprint, leak source, blast radius i chain root cause nie moga znikac po reloadzie DB.

### Architektura - dokumenty referencyjne

```bash
DAD_PROMPT="cd /mnt/d/BreachForge && Read docs/architecture/data-model.md and docs/architecture/storage-infra.md. Extract: Finding/ProofArtifact schema, reporting metadata expectations, Alembic migration constraints. Bullets. Max 25 lines." bash ~/.claude/scripts/dad-exec.sh
```

### Workstream A - DB schema

| ID | Zadanie | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| A1 | Dodac mapped column dla metadata findingu jako `extra_metadata`, DB column `metadata` JSON | `storage/db/models.py` | codex-dad | model tests | metadata jest mapowane przez SQLAlchemy |
| A2 | Alembic migration dodajaca `findings.metadata` z default `{}` | `storage/db/migrations/versions/*.py` | codex-dad | migration smoke | upgrade tworzy kolumne |
| A3 | Uniknac konfliktu z SQLAlchemy `metadata` na klasie modelu | `storage/db/models.py` | codex-dad | import tests | `Base.metadata` dalej dziala |

### Workstream B - Scorer/reporting consistency

| ID | Zadanie | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| B1 | Ujednolicic zapisy `finding.metadata`/`finding.extra_metadata` w scorerze | `control_plane/finding_scorer.py` | codex-main | scorer tests | metadata jest zapisana do kolumny |
| B2 | Ujednolicic odczyty w raportowaniu i chain builderze | `control_plane/reporting.py`, `control_plane/attack_chain_builder.py` | codex-main | reporting tests | raport widzi metadata po reloadzie |
| B3 | Dodac helper `_finding_metadata()` zamiast rozproszonych `getattr` | `control_plane/reporting.py`, `control_plane/finding_scorer.py` | codex-main | unit tests | brak duplikacji i silent fallbackow |

### Workstream C - Regression tests

| ID | Zadanie | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| C1 | Test: score artifact -> commit -> reload -> metadata nadal istnieje | `tests/unit/control_plane/test_finding_scorer_*.py` | codex-main | pytest | privilege/leak/source factors persistuja |
| C2 | Test: report zawiera `secret_blast_radius_matrix` po reloadzie | `tests/unit/control_plane/test_reporting.py` | codex-main | pytest | report nie zalezy od transient attrs |
| C3 | Test migration model import | `tests/unit/storage/` | codex-main | pytest | model + migration kompatybilne |

### Guardrails

- Nie uzywac transient atrybutow jako zrodla prawdy dla raportu.
- Nie logowac raw sekretow w metadata.
- Migration wymaga review Claude przed ship, bo dotyka DB.

### Weryfikacja

```bash
python -m pytest tests/unit/control_plane/test_finding_scorer_redaction.py -q
python -m pytest tests/unit/control_plane/test_reporting.py -q
python -m pytest tests/unit/storage/ -q
python -m pytest tests/unit/ -q
```

### Global acceptance criteria

- [ ] Finding ma trwale metadata w DB.
- [ ] Severity factors, leak source i privilege fingerprint przezywaja reload.
- [ ] Report nie opiera sie na transient ORM attributes.
- [ ] Alembic upgrade jest jawny i review-ready.

### Podzial pracy - codex-dad

A1-A3 ida do **codex-dad** jako DB/migration safe package. B-C robi **codex-main** po review diffu migracji.
