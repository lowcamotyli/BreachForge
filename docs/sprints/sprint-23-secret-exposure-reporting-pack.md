## Sprint 23 - Secret Exposure Reporting & Evidence Pack

**Goal:** Dostarczyc klientowi kompletna historie ataku i plan naprawczy dla secret exposure.

Ten sprint laczy wyniki Sprintow 17-22 w finalny, customer-grade raport: discovered secret -> classified -> replayed safely -> blast radius -> privilege -> lifecycle -> remediation.

### Architektura - dokumenty referencyjne

```bash
DAD_PROMPT="Read /mnt/d/BreachForge/docs/architecture/security-constraints.md and data-model.md. Extract reporting constraints for redaction, EvidenceStore, JSON/Markdown export, and auditability. Bullets. Max 25 lines." bash ~/.claude/scripts/dad-exec.sh
```

### Workstream A - Narrative Model

| ID | Zadanie | Pliki | Testy | Definition of Done |
|---|---|---|---|---|
| A1 | Dodaj model narracji secret exposure | `control_plane/reporting.py`, optional helper | reporting tests | raport ma spojna sekwencje etapow |
| A2 | Polacz: properties, replay, blast radius, privilege, source, lifecycle, severity | reporting helper | tests | brak pustych/duplikowanych sekcji |
| A3 | Evidence references bez secret value | reporting | redaction tests | referencje sa audytowalne i bezpieczne |

### Workstream B - Markdown Report

| ID | Zadanie | Pliki | Testy | Definition of Done |
|---|---|---|---|---|
| B1 | Sekcja executive summary dla secret exposure | `control_plane/reporting.py` | snapshot tests | nietechniczny opis impactu |
| B2 | Sekcja technical appendix z redacted matrix | reporting | tests | endpoint matrix i factors widoczne |
| B3 | Sekcja remediation plan z priorytetami | reporting | tests | rotate/revoke/scope/source/cache/CORS |

### Workstream C - JSON Export

| ID | Zadanie | Pliki | Testy | Definition of Done |
|---|---|---|---|---|
| C1 | JSON schema dla secret exposure evidence pack | `api/models/responses.py` lub reporting schema | tests | stabilne pola dla integracji |
| C2 | Export `secret_properties`, `blast_radius`, `privilege`, `lifecycle`, `severity_factors` | reporting JSON | tests | kompletne bez plaintext sekretu |
| C3 | Compatibility dla starych findingow bez nowych metadanych | reporting | regression tests | brak crashy na partial data |

### Workstream D - End-to-End Corpus

| ID | Zadanie | Pliki | Testy | Definition of Done |
|---|---|---|---|---|
| D1 | Corpus scenario: unauthenticated config leaks active JWT | `tests/corpus/` | corpus tests | end-to-end raport generowany |
| D2 | Corpus scenario: API key accepted on narrow endpoint only | `tests/corpus/` | corpus tests | blast radius narrow |
| D3 | Corpus scenario: active secret + broad admin read access | `tests/corpus/` | corpus tests | severity High/Critical wyjasnione |

### Guardrails

- Raport nigdy nie pokazuje sekretu.
- Evidence pack ma byc uzyteczny dla remediation, nie do naduzycia.
- JSON export jest stabilny i wstecznie kompatybilny.

### Weryfikacja

```bash
python -m pytest tests/unit/control_plane/test_reporting.py -q
python -m pytest tests/unit/ -q
python -m pytest tests/corpus/ -q
```

### Global acceptance criteria

- [ ] Raport pokazuje pelna historie secret exposure.
- [ ] Markdown i JSON maja redaction coverage.
- [ ] Minimum 3 corpus scenariusze secret exposure przechodza end-to-end.
- [ ] Klient dostaje konkretny, priorytetyzowany plan naprawczy.

### Post-sprint: przeglad skillow

Czy pojawil sie nowy powtarzalny pattern? Jesli tak - zaktualizuj lub dodaj skill w `.workflow/skills/` przed zamknieciem sprintu. Regula: pattern >= 2x -> skodyfikuj.
