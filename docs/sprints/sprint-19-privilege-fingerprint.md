## Sprint 19 - Privilege Fingerprint

**Goal:** Okreslic minimalny obserwowany poziom uprawnien sekretu bez wykonywania operacji mutujacych.

Ten sprint zmienia status matrix z Sprintu 18 w zrozumialy dla klienta opis: anonymous, user, elevated user, admin, service albo unknown.

### Architektura - dokumenty referencyjne

```bash
DAD_PROMPT="Read /mnt/d/BreachForge/docs/architecture/auth-architecture.md and validation-model.md. Extract constraints for identity context, proof confidence, and role inference. Bullets. Max 25 lines." bash ~/.claude/scripts/dad-exec.sh
```

### Workstream A - Fingerprint Model

| ID | Zadanie | Pliki | Testy | Definition of Done |
|---|---|---|---|---|
| A1 | Dodaj `PrivilegeFingerprint` DTO/dataclass | `execution_plane/validator/secret_intelligence.py` | unit tests | model ma level, confidence, evidence |
| A2 | Heurystyki statusow `200/401/403/404` | fingerprint helper | unit tests | accepted/rejected sa rozroznione |
| A3 | Heurystyki po endpointach `/admin`, `/settings`, `/billing`, `/users` | fingerprint helper | unit tests | endpoint hints wplywaja na inference |

### Workstream B - Claim & Scope Hints

| ID | Zadanie | Pliki | Testy | Definition of Done |
|---|---|---|---|---|
| B1 | Mapuj JWT `scope/scp/role/roles` do hints | classifier/fingerprint | unit tests | claims sa opisane jako untrusted hints |
| B2 | Rozroznij observed access od inferred privilege | scorer/report model | scorer tests | raport nie miesza faktow z inferencja |
| B3 | Confidence scoring dla privilege fingerprint | helper | unit tests | confidence deterministyczny |

### Workstream C - Reporting Integration

| ID | Zadanie | Pliki | Testy | Definition of Done |
|---|---|---|---|---|
| C1 | Dodaj fingerprint do finding metadata | `control_plane/finding_scorer.py` | scorer tests | finding zawiera `observed_access_level` |
| C2 | Renderuj "Privilege Fingerprint" | `control_plane/reporting.py` | reporting tests | widac level, confidence, evidence |
| C3 | Dodaj remediation pod nadmierne scope/uprawnienia | reporting guidance | reporting tests | guidance zalezy od level |

### Guardrails

- Claims JWT sa tylko hintami, nie dowodem uprawnien.
- Uprawnienia wynikaja przede wszystkim z odpowiedzi endpointow read-only.
- Brak eskalacji do mutacji w celu potwierdzenia roli.

### Weryfikacja

```bash
python -m pytest tests/unit/execution_plane/validator/ -q
python -m pytest tests/unit/control_plane/ -q
python -m pytest tests/unit/ -q
```

### Global acceptance criteria

- [ ] Raport pokazuje observed vs inferred privilege.
- [ ] Admin/service hints podbijaja impact tylko przy supporting evidence.
- [ ] Testy obejmuja role z JWT i endpointy `/admin`.
- [ ] Brak plaintext sekretow w fingerprint metadata.

### Post-sprint: przeglad skillow

Czy pojawil sie nowy powtarzalny pattern? Jesli tak - zaktualizuj lub dodaj skill w `.workflow/skills/` przed zamknieciem sprintu. Regula: pattern >= 2x -> skodyfikuj.
