## Sprint 17 - Secret Intelligence Core

**Goal:** System rozumie znaleziony sekret bez ujawniania jego wartosci w DB, logach ani raporcie.

Ten sprint jest fundamentem dla wszystkich kolejnych secret-exposure sprintow: klasyfikuje sekret, dekoduje bezpieczne metadane i przygotowuje dane do blast-radius oraz raportowania.

### Architektura - dokumenty referencyjne

```bash
DAD_PROMPT="Read /mnt/d/SimpliAppSec/docs/architecture/security-constraints.md and validation-model.md. Extract constraints for secret classification, redaction, proof-gate, and EvidenceStore boundaries. Bullets. Max 25 lines." bash ~/.claude/scripts/dad-exec.sh
```

### Workstream A - Secret Classification

| ID | Zadanie | Pliki | Testy | Definition of Done |
|---|---|---|---|---|
| A1 | Dodaj `SecretClassifier` z typami: jwt, bearer, api_key, session_token, generic_secret | `execution_plane/validator/secret_intelligence.py` (new) | unit tests | klasyfikacja deterministyczna dla fixture'ow |
| A2 | Znormalizuj wynik do DTO/dataclass bez wartosci sekretu | `execution_plane/validator/secret_intelligence.py` | unit tests | DTO zawiera tylko typ, fingerprint, length bucket, entropy bucket |
| A3 | Dodaj safe fingerprint sekretu (np. hash prefix) bez mozliwosci odzyskania wartosci | `execution_plane/validator/secret_intelligence.py` | redaction tests | fingerprint pozwala deduplikowac, nie ujawnia sekretu |

### Workstream B - JWT Metadata

| ID | Zadanie | Pliki | Testy | Definition of Done |
|---|---|---|---|---|
| B1 | Dekoduj JWT header/payload bez walidowania podpisu jako zaufanej prawdy | `execution_plane/validator/secret_intelligence.py` | unit tests | parser nie rzuca na malformed JWT |
| B2 | Ekstrahuj `iss`, `aud`, `exp`, `iat`, `nbf`, `scope`, `scp`, `role`, `roles`, `sub`, `client_id` | classifier helper | unit tests | pola sa opcjonalne i redacted gdzie trzeba |
| B3 | Oblicz TTL oraz flagi: expired, long_lived, missing_exp | classifier helper | unit tests | TTL stabilny przy kontrolowanym `now` |

### Workstream C - Pipeline Integration

| ID | Zadanie | Pliki | Testy | Definition of Done |
|---|---|---|---|---|
| C1 | Podlacz klasyfikacje do `SensitiveExposureStrategy` dla proof artifact notes | `execution_plane/validator/strategies/sensitive_exposure.py` | validator tests | evidence_notes zawiera `secret_type`, `secret_fingerprint`, `ttl_bucket` |
| C2 | Upewnij sie, ze raw secret nie trafia do `FindingScorer` payload | `control_plane/finding_scorer.py` | scorer tests | artifact payload redacted |
| C3 | Dodaj sekcje "Secret Properties" do raportu | `control_plane/reporting.py` | reporting tests | raport pokazuje metadane, nie wartosc |

### Guardrails

- Raw secret moze istniec tylko w RawProbe/EvidenceStore zgodnie z obecna granica storage.
- Nie zapisuj plaintext secret w `AttackTask.hypothesis`, DB finding, logs, Markdown ani JSON report.
- JWT claims sa traktowane jako attacker-controlled metadata, nie jako potwierdzone fakty.
- Proof-gate zostaje bez zmian.

### Weryfikacja

```bash
python -m pytest tests/unit/execution_plane/validator/ -q
python -m pytest tests/unit/control_plane/test_reporting.py -q
python -m pytest tests/unit/ -q
```

### Global acceptance criteria

- [ ] System klasyfikuje minimum 5 typow sekretow.
- [ ] JWT metadata jest dostepne w raporcie bez wartosci tokena.
- [ ] Redaction tests potwierdzaja brak plaintext sekretu poza EvidenceStore.
- [ ] Istniejace sensitive exposure findingi zachowuja kompatybilnosc.

### Post-sprint: przeglad skillow

Czy pojawil sie nowy powtarzalny pattern? Jesli tak - zaktualizuj lub dodaj skill w `.workflow/skills/` przed zamknieciem sprintu. Regula: pattern >= 2x -> skodyfikuj.
