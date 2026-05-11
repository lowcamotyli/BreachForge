## Sprint 36 - XXE & Insecure Deserialization

**Goal:** Wykrywanie XXE w endpointach konsumujacych XML oraz sygnaly insecure deserialization w endpointach przyjmujacych serialized objects (Java, Python pickle, YAML, PHP).

XXE jest nadal aktywna w aplikacjach przetwarzajacych XML (SAML, DOCX/XLSX upload, SOAP). Deserialization to wektor RCE w starszych Javowych systemach.

### Architektura - dokumenty referencyjne

```bash
DAD_PROMPT="Read /mnt/d/BreachForge/docs/architecture/attack-engine.md and security-constraints.md. Extract: proof types for file read signals, timing proof mechanics, OOB dependency notes, safe payload rules. Bullets. Max 25 lines." bash ~/.claude/scripts/dad-exec.sh
```

### Workstream A - XXE

| ID | Zadanie | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| A1 | Reguła XXE: wykrywa endpointy z `Content-Type: application/xml`, `text/xml`, `application/soap+xml`, oraz file upload z `.docx`, `.xlsx`, `.svg`, `.xsd` | `execution_plane/planner/rules/xxe.py` (new) | **codex-dad** | planner tests | rule klasyfikuje XML endpoints i upload endpoints jako XXE candidates |
| A2 | Strategia `xxe_classic`: wstrzykuje `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>` — proof gdy response zawiera `root:`, `daemon:`, `nobody:` lub unix user patterns | `execution_plane/validator/strategies/xxe.py` (new) | **codex-dad** | validator tests | confidence 0.95 przy file content hit |
| A3 | Strategia `xxe_error`: wstrzykuje nieprawidlowy SYSTEM URI — proof gdy error message ujawnia sciezke systemowa lub "XML parser" internals | `execution_plane/validator/strategies/xxe.py` | **codex-dad** | validator tests | confidence 0.80 przy path disclosure w error |
| A4 | Blind XXE (timing): wstrzykuje SYSTEM URL do kontrolowanego hosta — timing delta > 2s jako low-confidence sygnał; pełna wersja wymaga Sprint 43 OOB | `execution_plane/validator/strategies/xxe.py` | **codex-dad** | validator tests | blind xxe max confidence 0.65 bez OOB |
| A5 | Playbook XXE classic + error | `execution_plane/planner/playbooks/xxe_classic.yaml` (new) | codex-main | corpus tests | max_requests: 2 (baseline, xxe probe) |

### Workstream B - Insecure Deserialization

| ID | Zadanie | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| B1 | Reguła deserialization: wykrywa `Content-Type: application/x-java-serialized-object`, `application/x-www-form-urlencoded` z base64 blobs, `Content-Type: application/octet-stream`, YAML endpoints | `execution_plane/planner/rules/deserialization.py` (new) | **codex-dad** | planner tests | Content-Type i base64 blob detection |
| B2 | Strategia `deserialization_probe`: wysyla zmodyfikowany serialized object (bit flip w magic bytes, truncated payload) — proof przez error message ujawniajacy serialization framework | `execution_plane/validator/strategies/deserialization.py` (new) | **codex-dad** | validator tests | Java: `java.io.IOException`, Python: `pickle.UnpicklingError` w response = 0.85 |
| B3 | YAML deserialization detection: probe `!!python/object/apply:os.getpid []` — TYLKO detection przez error/timeout, nie execution | `execution_plane/validator/strategies/deserialization.py` | **codex-dad** | validator tests | probe jest bezpieczny — `os.getpid` nie ma skutkow ubocznych; confidence przy timeout = 0.72 |
| B4 | Playbook deserialization probe | `execution_plane/planner/playbooks/deserialization_probe.yaml` (new) | codex-main | corpus tests | max_requests: 2, timeout guard 3s |
| B5 | Rejestracja strategii | `execution_plane/validator/registry.py` (edit < 5 linii) | Claude | brak | klucze `xxe_classic`, `xxe_error`, `xxe_blind`, `deserialization_probe` |

### Workstream C - Tests & Corpus

| ID | Zadanie | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| C1 | Unit testy XXE: file content hit, error path disclosure, blind timing | `tests/unit/execution_plane/validator/test_xxe_strategy.py` (new) | codex-main | pytest -q | coverage > 90% |
| C2 | Unit testy deserialization: framework error, yaml timeout, truncated blob | `tests/unit/execution_plane/validator/test_deserialization_strategy.py` (new) | codex-main | pytest -q | coverage > 90% |
| C3 | Corpus: mock XML endpoint z DTD processing enabled | `tests/corpus/xxe_corpus.py` (new) | codex-main | corpus tests | hit na `/etc/passwd` fixture |

### Guardrails

- XXE payloady probe TYLKO `/etc/passwd` i `/etc/hostname` — nie probuje kluczy SSH, shadow, certificates.
- Deserialization probe uzywa truncated/malformed payloadow — NIGDY payloadow powodujacych execution (ysoserial gadgets, RCE pickle).
- YAML probe uzywa wylacznie `os.getpid` (read-only, brak skutkow ubocznych).
- Blind XXE confidence jest cappowana na 0.65 bez OOB infrastruktury.

### Weryfikacja

```bash
"/c/Program Files/Python312/python.exe" -m pytest tests/unit/execution_plane/validator/test_xxe_strategy.py -q
"/c/Program Files/Python312/python.exe" -m pytest tests/unit/execution_plane/validator/test_deserialization_strategy.py -q
"/c/Program Files/Python312/python.exe" -m pytest tests/unit/ -q
"/c/Program Files/Python312/python.exe" -m pytest tests/corpus/ -q
```

### Global acceptance criteria

- [ ] XXE rule wykrywa XML Content-Type i upload endpoints.
- [ ] XXE classic: file content hit = 0.95 confidence.
- [ ] Deserialization: framework error message = 0.85 confidence.
- [ ] YAML probe nie powoduje OS execution (tylko getpid).
- [ ] Zaden payload nie jest RCE — detection only.
- [ ] Blind XXE bez OOB capped na 0.65.

### Podział pracy — codex-dad

Wiekszosc pracy (A1, A2, A3, A4, B1, B2, B3): codex-dad — sensitive domain (XXE file read, deserialization detection).
Playbooki i testy (A5, B4, C1, C2, C3): codex-main.
Rejestracja (B5): Claude.

### Post-sprint: przeglad skillow

Czy pojawil sie nowy powtarzalny pattern? Jesli tak - zaktualizuj lub dodaj skill w `.workflow/skills/`. Regula: pattern >= 2x -> skodyfikuj.
