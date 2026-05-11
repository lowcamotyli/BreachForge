## Sprint 29 - JWT Attack Suite

**Goal:** Wykrywanie najczestszych luk w implementacjach JWT: alg:none, key confusion, claim manipulation, kid injection i expired token acceptance.

JWT to najczestszy wektor atakou na autentykacje w nowoczesnych API. Wiekszosc implementacji ma co najmniej jeden z tych defektow.

### Architektura - dokumenty referencyjne

```bash
DAD_PROMPT="Read /mnt/d/BreachForge/docs/architecture/auth-architecture.md and validation-model.md. Extract: session snapshot structure, proof types, confidence thresholds, writable credential rules. Bullets. Max 25 lines." bash ~/.claude/scripts/dad-exec.sh
```

### Workstream A - JWT Rule & Planner

| ID | Zadanie | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| A1 | Reguła wykrywająca endpointy z `Authorization: Bearer` + JWT decode (bez weryfikacji) do ekstrakcji claims | `execution_plane/planner/rules/jwt_attack.py` (new) | **codex-dad** | planner unit tests | rule zwraca candidate dla kazdego Bearer endpoint |
| A2 | Playbook alg:none — wysyla token z `"alg":"none"` i pusta sygnatura | `execution_plane/planner/playbooks/jwt_alg_none.yaml` (new) | codex-main | corpus tests | playbook ma safety budget max_requests: 2 |
| A3 | Playbook claim escalation — modyfikuje `role`/`scope`/`sub` w payload, zachowuje oryginalny alg | `execution_plane/planner/playbooks/jwt_claim_escalation.yaml` (new) | codex-main | corpus tests | playbook nie zapisuje zmodyfikowanych tokenow do logów |
| A4 | Playbook kid injection — testuje `kid` z wartosciami `../../etc/passwd`, `' OR 1=1--` | `execution_plane/planner/playbooks/jwt_kid_injection.yaml` (new) | codex-main | corpus tests | max_requests: 3, tylko read-only endpoints |

### Workstream B - Validator Strategy

| ID | Zadanie | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| B1 | Strategia `jwt_attack`: proof type `differential` — porownuje odpowiedz na manipulowany token vs baseline autentykowany | `execution_plane/validator/strategies/jwt_attack.py` (new) | **codex-dad** | validator unit + invariants | confidence >= 0.90 tylko przy body match >= 70% i status 200 |
| B2 | Detekcja expired JWT acceptance: token z `exp` w przeszlosci → sprawdz czy serwer odrzuca (401/403) | `execution_plane/validator/strategies/jwt_attack.py` | **codex-dad** | validator tests | expired token acceptance = 0.88 confidence |
| B3 | Rejestracja strategii w validatorze | `execution_plane/validator/registry.py` (edit, < 5 linii) | Claude | brak | strategy dostepna pod kluczem `jwt_attack` |

### Workstream C - Tests & Corpus

| ID | Zadanie | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| C1 | Unit testy strategii: alg:none hit, kid injection error response, expired acceptance, claim escalation | `tests/unit/execution_plane/validator/test_jwt_attack_strategy.py` (new) | codex-main | pytest -q | 100% scenariuszy pokrytych |
| C2 | Corpus fixture: mock JWT-vulnerable API zwracajace 200 na alg:none | `tests/corpus/jwt_attack_corpus.py` (new) | codex-main | corpus tests | fixture reprodukowalna deterministycznie |

### Guardrails

- JWT manipulation odbywa sie wylacznie na endpointach read-only lub safe fixtures — nigdy mutacja danych przez manipulowany token.
- Zmodyfikowane tokeny nie sa zapisywane w EvidenceStore (tylko proof artifact — typ anomalii + status code diff).
- kid injection payloady sa ograniczone do znanych-bezpiecznych pattern (path traversal, SQL — bez RCE payloadow).
- Proof gate: 0.90 dla alg:none/claim, 0.88 dla expired acceptance.

### Weryfikacja

```bash
"/c/Program Files/Python312/python.exe" -m pytest tests/unit/execution_plane/validator/test_jwt_attack_strategy.py -q
"/c/Program Files/Python312/python.exe" -m pytest tests/unit/execution_plane/planner/ -q
"/c/Program Files/Python312/python.exe" -m pytest tests/corpus/ -q
"/c/Program Files/Python312/python.exe" -m pytest tests/unit/ -q
```

### Global acceptance criteria

- [ ] Rule wykrywa Bearer endpoints i generuje JWT attack candidates.
- [ ] Strategia waliduje alg:none, claim escalation i expired acceptance.
- [ ] Zmodyfikowane tokeny nigdy nie zawieraja oryginalnych credentials w logach.
- [ ] Confidence >= 0.90 dla alg:none przy body match.
- [ ] Wszystkie 4 playbooki maja safety budget i nie modyfikuja stanu aplikacji.

### Podział pracy — codex-dad

Wiekszosc pracy (A1, B1, B2): codex-dad jako sensitive domain (validator/auth).
Playbooki YAML i testy (A2–A4, C1, C2): codex-main.
Rejestracja (B3): Claude bezposrednio.

### Post-sprint: przeglad skillow

Czy pojawil sie nowy powtarzalny pattern? Jesli tak - zaktualizuj lub dodaj skill w `.workflow/skills/`. Regula: pattern >= 2x -> skodyfikuj.
