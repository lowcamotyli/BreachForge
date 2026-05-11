## Sprint 28 - Attack Chain Scoring & Corpus

**Goal:** Ocenic i raportowac cale lancuchy ataku, a nie tylko pojedyncze findingi.

Ten sprint zamyka wdrozenie "top attacker simulation": system potrafi pokazac entry point, pivot, exploit, impact, blast radius, confidence i bezpieczne dowody.

### Architektura - dokumenty referencyjne

```bash
DAD_PROMPT="Read /mnt/d/BreachForge/docs/architecture/validation-model.md and reporting-model.md. Extract constraints for proof confidence, dedup, severity scoring, evidence references, and report redaction. Bullets. Max 25 lines." bash ~/.claude/scripts/dad-exec.sh
```

### Workstream A - Attack Chain Model

| ID | Zadanie | Pliki | Testy | Definition of Done |
|---|---|---|---|---|
| A1 | Dodaj `AttackChain` model: entry, pivot, exploit, impact, identities, evidence_refs | `api/models/responses.py`, scorer helper | scorer/report tests | chain jest stabilny w JSON |
| A2 | Chain root-cause dedup | `control_plane/finding_scorer.py` | scorer tests | variants lacza sie pod root cause |
| A3 | Chain confidence: min proof gate + repeatability + differential support | scorer helper | unit tests | weak link obniza chain confidence |

### Workstream B - Severity & Explainability

| ID | Zadanie | Pliki | Testy | Definition of Done |
|---|---|---|---|---|
| B1 | Scoring: impact x reachability x privilege x repeatability x blast radius x safety confidence | `control_plane/finding_scorer.py` | scorer tests | score ma explanation factors |
| B2 | Severity upgrade/downgrade rules dla multi-step chains | scorer helper | unit tests | Critical wymaga real impact evidence |
| B3 | Report explanation: dlaczego chain jest wazny i co naprawic najpierw | `control_plane/reporting.py` | reporting tests | remediation jest root-cause oriented |

### Workstream C - Corpus

| ID | Zadanie | Pliki | Testy | Definition of Done |
|---|---|---|---|---|
| C1 | Corpus: BOLA read -> write candidate -> tenant impact | `tests/corpus/` | corpus tests | chain report generowany |
| C2 | Corpus: low privilege -> admin read -> blast radius | `tests/corpus/` | corpus tests | differential proof widoczny |
| C3 | Corpus: secret exposure -> accepted token -> privilege fingerprint -> remediation | `tests/corpus/` | corpus tests | integruje sprinty 17-23 |
| C4 | Corpus: workflow skip -> state delta -> reproducible impact | `tests/corpus/` | corpus tests | behavioral chain przechodzi |
| C5 | Corpus: negative controls for false positives | `tests/corpus/` | corpus tests | brak findingu bez proof-gate |

### Workstream D - Final Simulation Harness

| ID | Zadanie | Pliki | Testy | Definition of Done |
|---|---|---|---|---|
| D1 | Dodaj end-to-end red-team simulation command | `tests/corpus/` lub `scripts/` | CI smoke | uruchamia curated scenarios |
| D2 | CI gate dla playbook + hypothesis + differential + chain reporting | CI config | pipeline tests | regressions blokuja merge |
| D3 | Review-ready diff checklist dla attack intelligence | `docs/process/attack-intelligence-review.md` (new) | process review | Claude ma jasny ship-gate checklist |

### Guardrails

- Finding nadal wymaga proof-gate.
- Chain scoring nie moze ukrywac slabego dowodu pojedynczego kroku.
- Raport nie pokazuje sekretow, credentials ani nadmiarowego response body.
- Customer-facing remediation ma wskazywac root cause, nie tylko symptom endpointu.

### Weryfikacja

```bash
python -m pytest tests/unit/control_plane/ -q
python -m pytest tests/unit/execution_plane/validator/ -q
python -m pytest tests/corpus/ -q
python -m pytest tests/ -q
```

### Global acceptance criteria

- [ ] Raport pokazuje cale attack chains z evidence refs i scoring explanation.
- [ ] Minimum 5 corpus chains przechodzi end-to-end.
- [ ] Negative controls nie tworza findingow.
- [ ] Claude ship-gate checklist obejmuje P1..P6, redaction i worker isolation.

### Post-sprint: przeglad skillow

Czy pojawil sie nowy powtarzalny pattern? Jesli tak - zaktualizuj lub dodaj skill w `.workflow/skills/` przed zamknieciem sprintu. Regula: pattern >= 2x -> skodyfikuj.
