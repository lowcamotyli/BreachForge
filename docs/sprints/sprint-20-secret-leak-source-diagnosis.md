## Sprint 20 - Secret Leak Source Diagnosis

**Goal:** Powiedziec klientowi nie tylko, ze sekret wyciekl, ale skad i dlaczego.

Ten sprint klasyfikuje miejsce wycieku: response body, header, debug endpoint, config JSON, source map, stack trace, public asset albo unknown.

### Architektura - dokumenty referencyjne

```bash
DAD_PROMPT="Read /mnt/d/SimpliAppSec/docs/architecture/attack-engine.md and data-model.md. Extract endpoint/probe metadata useful for leak source diagnosis. Bullets. Max 25 lines." bash ~/.claude/scripts/dad-exec.sh
```

### Workstream A - Source Classifier

| ID | Zadanie | Pliki | Testy | Definition of Done |
|---|---|---|---|---|
| A1 | Dodaj `SecretLeakSourceClassifier` | `execution_plane/validator/secret_leak_source.py` (new) | unit tests | klasyfikuje podstawowe source types |
| A2 | Heurystyki URL: `/debug`, `/config`, `.map`, `/assets`, `/swagger`, `/openapi` | classifier | unit tests | URL hints dzialaja deterministycznie |
| A3 | Heurystyki content-type/body/header | classifier | unit tests | JSON/header/stack trace rozroznione |

### Workstream B - Pipeline Integration

| ID | Zadanie | Pliki | Testy | Definition of Done |
|---|---|---|---|---|
| B1 | Dolacz leak source do `SensitiveExposureStrategy` evidence notes | strategy | validator tests | artifact zawiera `leak_source` |
| B2 | Scorer przenosi leak source do finding metadata | `control_plane/finding_scorer.py` | scorer tests | finding ma source classification |
| B3 | Dedup uwzglednia root source bez rozbijania tego samego wycieku | scorer helper | scorer tests | podobne warianty lacza sie logicznie |

### Workstream C - Remediation Mapping

| ID | Zadanie | Pliki | Testy | Definition of Done |
|---|---|---|---|---|
| C1 | Guidance per source type | `control_plane/reporting.py` | reporting tests | debug/config/source-map maja konkretne rekomendacje |
| C2 | Dodaj "Leak Source" do raportu | reporting | reporting tests | klient widzi przyczyne i naprawe |
| C3 | JSON export zawiera source type i confidence | reporting JSON | tests | integracje moga uzyc source classification |

### Guardrails

- Nie parsuj ani nie renderuj wartosci sekretu w source diagnosis.
- Source classification ma confidence, bo czesc heurystyk jest probabilistyczna.
- Nie zmieniaj proof-gate; to tylko wzbogacenie findingu.

### Weryfikacja

```bash
python -m pytest tests/unit/execution_plane/validator/ -q
python -m pytest tests/unit/control_plane/test_reporting.py -q
python -m pytest tests/unit/ -q
```

### Global acceptance criteria

- [ ] Minimum 7 source types jest rozpoznawanych.
- [ ] Raport pokazuje root cause oraz remediation per source.
- [ ] Source confidence jest widoczny w JSON.
- [ ] Brak regresji w sensitive exposure proof.

### Post-sprint: przeglad skillow

Czy pojawil sie nowy powtarzalny pattern? Jesli tak - zaktualizuj lub dodaj skill w `.workflow/skills/` przed zamknieciem sprintu. Regula: pattern >= 2x -> skodyfikuj.
