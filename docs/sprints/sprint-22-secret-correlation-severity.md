## Sprint 22 - Secret Correlation & Severity Upgrade

**Goal:** Korelowac aktywny sekret z innymi sygnalami, aby severity bylo wyjasnialne i uczciwe.

Ten sprint nie dodaje nowych atakow. Dodaje warstwe decyzyjna: kiedy sensitive exposure jest High/Critical i dlaczego.

### Architektura - dokumenty referencyjne

```bash
DAD_PROMPT="Read /mnt/d/BreachForge/docs/architecture/validation-model.md and noise-reduction.md. Extract constraints for severity, dedup, correlation, and false-positive control. Bullets. Max 25 lines." bash ~/.claude/scripts/dad-exec.sh
```

### Workstream A - Correlation Engine

| ID | Zadanie | Pliki | Testy | Definition of Done |
|---|---|---|---|---|
| A1 | Dodaj `SecretExposureCorrelator` | `control_plane/secret_correlation.py` (new) | unit tests | korelacje sa deterministyczne |
| A2 | Korelacja: unauthenticated exposure + active replay | correlator/scorer | scorer tests | severity upgrade z uzasadnieniem |
| A3 | Korelacja: active secret + broad blast radius | correlator/scorer | scorer tests | blast radius podbija impact |
| A4 | Korelacja: active secret + permissive CORS/cache headers | correlator/scorer | scorer tests | dodatkowe ryzyko exfiltration/cache |

### Workstream B - Severity Rules

| ID | Zadanie | Pliki | Testy | Definition of Done |
|---|---|---|---|---|
| B1 | Zdefiniuj reguly High/Critical dla secret exposure | `control_plane/finding_scorer.py` | unit tests | severity ma explanation |
| B2 | Zachowaj kompatybilnosc ze starym scoringiem | scorer | regression tests | stare findingi nie degraduja przypadkowo |
| B3 | Dodaj noise guard przeciw single weak signal upgrade | correlator | unit tests | jedna slaba heurystyka nie robi Critical |

### Workstream C - Report Explanation

| ID | Zadanie | Pliki | Testy | Definition of Done |
|---|---|---|---|---|
| C1 | Renderuj "Why Severity Is High/Critical" | `control_plane/reporting.py` | reporting tests | raport pokazuje konkretne sygnaly |
| C2 | JSON export `severity_factors` | reporting JSON | tests | kazdy factor ma source i confidence |
| C3 | Dodaj remediation priority | reporting | tests | klient wie, co robic pierwsze |

### Guardrails

- Severity upgrade musi miec supporting evidence.
- Nie podbijaj severity tylko przez nazwe endpointu lub sam claim JWT.
- Correlation nie moze tworzyc findingu bez proof-gate.

### Weryfikacja

```bash
python -m pytest tests/unit/control_plane/ -q
python -m pytest tests/unit/ -q
```

### Global acceptance criteria

- [ ] High/Critical secret exposure ma jawne severity factors.
- [ ] Broad blast radius i active replay podbijaja impact tylko z dowodem.
- [ ] False-positive guard ma testy.
- [ ] Raport zawiera czytelne uzasadnienie severity.

### Post-sprint: przeglad skillow

Czy pojawil sie nowy powtarzalny pattern? Jesli tak - zaktualizuj lub dodaj skill w `.workflow/skills/` przed zamknieciem sprintu. Regula: pattern >= 2x -> skodyfikuj.
