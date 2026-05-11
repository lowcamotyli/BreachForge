## Sprint 39 - Business Logic Advanced

**Goal:** Wykrywanie zaawansowanych ataków na logike biznesowa: ujemne wartosci, przepelnienie liczb calkowitych, manipulacja cena/waluta, account enumeration przez timing, i reservoir-cancel exploit.

Ataki logiki biznesowej sa niewidoczne dla WAFow i skanerow generic. Wymagaja rozumienia semantyki aplikacji — ktora BreachForge buduje z AssetMap i flow hints.

### Architektura - dokumenty referencyjne

```bash
DAD_PROMPT="Read /mnt/d/BreachForge/docs/architecture/attack-engine.md and noise-reduction.md. Extract: business logic workflow detection, safe fixture rules for mutation probes, timing analysis constraints. Bullets. Max 25 lines." bash ~/.claude/scripts/dad-exec.sh
```

### Workstream A - Numeric & Price Attacks

| ID | Zadanie | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| A1 | Reguła numeric attacks: wykrywa parametry `price`, `amount`, `quantity`, `balance`, `credits`, `discount`, `fee` w write endpoints — generuje numeric manipulation candidates | `execution_plane/planner/rules/business_logic_advanced.py` (new) | **codex-dad** | planner tests | rule wykrywa numeric params z priorytetem medium-high |
| A2 | Strategia `negative_value_attack`: probe z `-1`, `-99999`, `-0.01` na numeric params — proof gdy serwer akceptuje (balance increases, negative cart total) | `execution_plane/validator/strategies/business_logic_advanced.py` (new) | **codex-dad** | validator tests | confidence 0.90 gdy response potwierdza akceptacje ujemnej wartosci |
| A3 | Strategia `integer_overflow`: probe `2147483648`, `9223372036854775807`, `99999999999` — proof przez unexpected state change lub error revealing type | `execution_plane/validator/strategies/business_logic_advanced.py` | **codex-dad** | validator tests | confidence 0.85 przy overflow behavior lub revealing error |
| A4 | Strategia `price_manipulation`: wysyla cene w innej jednostce — `0.01` gdzie aplikacja oczekuje `1.00` (cents vs dollars confusion) lub zmiana currency param `USD`→`JPY` | `execution_plane/validator/strategies/business_logic_advanced.py` | **codex-dad** | validator tests | proof przez unexpected accepted price; confidence 0.88 |
| A5 | Playbooki: negative value i price manipulation | `execution_plane/planner/playbooks/negative_value_attack.yaml`, `price_manipulation.yaml` (new) | codex-main | corpus tests | oba max_requests: 3, tylko safe fixtures |

### Workstream B - Account Enumeration & Reservation

| ID | Zadanie | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| B1 | Strategia `account_enumeration_timing`: mierzy response time dla istniejacych vs nieistniejacych usernames/emails — statystyczna roznica (> 2 sigma) = timing oracle | `execution_plane/validator/strategies/business_logic_advanced.py` | **codex-dad** | validator tests | min 10 probe par do statystyki; confidence 0.80 przy > 2 sigma delta |
| B2 | Strategia `inventory_reservation_exploit`: reserve→GET (confirm hold) → cancel → reserve (sprawdz czy mozna powtarzac bez limitu) | `execution_plane/validator/strategies/business_logic_advanced.py` | **codex-dad** | validator tests | cyclic reservation bez dekrementu inventory = confidence 0.87 |
| B3 | Reguła account enumeration: wykrywa `/login`, `/register`, `/forgot-password`, `/check-email` jako enumeration candidates | `execution_plane/planner/rules/business_logic_advanced.py` | **codex-dad** | planner tests | candidates generowane dla auth endpoints |
| B4 | Playbooki: account enumeration timing i reservation exploit | `execution_plane/planner/playbooks/account_enumeration_timing.yaml`, `inventory_reservation.yaml` (new) | codex-main | corpus tests | enumeration: min 10 probes; reservation: max 3 cycles |
| B5 | Rejestracja strategii | `execution_plane/validator/registry.py` (edit < 5 linii) | Claude | brak | klucze `negative_value`, `integer_overflow`, `price_manipulation`, `account_enumeration_timing`, `inventory_reservation` |

### Workstream C - Tests & Corpus

| ID | Zadanie | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| C1 | Unit testy wszystkich strategii: negative value accept, overflow behavior, price unit confusion, timing oracle, reservation cycle | `tests/unit/execution_plane/validator/test_business_logic_advanced_strategy.py` (new) | codex-main | pytest -q | coverage > 90% |
| C2 | Corpus: mock cart API z brakiem walidacji wartosci, mock auth z timing oracle, mock inventory | `tests/corpus/business_logic_corpus.py` (new) | codex-main | corpus tests | 5 findingow z roznymi confidence |

### Guardrails

- Negative value i price probes sa wykonywane TYLKO na safe fixtures — nie na prawdziwych produktach/platnosciach.
- Integer overflow probe: jesli aplikacja wykonuje przelewek/transfer, wymaga explicit `mutation_allowed: true`.
- Reservation exploit: max 3 cykle — nie wyczerpuje prawdziwego inventory.
- Timing oracle: minimum 10 par — zbyt malo prob = false positive. Uzywaj tylko read-only (login check bez faktycznego logowania).

### Weryfikacja

```bash
"/c/Program Files/Python312/python.exe" -m pytest tests/unit/execution_plane/validator/test_business_logic_advanced_strategy.py -q
"/c/Program Files/Python312/python.exe" -m pytest tests/unit/ -q
"/c/Program Files/Python312/python.exe" -m pytest tests/corpus/ -q
```

### Global acceptance criteria

- [ ] Negative value finding zawiera: endpoint, parametr, wartosc probe, zaakceptowany stan.
- [ ] Price manipulation finding zawiera: oryginalna cena, manipulowana, roznica.
- [ ] Timing oracle wymaga min 10 par i statystycznej walidacji przed findingiem.
- [ ] Reservation exploit nie wyczerpuje prawdziwych zasobow.
- [ ] Wszystkie write probes wymagaja safe fixture lub explicit allowlist.

### Podział pracy — codex-dad

Wiekszosc pracy (A1, A2, A3, A4, B1, B2, B3): codex-dad — kompleksowa logika + sensitive domain (price/payment params).
Playbooki i testy (A5, B4, C1, C2): codex-main.
Rejestracja (B5): Claude.

### Post-sprint: przeglad skillow

Czy pojawil sie nowy powtarzalny pattern? Jesli tak - zaktualizuj lub dodaj skill w `.workflow/skills/`. Regula: pattern >= 2x -> skodyfikuj.
