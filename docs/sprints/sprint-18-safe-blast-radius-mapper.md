## Sprint 18 - Safe Blast Radius Mapper

**Goal:** Sprawdzic, gdzie znaleziony sekret jest akceptowany, bez masowego pobierania danych i bez mutacji.

Ten sprint rozszerza `impact_secret_replay` w kontrolowana mape zasiegu: kilka read-only endpointow, status matrix i jasny dowod dla klienta.

### Architektura - dokumenty referencyjne

```bash
DAD_PROMPT="Read /mnt/d/SimpliAppSec/docs/architecture/attack-engine.md and security-constraints.md. Extract constraints for scoped read-only replay, rate limits, and worker isolation. Bullets. Max 25 lines." bash ~/.claude/scripts/dad-exec.sh
```

### Workstream A - Endpoint Selection

| ID | Zadanie | Pliki | Testy | Definition of Done |
|---|---|---|---|---|
| A1 | Dodaj selector read-only endpointow z `AssetMap` | `execution_plane/planner/secret_blast_radius.py` (new) | planner tests | wybiera tylko GET/HEAD/OPTIONS |
| A2 | Priorytety: source endpoint, `/me`, `/profile`, `/user`, `/account`, `/settings`, `/appointments`, `/admin` | selector | unit tests | ranking deterministyczny |
| A3 | Limit requestow per secret, domyslnie 8 | selector/dispatcher | unit tests | cap nie do obejscia przez duza mape |

### Workstream B - Replay Execution

| ID | Zadanie | Pliki | Testy | Definition of Done |
|---|---|---|---|---|
| B1 | Dodaj follow-up `impact_secret_blast_radius` | `execution_plane/workers/dispatcher.py` | worker tests | tworzy bounded task set |
| B2 | Wykonuj replay tylko read-only, in-scope i rate-limited | `execution_plane/workers/attack_worker.py` | guardrail tests | mutating/out-of-scope fail-closed |
| B3 | Dodaj response size cap dla blast-radius probes | worker helper | worker tests | duze body jest przycinane albo body omitted |

### Workstream C - Result Model

| ID | Zadanie | Pliki | Testy | Definition of Done |
|---|---|---|---|---|
| C1 | Zapisz matrix: endpoint, method, status, content_type, response_size, auth_accepted | `control_plane/finding_scorer.py`, report DTO | scorer tests | matrix trafia do finding metadata |
| C2 | Oznacz accepted tylko dla 2xx/3xx zgodnie z polityka | scoring helper | unit tests | 401/403 nie podbijaja impact |
| C3 | Renderuj "Secret Blast Radius" w Markdown/JSON | `control_plane/reporting.py` | reporting tests | tabela bez sekretu |

### Guardrails

- Max 8 requestow per sekret, konfigurowalne przez env z gornym clampem.
- Tylko `GET`, `HEAD`, `OPTIONS`.
- Brak body requestu dla secret replay.
- Brak masowego harvestingu danych; response body nie jest potrzebne do matrix.

### Weryfikacja

```bash
python -m pytest tests/unit/execution_plane/workers/ -q
python -m pytest tests/unit/execution_plane/planner/ -q
python -m pytest tests/unit/ -q
```

### Global acceptance criteria

- [ ] Secret blast radius matrix powstaje dla aktywnego sekretu.
- [ ] Limity requestow i metody read-only sa egzekwowane testami.
- [ ] Raport pokazuje zasieg bez ujawniania sekretu.
- [ ] Brak regresji dla pojedynczego `impact_secret_replay`.

### Post-sprint: przeglad skillow

Czy pojawil sie nowy powtarzalny pattern? Jesli tak - zaktualizuj lub dodaj skill w `.workflow/skills/` przed zamknieciem sprintu. Regula: pattern >= 2x -> skodyfikuj.
