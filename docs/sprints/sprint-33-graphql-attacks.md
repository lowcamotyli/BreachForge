## Sprint 33 - GraphQL Attack Surface

**Goal:** Wykrywanie luk specyficznych dla GraphQL: introspection w produkcji, batch query amplification, query depth abuse, alias-based rate limit bypass i field suggestion exploitation.

GraphQL zmienia model autoryzacji z resource-level na field-level — wiekszosc testow HTTP nie lapie tych lukow. Introspection to "darmowy recon" dla atakujacego.

### Architektura - dokumenty referencyjne

```bash
DAD_PROMPT="Read /mnt/d/BreachForge/docs/architecture/attack-engine.md and validation-model.md. Extract: crawler asset map structure, how HTTP content-type endpoints are tagged, proof types for information disclosure. Bullets. Max 25 lines." bash ~/.claude/scripts/dad-exec.sh
```

### Workstream A - GraphQL Parser & Rule

| ID | Zadanie | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| A1 | GraphQL endpoint detector: wykrywa `/graphql`, `/api/graphql`, `/gql`, `Content-Type: application/graphql` w AssetMap | `execution_plane/crawler/graphql_parser.py` (new) | **codex-dad** | crawler unit tests | wykrywa endpoint i oznacza go `graphql: true` w AssetMap |
| A2 | Schema extractor: wysyla introspection query `{__schema{types{name}}}` i parsuje typy/pola/mutations | `execution_plane/crawler/graphql_parser.py` | **codex-dad** | parser tests | schema dostepna jako dict types→fields→args |
| A3 | Reguła GraphQL — generuje candidates dla: introspection, batch, depth, alias-bypass | `execution_plane/planner/rules/graphql.py` (new) | **codex-dad** | planner unit tests | 4 typy kandydatow generowane jesli endpoint GraphQL |
| A4 | Playbook introspection — sprawdza introspection w produkcji i mapuje sensitive types | `execution_plane/planner/playbooks/graphql_introspection.yaml` (new) | codex-main | corpus tests | max_requests: 1, read-only |
| A5 | Playbook batch amplification — `[{q: A} x 20]` przez jeden request, sprawdza czy rate limit omijany | `execution_plane/planner/playbooks/graphql_batch_amplification.yaml` (new) | codex-main | corpus tests | max_batch_size: 20, bezpieczne query (tylko __typename) |
| A6 | Playbook query depth — query 10 poziomow glebokosci via fragmenty (tylko read types) | `execution_plane/planner/playbooks/graphql_query_depth.yaml` (new) | codex-main | corpus tests | max_depth: 10, timeout guard |

### Workstream B - GraphQL Validator Strategy

| ID | Zadanie | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| B1 | Strategia `graphql_introspection`: proof `absolute` — response zawiera `__schema` lub `__type` = introspection enabled; confidence 0.95 | `execution_plane/validator/strategies/graphql.py` (new) | **codex-dad** | validator tests | disabled introspection = confidence 0 |
| B2 | Strategia `graphql_batch`: proof `differential` — response na 20x batch request vs 1x request; rate limit bypass jesli batch zwraca N responses bez 429 | `execution_plane/validator/strategies/graphql.py` | **codex-dad** | validator tests | confidence 0.88 przy N=20 responses bez throttle |
| B3 | Strategia `graphql_field_suggestion`: proof `absolute` — error message zawiera `Did you mean` + pole ktore nie jest w spec = information disclosure | `execution_plane/validator/strategies/graphql.py` | **codex-dad** | validator tests | confidence 0.85 przy field suggestion w error |
| B4 | Rejestracja strategii | `execution_plane/validator/registry.py` (edit < 5 linii) | Claude | brak | klucze `graphql_*` dostepne |

### Workstream C - Tests & Corpus

| ID | Zadanie | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| C1 | Unit testy: introspection hit, batch N-response, field suggestion, depth timeout signal | `tests/unit/execution_plane/validator/test_graphql_strategy.py` (new) | codex-main | pytest -q | scenariusze pokryte |
| C2 | Corpus: mock GraphQL server z introspection enabled i batch bez rate limit | `tests/corpus/graphql_corpus.py` (new) | codex-main | corpus tests | finding dla obu wektorow |

### Workstream D - No-Auth Coverage

| ID | Zadanie | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| D1 | `requires_auth: False` dla graphql rules — introspection, batch, field_suggestion sa czesto dostepne bez sesji | `execution_plane/planner/rules/graphql.py` (dodaj atrybut) | Claude | brak | 3 z 4 graphql rules maja `requires_auth = False` |
| D2 | Unauth-first introspection: GraphQL introspection jest ZAWSZE probowana najpierw bez credentials — nawet gdy sesja istnieje (mozliwe ze anon dostep ujawnia wiecej) | `execution_plane/validator/strategies/graphql.py` (edit probe order) | **codex-dad** | validator tests | unauth introspection probe przed auth probe |
| D3 | OpenAPI → GraphQL: jesli spec import (Sprint 44) ujawnial endpoint `/graphql` — automatycznie generuje introspection candidate bez recon phase | `execution_plane/planner/rules/graphql.py` | **codex-dad** | planner tests | spec-sourced GraphQL endpoint = candidate bez crawl |
| D4 | JS bundle GraphQL endpoint discovery: `graphql_parser.py` szuka `apolloClient`, `graphqlEndpoint`, `gqlUrl` w JS bundlach | `execution_plane/crawler/graphql_parser.py` (edit) | **codex-dad** | crawler tests | JS-discovered GraphQL endpoints w AssetMap |

> **Zaleznosc:** D3 wymaga Sprint 44 (OpenAPI import). D4 wymaga Sprint 44 (JS mining). D1/D2 niezalezne.

### Guardrails

- Batch query uzywa TYLKO read-only operacji (`query`, nigdy `mutation`) i tylko `__typename` lub inne nieszkodliwe pola.
- Query depth probe ma timeout guard — jesli serwer nie odpowie w 5s = odnotuj jako potential DoS risk, nie retry.
- Introspection query jest wysylana raz per GraphQL endpoint, bez powtorzen.
- Field suggestion probe uzywa losowych, nieistotnych nazw pol — nie zgaduje prawdziwych nazw wrażliwych pol.

### Weryfikacja

```bash
"/c/Program Files/Python312/python.exe" -m pytest tests/unit/execution_plane/validator/test_graphql_strategy.py -q
"/c/Program Files/Python312/python.exe" -m pytest tests/unit/execution_plane/planner/ -q
"/c/Program Files/Python312/python.exe" -m pytest tests/corpus/ -q
"/c/Program Files/Python312/python.exe" -m pytest tests/unit/ -q
```

### Global acceptance criteria

- [ ] Crawler wykrywa GraphQL endpoints i ekstrahuje dostepny schema.
- [ ] Introspection enabled = finding Critical (pelny schema dostep dla atakujacego).
- [ ] Batch amplification finding zawiera: ile requestow wygenerowanych per jeden HTTP request.
- [ ] Field suggestion finding redaguje nazwy pol w logach.
- [ ] Depth probe nie powoduje powtarzajacych sie requestow przy timeout.

### Podział pracy — codex-dad

Wiekszosc pracy (A1, A2, A3, B1, B2, B3): codex-dad — kompleksowe parsowanie + sensitive validator.
Playbooki i testy (A4–A6, C1, C2): codex-main.
Rejestracja (B4): Claude.

### Post-sprint: przeglad skillow

Czy pojawil sie nowy powtarzalny pattern? Jesli tak - zaktualizuj lub dodaj skill w `.workflow/skills/`. Regula: pattern >= 2x -> skodyfikuj.
