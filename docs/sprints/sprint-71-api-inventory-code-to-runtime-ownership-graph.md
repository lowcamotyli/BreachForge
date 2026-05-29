## Sprint 71 - API Inventory Code-To-Runtime Ownership Graph

**Goal:** Wygrac z narzedziami, ktore pokazuja findingi bez kontekstu: BreachForge ma wiedziec co istnieje, skad zostalo odkryte, kto to posiada, co bylo testowane i co pozostaje blind spotem.

### Architektura - dokumenty referencyjne

```bash
# Wszystkie trzy to pliki sprintow → Claude: Read bezposrednio
# Read docs/sprints/sprint-40-shadow-api-inventory.md
# Read docs/sprints/sprint-60-operator-grade-auth-discovery.md
# Read docs/sprints/sprint-67-developer-evidence-remediation-workflow.md
# Jezeli istnieje docs/architecture/data-model.md — odczytaj Gemini CLI:
{
  echo "=== FILE: data-model.md ==="; cat ~/BreachForge/docs/architecture/data-model.md
} | gemini --output-format text \
  -p "File above. Extract inventory/ownership data model constraints: endpoint attribution, source tracking, ownership confidence, shadow API detection. Bullets. Max 40 lines." \
  2>&1 | grep -v "^Warning:" | grep -v "^Ripgrep"
```

### Workstream A - Inventory ingestion

| ID | Zadanie | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| A1 | Unified source ingestion: OpenAPI, Postman, HAR, JS extraction, crawler, manual, gateway logs | `execution_plane/crawler/asset_map.py`, importers | codex-main | importer tests | kazdy endpoint ma source attribution |
| A2 | Code route extractors: FastAPI, Express, Rails, Spring basic patterns | `execution_plane/crawler/code_extractors/` | codex-dad | fixture tests | repo routes mozna porownac z runtime |
| A3 | Endpoint normalization v2: path params, versions, trailing slashes, methods, GraphQL operations | asset_map/benchmark | codex-main | normalization tests | coverage matching nie gubi TP przez format |

### Workstream B - Ownership graph

| ID | Zadanie | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| B1 | Graph model: service -> repo -> endpoint -> operation -> owner -> findings -> evidence | storage models/reporting | codex-main | model tests | mozna odpowiedziec "kto odpowiada za endpoint" |
| B2 | Confidence scoring for ownership: CODEOWNERS, service catalog, OpenAPI extensions, path heuristics | ownership module | codex-dad | scoring tests | owner mapping ma jawna pewnosc |
| B3 | Ownership drift detection: runtime endpoint with no repo owner, repo route not deployed, stale API version | inventory/reporting | codex-main | drift tests | shadow/zombie API staja sie widoczne |

### Workstream C - Coverage truth views

| ID | Zadanie | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| C1 | Coverage report: discovered, tested, skipped, blocked, auth_failed, unsupported_class per endpoint | reporting/API | codex-main | reporting tests | clean report nie ukrywa blind spots |
| C2 | Attack-class readiness score per service: auth, discovery, identity, stateful proof capability | reporting/scorer | codex-main | score tests | buyer widzi gdzie produkt jest silny/slaby |
| C3 | Inventory API for UI and integrations | API routers/responses | codex-dad | API tests | frontend/integracje maja stabilny kontrakt |

### Dispatch pattern

**Phase 1 (parallel):** main → A1, A3, B1, B3; dad → (brak — A2 zalezy od A1, B2 od B1)
**Phase 2 (parallel, po verify):** main → C1, C2; dad → A2 → B2 → C3
**Dad sequence:** A2 (po A1 asset_map) → B2 (po B1 graph model) → C3 (po B1+A1)
**Kluczowe zaleznosci:** A2 wymaga A1 (extractory po asset_map); B2 wymaga B1 (scoring po graph); C3 wymaga B1+A1 (API kontraktu)

### Guardrails

- Coverage score nie jest findingiem.
- Ownership heuristics bez pewnosci nie moga automatycznie assignowac blokujacych tickets.
- Gateway/code logs moga zawierac sekrety i musza isc przez redaction.
- Inventory import nie moze rozszerzac scan scope bez policy approval.

### Weryfikacja

```bash
python -m pytest tests/unit/execution_plane/crawler/ -q
python -m pytest tests/unit/control_plane/test_ownership.py -q
python -m pytest tests/unit/control_plane/test_reporting.py -q
python scripts/benchmark_lab.py --full --output .runtime/inventory-coverage.json
```

### TL_PROMPT

```bash
TL_PROMPT="Read ~/BreachForge/.workflow/skills/testing-lead.md and follow it.
Sprint: 71 - API Inventory Code-To-Runtime Ownership Graph
Changed: execution_plane/crawler/asset_map.py, execution_plane/crawler/code_extractors/, control_plane/ownership.py, control_plane/reporting.py
Test cases:
- Endpoint inventory laczy runtime, specs, HAR, JS i code routes
- Findings maja owner/service/repo metadata z confidence
- Raport pokazuje coverage truth per endpoint
- Shadow/zombie/no-owner APIs sa wykrywane" bash ~/.claude/scripts/testing-lead-exec.sh < /dev/null
```

### Global acceptance criteria

- [ ] Endpoint inventory laczy runtime, specs, HAR, JS i code routes.
- [ ] Findings maja owner/service/repo metadata z confidence.
- [ ] Raport pokazuje coverage truth per endpoint.
- [ ] Shadow/zombie/no-owner APIs sa wykrywane.

### Podzial pracy - codex-dad

A2, B2 i C3 ida do **codex-dad**. Reszte robi **codex-main**.
