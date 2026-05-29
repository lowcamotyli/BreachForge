## Sprint 66 - Full Multi-Lab Live Corpus v1

**Goal:** Usunac ostatni "prototype smell": wszystkie laby z multi-lab suite maja dzialac w `--full`, generowac realne findings i miec golden baselines. Bez placeholderow, bez quick-only dla kluczowych klas.

### Architektura - dokumenty referencyjne

```bash
# sprint-59 → Claude: Read docs/sprints/sprint-59-multi-lab-coverage-suite.md bezposrednio
{
  echo "=== FILE: benchmark_lab.py ==="; cat ~/BreachForge/scripts/benchmark_lab.py
  for f in ~/BreachForge/tests/benchmark_lab/labs/*/ground_truth.json; do
    echo "=== FILE: $f ==="; cat "$f"
  done
} | gemini --output-format text \
  -p "Files above. Map quick-only lab gaps to live runner work: which labs lack full/live mode, what runtime inputs are needed per lab. Table format. Max 45 lines." \
  2>&1 | grep -v "^Warning:" | grep -v "^Ripgrep"
```

### Workstream A - Live lab harness for every lab

| ID | Zadanie | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| A1 | Generic lab runtime: resolve lab_id -> ASGI app/module, random localhost port, health check | `scripts/benchmark_lab.py`, `tests/benchmark_lab/lab_manifest.py` | codex-main | lab runtime tests | `--full --lab <id>` dziala dla kazdego labu |
| A2 | Seed identity/spec/HAR/OpenAPI per lab and inject into scan context | lab apps/manifests | codex-dad | lab smoke | scanner dostaje realistyczny input per lab |
| A3 | Per-lab reset and deterministic state restore between probes | lab apps | codex-main | state tests | wyniki nie zaleza od kolejnosci testow |

### Workstream B - Detection coverage closure

| ID | Zadanie | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| B1 | `api_saas` full detections: BOLA, BFLA, hidden endpoint, tenant, mass assignment | planner/validators/lab | codex-main | benchmark | >= 4/5 TP, 0 FP |
| B2 | `graphql` and `spa_har` full detections: introspection/batch/depth/field auth + JS/HAR discovery | crawler/graphql/validators | codex-dad | benchmark | GraphQL i SPA maja realny full mode |
| B3 | `business_race` and `auth_oauth` full detections with stateful proof | workers/validators/labs | codex-main | benchmark | stateful/auth klasy maja proof artifacts |

### Workstream C - Golden baselines and public corpus shape

| ID | Zadanie | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| C1 | Golden metrics per lab: full mode, coverage, FP/FN, discovery/auth gates | `tests/benchmark_lab/golden/` | codex-main | golden tests | regresje widac per lab |
| C2 | Corpus taxonomy aligned to OWASP API Top 10, WSTG and BreachForge attack_class | `docs/BENCHMARK_README.md`, manifests | codex-main | doc/schema tests | benchmark jest zrozumialy dla kupujacych |
| C3 | Nightly all-labs summary with release threshold and diff vs previous baseline | benchmark scripts | codex-main | smoke | jedna komenda daje ship/no-ship |

### Dispatch pattern

**Phase 1 (parallel):** main → A1, A3, B1, B3; dad → A2
**Phase 2 (parallel, po verify):** main → C1, C2, C3; dad → B2
**Dad sequence:** A2 (faza 1, niezalezny) → B2 (faza 2, po B1)
**Kluczowe zaleznosci:** A2 potrzebuje A1 runtime; B2 potrzebuje B1 planera; C1/C2/C3 potrzebuja A+B coverage

### Guardrails

- Laby dalej sa offline i deterministic.
- Discovery coverage i finding coverage pozostaja osobnymi metrykami.
- No special-casing po vulnerability ID.
- Full mode nie moze miec placeholder note ani quick fallback.

### Weryfikacja

```bash
python -m pytest tests/benchmark_lab/ -q
python scripts/benchmark_lab.py --full --lab all --min-coverage 0.80 --max-fp 0
python scripts/benchmark_lab.py --full --lab graphql --max-fp 0
python -m pytest tests/integration/test_benchmark_smoke.py -q
```

### TL_PROMPT

```bash
TL_PROMPT="Read ~/BreachForge/.workflow/skills/testing-lead.md and follow it.
Sprint: 66 - Full Multi-Lab Live Corpus v1
Changed: scripts/benchmark_lab.py, tests/benchmark_lab/, tests/benchmark_lab/golden/
Test cases:
- Kazdy lab dziala w full/live mode (--full --lab all nie ma placeholderow)
- Nightly all-labs ma minimum 80% aggregate coverage i 0 FP
- Kazdy TP ma proof artifact
- Golden baselines sa aktualne per lab" bash ~/.claude/scripts/testing-lead-exec.sh < /dev/null
```

### Global acceptance criteria

- [ ] Kazdy lab dziala w full/live mode.
- [ ] Nightly all-labs ma minimum 80% aggregate coverage i 0 FP.
- [ ] Kazdy TP ma proof artifact.
- [ ] Golden baselines sa aktualne per lab.

### Podzial pracy - codex-dad

A2 i B2 ida do **codex-dad**. Reszte robi **codex-main**.
