## Sprint 64 - Competitive Scanner Benchmark Harness

**Goal:** Zamienic BreachForge w warstwe prawdy dla scannerow: jedna komenda uruchamia native engine i zewnetrzne DAST/tool providers na tych samych labach, a raport pokazuje TP/FP/FN, blind spots, proof depth i czas do dowodu.

### Architektura - dokumenty referencyjne

```bash
# sprint-63 → Claude: Read docs/sprints/sprint-63-execution-provider-sandbox-hexstrike-adapter.md
{
  echo "=== FILE: BENCHMARK_README.md ==="; cat ~/BreachForge/docs/BENCHMARK_README.md
  echo "=== FILE: validation-model.md ==="; cat ~/BreachForge/docs/architecture/validation-model.md
} | gemini --output-format text \
  -p "Files above. Extract benchmark comparison contracts and normalization risks. Bullets. Max 40 lines." \
  2>&1 | grep -v "^Warning:" | grep -v "^Ripgrep"
```

### Workstream A - External findings import

| ID | Zadanie | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| A1 | Import parsers: ZAP JSON/XML, Nuclei JSONL, SARIF, generic DAST JSON | `scripts/benchmark_importers/`, `execution_plane/providers/normalizers.py` | codex-main | parser fixtures | zewnetrzne wyniki mozna porownac z ground truth |
| A2 | Finding normalizer: type mapping, endpoint normalization, method, evidence fields, confidence hints | `scripts/benchmark_lab.py`, importers | codex-dad | metrics tests | BOLA/BFLA/Auth/etc. mapuja sie stabilnie |
| A3 | Unknown/ambiguous bucket with manual-review flag, never counted as TP without mapping | importers/metrics | codex-main | negative tests | benchmark nie daje kredytu za niejasny alert |

### Workstream B - Multi-engine benchmark runner

| ID | Zadanie | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| B1 | CLI: `--engine native|hexstrike|zap|nuclei|import:file` and `--matrix` | `scripts/benchmark_lab.py` | codex-main | CLI tests | jeden runner obsluguje wiele engineow |
| B2 | Same-scope execution package: lab URL, auth material, OpenAPI/HAR, policy and budgets shared across engines | benchmark runner/providers | codex-dad | integration smoke | porownanie jest fair i powtarzalne |
| B3 | Repeatability mode: fixed seeds, run_id, artifacts dir, per-engine raw outputs | benchmark runner | codex-main | snapshot tests | wynik da sie odtworzyc i audytowac |

### Workstream C - Competitive scorecard

| ID | Zadanie | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| C1 | Metrics: TP/FP/FN, coverage_by_attack_class, discovery_coverage, proof_depth, auth_health, time_to_first_proof | `scripts/benchmark_lab.py` | codex-main | metrics tests | raport pokazuje jakosc, nie tylko liczbe alertow |
| C2 | Markdown/JSON comparison report with rank table and per-class misses | reporting/benchmark docs | codex-main | golden tests | mozna pokazac roznice z liderami rynku |
| C3 | "Why missed" classifier: crawler, auth, planner, execution, validator, unsupported_class | benchmark metrics | codex-dad | FN tests | raport jest actionable dla rozwoju produktu |

### Dispatch pattern

**Phase 1 (parallel):** main → A1, A3, B1, B3; dad → (brak — pierwsze taski dada zaleза od A1/B1)
**Phase 2 (parallel, po verify):** main → C1, C2; dad → A2 → B2 → C3
**Dad sequence:** A2 (po A1) → B2 (po A2+B1) → C3 (po C1+A2)
**Kluczowe zaleznosci:** A2 wymaga A1; B2 wymaga B1+A2; C3 wymaga C1+A2

### Guardrails

- Fairness: kazdy engine dostaje ten sam scope, auth i time budget.
- Imported alerts nie sa proof artifacts; to osobna kategoria `external_claim`.
- Benchmark nie wysyla ruchu poza lokalne laby bez jawnego `--external-target`.
- Nie wolno special-case'owac pod nazwe enginea w ground truth matching.

### Weryfikacja

```bash
python -m pytest tests/unit/scripts/test_benchmark_importers.py -q
python scripts/benchmark_lab.py --full --engine native --max-fp 0
python scripts/benchmark_lab.py --full --matrix native,hexstrike,zap --output .runtime/benchmark-matrix.json
python -m pytest tests/integration/test_benchmark_smoke.py -q
```

### TL_PROMPT

```bash
TL_PROMPT="Read ~/BreachForge/.workflow/skills/testing-lead.md and follow it.
Sprint: 64 - Competitive Scanner Benchmark Harness
Changed: scripts/benchmark_importers/, scripts/benchmark_lab.py, execution_plane/providers/normalizers.py
Test cases:
- Benchmark porownuje native BreachForge z minimum dwoma zewnetrznymi engineami/importami
- Scorecard pokazuje TP/FP/FN, proof depth i discovery/auth blind spots
- FN maja missing_detection_stage
- Wyniki sa odtwarzalne z artifacts dir" bash ~/.claude/scripts/testing-lead-exec.sh < /dev/null
```

### Global acceptance criteria

- [ ] Benchmark porownuje native BreachForge z minimum dwoma zewnetrznymi engineami/importami.
- [ ] Scorecard pokazuje TP/FP/FN, proof depth i discovery/auth blind spots.
- [ ] FN maja `missing_detection_stage`.
- [ ] Wyniki sa odtwarzalne z artifacts dir.

### Podzial pracy - codex-dad

A2, B2 i C3 ida do **codex-dad**. Reszte robi **codex-main**.
