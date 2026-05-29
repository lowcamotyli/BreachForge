## Sprint 73 - Public Benchmark Trust Program

**Goal:** Zachowac unikatowosc BreachForge i zbudowac zaufanie rynku: publiczny, reprodukowalny benchmark pokazuje nie tylko "nasz scanner wykryl", ale co kazdy engine widzial, pominol i potrafil udowodnic.

### Architektura - dokumenty referencyjne

```bash
# sprint-64, sprint-66 → Claude: Read docs/sprints/sprint-{64,66}-*.md bezposrednio
{
  echo "=== FILE: BENCHMARK_README.md ==="; cat ~/BreachForge/docs/BENCHMARK_README.md
} | gemini --output-format text \
  -p "File above. Extract public benchmark packaging and anti-gaming requirements: deterministic seeds, ground truth immutability, claims policy, reproducibility guarantees. Bullets. Max 40 lines." \
  2>&1 | grep -v "^Warning:" | grep -v "^Ripgrep"
```

### Workstream A - Public corpus packaging

| ID | Zadanie | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| A1 | Benchmark corpus package: Docker compose, deterministic seeds, lab manifests, ground truth docs | `docker/benchmark/`, `tests/benchmark_lab/`, docs | codex-main | package smoke | outsider moze uruchomic benchmark lokalnie |
| A2 | Anti-gaming mode: randomized IDs, route variants, tenant names, timing seeds while preserving ground truth | lab runtime | codex-dad | determinism tests | engine nie moze hardcodowac labowych wartosci |
| A3 | Corpus contribution guide: add lab, add vuln class, add expected proof, add golden baseline | docs/process | codex-main | doc review | benchmark moze rosnac bez chaosu |

### Workstream B - Reproducible comparison kit

| ID | Zadanie | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| B1 | `breachforge-bench` CLI: run engine, import results, compare, export scorecard | CLI/scripts | codex-main | CLI tests | publiczny benchmark ma jedno wejscie |
| B2 | Engine adapters/import recipes for native, HexStrike, ZAP, Nuclei and generic SARIF | docs/adapters/importers | codex-dad | adapter smoke | inne narzedzia mozna uczciwie porownac |
| B3 | Repro bundle: raw outputs, normalized findings, metrics, environment metadata, signed manifest | benchmark runner/reporting | codex-main | reproducibility tests | wynik da sie sprawdzic pozniej |

### Workstream C - Trust-facing outputs

| ID | Zadanie | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| C1 | Public scorecard template: coverage by class, FP/FN, proof depth, auth/discovery health, unsupported classes | docs/reporting templates | codex-main | snapshot tests | komunikat rynkowy jest konkretny |
| C2 | Benchmark changelog and version pinning: corpus version, schema version, engine config version | docs/scripts | codex-main | version tests | wyniki z roznych dat sa porownywalne |
| C3 | "Claims policy": rules for saying market-leading/better/faster with required evidence | docs/process | codex-dad | doc review | marketing nie wyprzedza dowodow |

### Dispatch pattern

**Phase 1 (parallel):** main → A1, A3, B1, B3; dad → (brak — A2 zalezy od A1, B2 od B1)
**Phase 2 (parallel, po verify):** main → C1, C2; dad → A2 → B2 → C3
**Dad sequence:** A2 (po A1 corpus package) → B2 (po B1 CLI) → C3 (po A2+B2 — claims bazuja na udowodnionych wynikach)
**Kluczowe zaleznosci:** A2 wymaga A1 (anti-gaming operuje na corpus); B2 wymaga B1 (adaptery po CLI); C3 wymaga A2+B2 (claims policy bazuje na gotowym benchmarku)

### Guardrails

- Public benchmark nie moze zawierac prawdziwych sekretow ani zewnetrznych zaleznosci.
- Anti-gaming nie moze zmieniac klasy podatnosci ani expected proof.
- Wyniki z imported third-party scanners musza pokazywac config i raw artifacts.
- Claims policy blokuje nieudokumentowane porownania z vendorami.

### Weryfikacja

```bash
python -m pytest tests/benchmark_lab/ -q
python scripts/benchmark_lab.py --full --lab all --anti-gaming-seed 123 --max-fp 0
breachforge-bench run --engine native --corpus local --output .runtime/public-bench.json
python -m pytest tests/unit/scripts/ -q
```

### TL_PROMPT

```bash
TL_PROMPT="Read ~/BreachForge/.workflow/skills/testing-lead.md and follow it.
Sprint: 73 - Public Benchmark Trust Program
Changed: docker/benchmark/, tests/benchmark_lab/, cli/, docs/
Test cases:
- Public corpus mozna uruchomic lokalnie z deterministic seed (Docker compose dziala)
- Anti-gaming mode dziala bez special-case breaking (ground truth niezmienione)
- Scorecard jest reprodukowalny i podpisany
- Claims policy chroni wiarygodnosc rynkowa" bash ~/.claude/scripts/testing-lead-exec.sh < /dev/null
```

### Global acceptance criteria

- [ ] Public corpus mozna uruchomic lokalnie z deterministic seed.
- [ ] Anti-gaming mode dziala bez special-case breaking.
- [ ] Scorecard jest reprodukowalny i podpisany.
- [ ] Claims policy chroni wiarygodnosc rynkowa.

### Podzial pracy - codex-dad

A2, B2 i C3 ida do **codex-dad**. Reszte robi **codex-main**.
