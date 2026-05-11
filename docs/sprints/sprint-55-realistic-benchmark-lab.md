## Sprint 55 - Realistic Benchmark Lab

**Goal:** Zbudowac benchmark skutecznosci na realistycznej aplikacji labowej z ground truth, zamiast oceniac system tylko po unit testach.

### Architektura - dokumenty referencyjne

```bash
DAD_PROMPT="cd /mnt/d/BreachForge && Read docs/architecture/attack-engine.md and docs/process/incident-to-corpus.md. Extract: corpus pattern, benchmark metrics, proof expectations. Bullets. Max 25 lines." bash ~/.claude/scripts/dad-exec.sh
```

### Workstream A - Vulnerable SaaS lab

| ID | Zadanie | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| A1 | Mini app: tenants, roles, billing/cart, approvals, API tokens | `tests/benchmark_lab/` lub `tests/corpus/lab/` | codex-dad | lab smoke | aplikacja odpala lokalnie |
| A2 | REST + GraphQL + OAuth-ish auth + async job endpointy | lab files | codex-dad | lab tests | powierzchnia jest realistyczna |
| A3 | Seeded vulnerabilities z ground truth manifest | lab manifest | codex-dad | benchmark tests | kazda podatnosc ma expected finding |

### Workstream B - Benchmark runner

| ID | Zadanie | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| B1 | Runner: start lab -> run scan -> collect findings -> compare ground truth | `scripts/benchmark_lab.py` | codex-main | smoke | generuje metrics JSON |
| B2 | Metrics: TP, FP, FN, coverage, time-to-proof, unsafe-block count | `scripts/benchmark_lab.py` | codex-main | tests | wynik jest porownywalny w czasie |
| B3 | Golden reports dla baseline | `tests/benchmark_lab/golden/` | codex-main | regression | zmiany widoczne w diffie |

### Workstream C - CI/nightly integration

| ID | Zadanie | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| C1 | Szybki smoke benchmark w unit/integration suite | tests/scripts | codex-main | CI smoke | nie spowalnia podstawowego test runu |
| C2 | Pelny benchmark jako optional/nightly | docs/scripts | codex-main | manual/nightly | mozna uruchomic lokalnie |
| C3 | README benchmark usage | docs | codex-main | doc review | jasna instrukcja |

### Guardrails

- Lab nie moze wymagac zewnetrznych sekretow.
- Benchmark nie moze wysylac ruchu poza localhost.
- Golden output redaguje sekrety.

### Weryfikacja

```bash
python -m pytest tests/benchmark_lab/ -q
python scripts/benchmark_lab.py --quick
python -m pytest tests/unit/ -q
```

### Global acceptance criteria

- [ ] Benchmark lab ma realistyczne auth/multi-tenant/business flows.
- [ ] Ground truth pozwala mierzyc TP/FP/FN.
- [ ] Runner generuje metrics JSON.
- [ ] Quick benchmark dziala lokalnie bez zewnetrznych uslug.

### Podzial pracy - codex-dad

A1-A3 ida do **codex-dad** jako duzy context/build package. B-C robi **codex-main**.
