## Sprint 63 - Execution Provider Sandbox And HexStrike Adapter

**Goal:** Polaczyc sile wykonawcza HexStrike z rdzeniem BreachForge bez wnoszenia ryzyka raw shell/RCE: HexStrike i inne narzedzia maja byc providerami wykonawczymi, a nie zrodlem prawdy o findingach.

### Architektura - dokumenty referencyjne

```bash
{
  echo "=== FILE: security-constraints.md ==="; cat ~/BreachForge/docs/architecture/security-constraints.md
  echo "=== FILE: attack-engine.md ==="; cat ~/BreachForge/docs/architecture/attack-engine.md
  echo "=== FILE: hexstrike README ==="; cat ~/HexStrikeAI/hexstrike-ai/README.md
} | gemini --output-format text \
  -p "Files above separated by === FILE: ===. Extract execution-provider boundary, sandbox and evidence-normalization requirements. Bullets. Max 40 lines." \
  2>&1 | grep -v "^Warning:" | grep -v "^Ripgrep"
```

### Workstream A - Provider contract

| ID | Zadanie | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| A1 | `ExecutionProvider` interface: capabilities, input schema, output schema, budgets, safety class | `execution_plane/providers/`, `api/models/requests.py` | codex-main | provider unit tests | BreachForge moze wywolac narzedzie bez znajomosci jego CLI |
| A2 | Tool capability registry: zap, nuclei, httpx, katana, hexstrike_proxy | `execution_plane/providers/registry.py` | codex-main | registry tests | planner widzi tylko dopuszczone capabilities |
| A3 | `ToolEvidence` normalizer: stdout/stderr/json/HAR -> RawProbe/DiscoverySignal | `execution_plane/providers/normalizers.py`, evidence store | codex-dad | parser tests | output narzedzia nie omija validatora |

### Workstream B - Sandbox and policy enforcement

| ID | Zadanie | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| B1 | Containerized provider runner with no host shell, read-only FS, timeout, memory and CPU budgets | `execution_plane/providers/runner.py`, `docker/` | codex-dad | sandbox tests | zadne narzedzie nie odpala arbitralnych komend na control plane |
| B2 | Argument allowlist per tool: structured params zamiast `additional_args` string | provider schemas | codex-main | injection tests | command injection przez target/args jest niemozliwy w adapterze |
| B3 | Network scope enforcement inside provider runner: allowed_hosts, localhost benchmark mode, deny private ranges unless policy allows | runner/policy files | codex-main | guardrail tests | provider nie rozszerza scope poza scan policy |

### Workstream C - HexStrike adapter v1

| ID | Zadanie | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| C1 | HexStrike HTTP adapter jako opcjonalny provider z health/capabilities/version checks | `execution_plane/providers/hexstrike.py` | codex-main | adapter tests | BreachForge moze uzyc HexStrike bez bezposredniego importu kodu |
| C2 | First safe capability mapping: zap baseline, nuclei templates, httpx tech/discovery, katana crawler | provider registry | codex-dad | integration smoke | top capabilities dzialaja na benchmark lab |
| C3 | Provider result attribution in reports: which engine generated which signal and which validator confirmed it | `control_plane/reporting.py`, DB models | codex-main | reporting tests | klient widzi roznice miedzy signalem a findingiem |

### Dispatch pattern

**Phase 1 (parallel):** main → A1, A2, B2, B3; dad → B1
**Phase 2 (parallel, po verify):** main → C1, C3; dad → A3 → C2
**Dad sequence:** B1 (faza 1) → A3 (faza 2, po A1+A2) → C2 (faza 2, po A3+C1)
**Kluczowe zaleznosci:** A3 wymaga A1+A2; C1 wymaga A1+A2; C2 wymaga A3+C1; C3 wymaga A3+C1

### Guardrails

- HexStrike/third-party provider nie moze tworzyc `Finding` bez BreachForge validatora.
- Brak raw `shell=True` path w nowym provider runnerze.
- Credentials nie trafiaja do provider logs, command metadata ani cache.
- Provider moze byc calkowicie wylaczony bez psucia native engine.

### Weryfikacja

```bash
python -m pytest tests/unit/execution_plane/providers/ -q
python -m pytest tests/unit/execution_plane/workers/ -q
python scripts/benchmark_lab.py --full --provider native --max-fp 0
python scripts/benchmark_lab.py --full --provider hexstrike --max-fp 0
python -m pytest tests/unit/ -q
```

### TL_PROMPT

```bash
TL_PROMPT="Read ~/BreachForge/.workflow/skills/testing-lead.md and follow it.
Sprint: 63 - Execution Provider Sandbox And HexStrike Adapter
Changed: execution_plane/providers/, api/models/requests.py, docker/
Test cases:
- HexStrike dziala jako sandboxed execution provider (provider nie moze tworzyc Finding bez validatora)
- Output providerow jest normalizowany jako evidence/signals, nie findingi
- Argument injection i scope escape sa pokryte testami
- Raport pokazuje provider attribution" bash ~/.claude/scripts/testing-lead-exec.sh < /dev/null
```

### Global acceptance criteria

- [ ] HexStrike dziala jako sandboxed execution provider.
- [ ] Output providerow jest normalizowany jako evidence/signals, nie findingi.
- [ ] Argument injection i scope escape sa pokryte testami.
- [ ] Raport pokazuje provider attribution.

### Podzial pracy - codex-dad

A3, B1 i C2 ida do **codex-dad** jako context-heavy/sandbox packages. Reszte robi **codex-main**.
