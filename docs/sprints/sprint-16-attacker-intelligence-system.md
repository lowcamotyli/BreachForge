## Sprint 16 - Attacker Intelligence System (Top-10 Capabilities)

**Goal:** Domknac 10 kluczowych capability, aby system dzialal jak zaawansowany attacker engine:
1) Attack Graph Engine
2) Adaptive Strategy Loop
3) Identity Lab
4) State Snapshot + Time Travel
5) Concurrency Harness
6) Stealth/Human Simulation Profiles
7) Exploitability Scoring v2
8) Continuous Learning Corpus
9) Payload Intelligence Layer
10) Kill-Chain Reporting

Ten sprint jest "meta-warstwa" nad sprintem 15: nie zastepuje coverage klas atakow, tylko robi z nich inteligentny system.

### Decyzyjnosc dynamiczna (kluczowa zmiana)

`AttackPlanner` przestaje byc jednorazowym generatorem taskow. Staje sie **dynamicznym decydentem ataku**
(roboczo: `AttackDirector` jako rola runtime, moze zostac zachowana nazwa klasy `AttackPlanner` dla kompatybilnosci).

Nowy kontrakt:
- stale pobiera sygnaly runtime (probe outcomes, state deltas, identity context, rate/scope budget),
- wyznacza `next_best_actions` w petli,
- aktualizuje kolejnosc i rodzaj atakow bez restartu skanu,
- respektuje twarde polityki P1..P6 i proof-gate.

### Architektura - dokumenty referencyjne

```bash
DAD_PROMPT="Read /mnt/d/SimpliAppSec/ARCHITECTURE.md and extract constraints that cannot be broken by attacker-intelligence features (P1..P6, proof-gate, worker isolation, redaction boundary). Bullets. Max 25 lines." bash ~/.claude/scripts/dad-exec.sh
```

### Integracja Codex CLI podczas wykonywania atakow

Codex CLI jest tu traktowany jako **Attack Analyst Copilot**, nie jako komponent podejmujacy decyzje o findingach.

- Wejscie do Codex CLI:
  - `AssetMap` + `SessionSnapshot metadata` + historia probe'ow (bez secretow)
  - lokalny kontekst flow (step chain, status, response deltas)
- Wyjscie z Codex CLI:
  - ranking kolejnych hipotez (`next_best_actions`)
  - sugestie payloadow i kolejnosci krokow
  - uzasadnienie dlaczego dany krok ma wysoki potencjal
- Ograniczenia:
  - Codex CLI **nie moze** oznaczyc findingu
  - Codex CLI **nie omija** proof-gate
  - Codex CLI outputs przechodza przez walidacje polityk scope/rate/isolation

### Workstream A - Attack Graph Engine

| ID | Zadanie | Pliki | Testy | Definition of Done |
|---|---|---|---|---|
| A1 | Model grafu: nodes (endpoint,state,identity), edges (action,precondition) | `execution_plane/planner/attack_graph.py` (new) | planner unit tests | graf serializuje sie per scan |
| A2 | Budowa grafu z AssetMap + probe history | `execution_plane/planner/planner.py` + helper | integration tests | planner tworzy i aktualizuje graf incrementalnie |
| A3 | Path ranking (impact x reachability x cost) | `execution_plane/planner/path_ranker.py` (new) | unit tests | top-k sciezek stabilne i deterministyczne |

### Workstream B - Adaptive Strategy Loop

| ID | Zadanie | Pliki | Testy | Definition of Done |
|---|---|---|---|---|
| B1 | Refactor `AttackPlanner` do petli decyzyjnej (`plan -> execute -> observe -> replan`) | `execution_plane/planner/planner.py` | planner tests | planner dziala ciagle i aktualizuje plan runtime |
| B2 | Runtime state machine dla decyzji (`idle`, `planning`, `dispatching`, `waiting_feedback`, `replanning`) | `execution_plane/planner/planner.py`, helper state module | unit tests | brak deadlocku i deterministyczne przejscia |
| B3 | Feedback loop: probe outcome -> reprioritization | `execution_plane/planner/planner.py` | integration tests | kolejne taski zalezne od wynikow poprzednich |
| B4 | Policy guard dla adaptacji (scope/rate/safety caps) | `control_plane/rate_limiter.py`, planner guard | unit tests | adaptacja nie lamie safety constraints |
| B5 | Codex CLI hook: `suggest_next_actions()` | `control_plane/codex_analyst.py` (new) | mock tests | sugestie trafiaja do planera jako advisory ranking |
| B6 | Decision audit trail (dlaczego planner wybral krok X) | `execution_plane/planner/decision_log.py` (new), reporting hooks | tests | kazda decyzja ma uzasadnienie i timestamp |

### Workstream C - Identity Lab

| ID | Zadanie | Pliki | Testy | Definition of Done |
|---|---|---|---|---|
| C1 | Multi-identity model (`anon,user,admin,tenantA,tenantB`) | `control_plane/auth_manager.py`, `api/models/requests.py` | auth unit/integration | min. 3 tozsamosci aktywne w skanie |
| C2 | Identity switch per task/chain step | `execution_plane/workers/attack_worker.py` | worker integration | chain moze zmieniac identity miedzy krokami |
| C3 | Identity-aware validator context | `execution_plane/validator/validator.py` | validator tests | proof uwzglednia kontekst tozsamosci |

### Workstream D - State Snapshot + Time Travel

| ID | Zadanie | Pliki | Testy | Definition of Done |
|---|---|---|---|---|
| D1 | Snapshot store (pre/post action) | `storage/evidence/state_store.py` (new) | storage tests | snapshot per step zapisany i wersjonowany |
| D2 | Diff engine (state delta) | `execution_plane/validator/state_diff.py` (new) | validator unit tests | delta state dostepna dla strategii |
| D3 | Replay/time-travel executor | worker helper | integration tests | mozna odtworzyc scenariusz z konkretnego snapshotu |

### Workstream E - Concurrency Harness

| ID | Zadanie | Pliki | Testy | Definition of Done |
|---|---|---|---|---|
| E1 | Controlled parallel burst executor | `execution_plane/workers/concurrency.py` (new) | worker tests | N requestow w jednym oknie czasowym |
| E2 | Race templates (double-spend, TOCTOU, idempotency bypass) | `execution_plane/planner/rules/race_templates.py` (new) | planner tests | min. 3 template'y gotowe |
| E3 | Race validator semantics | `execution_plane/validator/strategies/session_misuse.py` + new helpers | validator tests | race finding tylko przy reprodukcji |

### Workstream F - Human Simulation Profiles

| ID | Zadanie | Pliki | Testy | Definition of Done |
|---|---|---|---|---|
| F1 | Profile: low-and-slow, burst, mixed | `execution_plane/workers/behavior_profiles.py` (new) | worker tests | profile wybieralny per scan |
| F2 | Timing jitter + think-time + sequence constraints | worker + planner | integration tests | ruch wyglada jak sesja usera, nie fuzz storm |
| F3 | Repeatability policy (3x) | validator | corpus tests | finding wymaga powtorzenia zgodnie z profilem |

### Workstream G - Exploitability Scoring v2

| ID | Zadanie | Pliki | Testy | Definition of Done |
|---|---|---|---|---|
| G1 | Formula: confidence x impact x reachability x repeatability x blast radius | `control_plane/finding_scorer.py` | scorer tests | wynik jest wyjasnialny i audytowalny |
| G2 | Severity mapping v2 + backward compatibility | scorer + report | tests | brak regresji dla starych findingow |
| G3 | Score explanation in report | `control_plane/reporting.py` | reporting tests | raport pokazuje skad wynik score |

### Workstream H - Continuous Learning Corpus

| ID | Zadanie | Pliki | Testy | Definition of Done |
|---|---|---|---|---|
| H1 | Corpus structure per attack class + kill chain | `tests/corpus/` | corpus CI | kazda klasa ma min. 1 scenariusz |
| H2 | Incident-to-test workflow | `docs/process/incident-to-corpus.md` (new) | process review | kazdy incident dodaje test regresyjny |
| H3 | CI gate: strategy/rule change wymaga corpus pass | CI config | pipeline tests | merge block przy niezaliczonym corpus |

### Workstream I - Payload Intelligence Layer

| ID | Zadanie | Pliki | Testy | Definition of Done |
|---|---|---|---|---|
| I1 | Payload registry by stack/framework | `execution_plane/planner/payload_registry.py` (new) | planner tests | payload selection zalezna od kontekstu |
| I2 | Dynamic payload tuning from probe feedback | planner + codex analyst hook | integration tests | payloady adaptuja sie po outcome |
| I3 | Safety filter for payload generation | planner guard | unit tests | brak payloadow wykraczajacych poza safe boundaries |

### Workstream J - Kill-Chain Reporting

| ID | Zadanie | Pliki | Testy | Definition of Done |
|---|---|---|---|---|
| J1 | Kill-chain schema (entry -> pivot -> exploit -> impact) | `api/models/responses.py`, reporting | reporting tests | finding ma sciezke kill-chain |
| J2 | Render kill-chain in Markdown/JSON | `control_plane/reporting.py` | report tests | raport pokazuje nie tylko pojedynczy probe |
| J3 | Dedup aware of chain root cause | `control_plane/finding_scorer.py` | scorer tests | variants lacza sie do jednej chain root |

### Dispatch strategy (recommended)

1. Parallel A: A + B + C (core intelligence).
2. Parallel B: D + E + F (execution realism).
3. Parallel C: G + I (decision quality).
4. Parallel D: H + J (quality gates + customer output).
5. Final: end-to-end red-team simulation on corpus.

### Weryfikacja

```bash
python -m pytest tests/unit/ -q
python -m pytest tests/integration/ -q
python -m pytest tests/corpus/ -q
```

### Global acceptance criteria (for sprint close)

- [ ] Wszystkie 10 capability sa wdrozone i uzyte w runtime.
- [ ] AttackPlanner dziala jako dynamiczny decydent (replanning loop), nie statyczny generator.
- [ ] Codex CLI jest zintegrowany jako advisory analyst w petli ataku.
- [ ] Codex CLI nie omija proof-gate i nie ma authority do tworzenia findingow.
- [ ] Co najmniej 3 kompleksowe kill-chain scenariusze przechodza end-to-end.
- [ ] Raport pokazuje kill-chain + scoring v2 + reproducible evidence.

### Post-sprint: przeglad skillow

Czy pojawil sie nowy powtarzalny pattern? Jesli tak - zaktualizuj lub dodaj skill w `.workflow/skills/` przed zamknieciem sprintu. Regula: pattern >= 2x -> skodyfikuj.
