## Sprint 15 - Security Attack Coverage (Task-by-Task)

**Goal:** Domknac komplet pokrycia testowego dla: IDOR/BOLA, missing auth, privilege escalation, session misuse, business logic abuse, data exposure, rate limit abuse, injection (basic), misconfiguration, endpoint discovery.

To jest sprint wykonawczy "matryca pokrycia". Zawiera konkretne taski wdrozeniowe, pliki, testy i kryteria proof-gate.

### Powiazanie z intelligence layer

Szczegolowy plan 10 capability "system, ktory mysli jak attacker" oraz integracji Codex CLI:
`docs/sprints/sprint-16-attacker-intelligence-system.md`.

### Architektura - dokumenty referencyjne

```bash
DAD_PROMPT="Read /mnt/d/SimpliAppSec/ARCHITECTURE.md and extract proof requirements per attack class, plus non-negotiables P1..P6. Bullets. Max 25 lines." bash ~/.claude/scripts/dad-exec.sh

DAD_PROMPT="Read /mnt/d/SimpliAppSec/docs/architecture/attack-engine.md, validation-model.md, security-constraints.md and extract implementation constraints for each attack type in this sprint. Bullets. Max 30 lines." bash ~/.claude/scripts/dad-exec.sh
```

### Gate 0 - platform blockers (must pass before attack coverage)

| ID | Zadanie | Pliki | Acceptance |
|---|---|---|---|
| G0-1 | Naprawic brakujace entrypointy RQ i import paths | `control_plane/orchestrator.py`, `api/routers/scans.py`, nowe funkcje jobow | enqueue -> worker -> DB dziala |
| G0-2 | Spojny FSM statusow skanu + pause semantics | `storage/db/models.py`, migration, `control_plane/orchestrator.py`, `api/routers/scans.py` | brak statusow spoza enum |
| G0-3 | Podpiac wszystkie strategie validatora | `execution_plane/validator/validator.py` | brak `validator_no_strategy` dla wspieranych klas |
| G0-4 | Ujednolicic `attack_class` injection | `execution_plane/planner/rules/injection.py`, `control_plane/finding_scorer.py`, strategie | planner -> validator -> scorer zgodne |
| G0-5 | Security data path: unredacted evidence write + redaction only export + encrypted credentials | `execution_plane/workers/attack_worker.py`, `control_plane/reporting.py`, `api/routers/scans.py`, `control_plane/auth_manager.py`, `storage/db/encryption.py` | zgodnosc z ARCHITECTURE.md sec. 11-12 |

### Implementacja per typ ataku

### Must-Have: attacker-mindset capabilities (cross-cutting)

Te zdolnosci sa wymagane przekrojowo. Bez nich narzedzie nie "mysli jak attacker".

#### A) Session / State Abuse

| ID | Zadanie | Pliki | Testy | Definition of Done |
|---|---|---|---|---|
| SSA-1 | Token/session replay probes (reuse tokenow po czasie i miedzy taskami) | `execution_plane/planner/rules/session_misuse.py`, `execution_plane/workers/attack_worker.py` | unit + integration | replay jest wykonywany kontrolowanie i logowany jako chain |
| SSA-2 | Session mutation probes (manipulacja cookie flags, token claims, session binding) | `execution_plane/workers/attack_worker.py`, helpery auth/session | worker unit tests | probe obejmuje co najmniej 3 klasy mutacji sesji |
| SSA-3 | Race-condition runner (parallel same-endpoint probes) | `execution_plane/workers/attack_worker.py`, `execution_plane/workers/supervisor.py` | integration/corpus | odtwarzalne wyslanie N rownoleglych requestow w jednym oknie czasowym |
| SSA-4 | Validator dla state abuse + race | `execution_plane/validator/strategies/session_misuse.py` | validator unit tests | finding tylko przy obserwowalnej niespojnosci/autoryzacji |

#### B) Multi-Step Attacks

| ID | Zadanie | Pliki | Testy | Definition of Done |
|---|---|---|---|---|
| MSA-1 | Chain model: exploit wymaga login + >=3 request + state transition | `execution_plane/planner/rules/workflow_abuse.py`, nowy helper chain | planner unit tests | task niesie pelna definicje krokow i prerekwizytow |
| MSA-2 | Stateful executor (przenoszenie tokenow/ID miedzy krokami) | `execution_plane/workers/attack_worker.py` | worker integration | step B/C konsumuje artefakty ze step A |
| MSA-3 | Validator reproduction dla multi-step flow | `execution_plane/validator/strategies/workflow_abuse.py` | validator + corpus | evidence zawiera pelny request chain i potwierdzenie final state |
| MSA-4 | Reporting: czytelny "attack path" per finding | `control_plane/reporting.py` | reporting tests | raport pokazuje kolejnosc krokow i warunki triggera |

#### C) Human-Like Behavior

| ID | Zadanie | Pliki | Testy | Definition of Done |
|---|---|---|---|---|
| HLB-1 | Timing profiles (human jitter, think-time, burst/noise windows) | `execution_plane/workers/attack_worker.py` | worker unit tests | profile czasowe sa konfigurowalne per task |
| HLB-2 | Sequence engine (realistic request order, nie tylko izolowane call'e) | `execution_plane/planner/planner.py`, rules | planner tests | planner generuje scenariusze kolejnosciowe |
| HLB-3 | Repeatability harness (powtarzalnosc scenariusza 3x) | `execution_plane/validator/validator.py`, test harness | corpus tests | finding wymaga powtorzenia scenariusza (redukcja FP) |
| HLB-4 | Confidence boost/penalty od timing+repeatability | `execution_plane/validator/strategies/*` | validator tests | confidence uwzglednia powtarzalnosc i timing consistency |

#### 1) IDOR / BOLA

| ID | Zadanie | Pliki | Testy | Definition of Done |
|---|---|---|---|---|
| BOLA-1 | Domknac generowanie taskow dla path/query/body ID | `execution_plane/planner/rules/bola.py` | `tests/unit/execution_plane/planner/test_bola_rule.py` | taski tworza sie dla realnych parametrow ID |
| BOLA-2 | Differential validator z control probe | `execution_plane/validator/strategies/bola.py` | `tests/unit/execution_plane/validator/test_bola_strategy.py` | artifact tylko gdy confidence >= 0.85 |
| BOLA-3 | End-to-end routing task->probe->artifact->finding | `execution_plane/validator/validator.py`, `control_plane/finding_scorer.py` | integration test | 1 potwierdzony finding z repro |

#### 2) Missing Auth

| ID | Zadanie | Pliki | Testy | Definition of Done |
|---|---|---|---|---|
| AUTH-1 | Rule: remove/downgrade auth variants | `execution_plane/planner/rules/auth_bypass.py` | planner unit tests | co najmniej 2 warianty probe |
| AUTH-2 | Worker support: kontrolowane usuwanie header/cookie | `execution_plane/workers/attack_worker.py` | worker unit tests | probe jest faktycznie unauth |
| AUTH-3 | Absolute validator (baseline structural match) | `execution_plane/validator/strategies/auth_bypass.py` | validator unit tests | false positives ograniczone thresholdem |

#### 3) Privilege Escalation

| ID | Zadanie | Pliki | Testy | Definition of Done |
|---|---|---|---|---|
| PRIV-1 | Rule dla `role/user_id/account_id/org_id/scope` | `execution_plane/planner/rules/privilege_escalation.py` | planner unit tests | poprawna selekcja endpointow |
| PRIV-2 | Payload substitution strategy | `execution_plane/workers/attack_worker.py` lub helper | worker unit tests | probe zmienia tylko target param |
| PRIV-3 | Validator: access-level delta vs baseline | `execution_plane/validator/strategies/privilege_escalation.py` | validator unit tests | finding tylko przy realnym podniesieniu uprawnien |

#### 4) Session Misuse (new class)

| ID | Zadanie | Pliki | Testy | Definition of Done |
|---|---|---|---|---|
| SES-1 | Dodac nowa klase `session_misuse` (rule) | `execution_plane/planner/rules/session_misuse.py` (new) | planner unit tests | taski: replay, token-swap, stale session |
| SES-2 | Validator `SessionMisuseStrategy` | `execution_plane/validator/strategies/session_misuse.py` (new) | validator unit tests | proof typu absolute/differential |
| SES-3 | Rejestracja strategii + severity mapping | `execution_plane/validator/validator.py`, `control_plane/finding_scorer.py` | control plane unit tests | routing bez dropow |

#### 5) Business Logic Abuse

| ID | Zadanie | Pliki | Testy | Definition of Done |
|---|---|---|---|---|
| BIZ-1 | Rozszerzyc `workflow_abuse` o real chain model | `execution_plane/planner/rules/workflow_abuse.py` | planner unit tests | task zawiera prerequisite/state chain |
| BIZ-2 | Worker support dla chained tasks | `execution_plane/workers/attack_worker.py` | worker unit tests | krok B wykorzystuje state z kroku A |
| BIZ-3 | Reproduction validator z request chain evidence | `execution_plane/validator/strategies/workflow_abuse.py` | validator unit tests | pelny chain w evidence_notes |

#### 6) Data Exposure

| ID | Zadanie | Pliki | Testy | Definition of Done |
|---|---|---|---|---|
| DATA-1 | Rule aktywacji dla structured responses | `execution_plane/planner/rules/sensitive_exposure.py` | planner unit tests | brak triggerow dla nie-structured noise |
| DATA-2 | Rozszerzyc pattern registry (token/secret/PII) | `execution_plane/validator/strategies/sensitive_exposure.py` | validator unit tests | wykrywa wzorce bez nadmiaru FP |
| DATA-3 | Dolozyc context check (czy caller powinien widziec dane) | strategy + helper | integration tests | finding tylko dla unauthorized exposure |

#### 7) Rate Limit Abuse (new class)

| ID | Zadanie | Pliki | Testy | Definition of Done |
|---|---|---|---|---|
| RATE-1 | Rule `rate_limit_abuse` (burst, staircase, retry) | `execution_plane/planner/rules/rate_limit_abuse.py` (new) | planner unit tests | taski generuja profile obciazenia |
| RATE-2 | Worker support dla controlled burst windows | `execution_plane/workers/attack_worker.py` | worker unit tests | brak naruszenia globalnych safety caps |
| RATE-3 | Validator (brak throttling/lockout przy przekroczeniu) | `execution_plane/validator/strategies/rate_limit_abuse.py` (new) | validator unit tests | proof potwierdza exploitable abuse |

#### 8) Injection (basic)

| ID | Zadanie | Pliki | Testy | Definition of Done |
|---|---|---|---|---|
| INJ-1 | Ujednolicic `attack_class` na canonical value | planner/scorer/validator | unit tests | brak rozjazdu nazw |
| INJ-2 | Basic payload set: error-based + timing-based minimal | `execution_plane/planner/rules/injection.py` | planner unit tests | brak random fuzzingu |
| INJ-3 | Validator: parser/db signature + timing confirmations | `execution_plane/validator/strategies/injection.py` (new lub update) | validator unit tests | finding tylko z obserwowalnym dowodem |

#### 9) Misconfiguration (new class)

| ID | Zadanie | Pliki | Testy | Definition of Done |
|---|---|---|---|---|
| MIS-1 | Rule `misconfiguration` (CORS, debug endpoints, unsafe methods, verbose errors) | `execution_plane/planner/rules/misconfiguration.py` (new) | planner unit tests | zadania tylko dla exploitable scenariuszy |
| MIS-2 | Validator `MisconfigurationStrategy` | `execution_plane/validator/strategies/misconfiguration.py` (new) | validator unit tests | brak teoretycznych findings |
| MIS-3 | Scorer/fix guidance mapping | `control_plane/finding_scorer.py` | control plane unit tests | sensowne severity i remediation |

#### 10) Endpoint Discovery

| ID | Zadanie | Pliki | Testy | Definition of Done |
|---|---|---|---|---|
| DISC-1 | Wzmocnic recon: xhr/fetch/forms/links + method coverage | `execution_plane/crawler/engine.py` | crawler unit tests | wyzsze pokrycie endpointow |
| DISC-2 | Normalize + dedup endpoint signatures | `execution_plane/crawler/asset_map.py` | crawler unit tests | brak duplikatow tej samej sciezki/metody |
| DISC-3 | Scope enforcement handoff do planner/worker | crawler + worker | integration tests | zero out-of-scope probes |

### Dispatch strategy (recommended)

1. **Parallel A (critical path):** G0-1..G0-5.
2. **Parallel B:** BOLA + MissingAuth + PrivEsc + Injection.
3. **Parallel C:** SessionMisuse + RateLimitAbuse + Misconfiguration (new classes).
4. **Parallel D:** BusinessLogic + DataExposure + Discovery hardening.
5. **Final pass:** severity/dedup/report consistency + integration/corpus gates.

### Weryfikacja

```bash
python -m pytest tests/unit/ -q
python -m pytest tests/integration/ -q
python -m pytest tests/corpus/ -q
```

### Global acceptance criteria (for sprint close)

- [ ] Kazdy z 10 typow ma rule + worker path + validator strategy + scorer mapping.
- [ ] Session/state abuse obejmuje: token reuse, session mutation, race conditions.
- [ ] Multi-step attacks obejmuja co najmniej 1 flow: login -> 3 requesty -> state change -> exploit.
- [ ] Human-like behavior obejmuje timing, kolejnosc i repeatability (min. 3x).
- [ ] Kazdy typ ma przynajmniej 1 integration scenario i 1 corpus scenario.
- [ ] Proof-gate (>= 0.85) jest enforceowany dla wszystkich typow findings.
- [ ] Worker isolation i scope/rate safety nie sa naruszone przez nowe klasy.
- [ ] Raport zawiera reproducible evidence (exact request/response + repro steps) dla kazdego typu.

### Post-sprint: przeglad skillow

Czy pojawil sie nowy powtarzalny pattern? Jesli tak - zaktualizuj lub dodaj skill w `.workflow/skills/` przed zamknieciem sprintu. Regula: pattern >= 2x -> skodyfikuj.
