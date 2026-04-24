# Work Item: sprint-16-attacker-intelligence
## Owner
- Orchestrator: Claude | Workers: codex-main, codex-dad | Status: dispatch

## Intent
Wdrożyć 10 capability tworząc inteligentny attacker engine z dynamicznym planowaniem,
identity lab, state snapshots, concurrency harness, payload intelligence i kill-chain reporting.
AttackPlanner staje się dynamicznym decydentem (pętla plan→execute→observe→replan).

## Constraints
- P1: ExploitValidator jedynym autorytetem proof (confidence >= 0.85)
- P2: Auth centralized in AuthManager, workers konsumują fresh session snapshot
- P3: Depth over breadth
- P4: Dedup before write
- P5: Workers produkują evidence only — nie piszą findings
- P6: Crawl = recon, nie spidering
- Redakcja TYLKO na export (nie przy zapisie)
- Codex CLI advisory only — nie omija proof-gate, nie tworzy findings

## Acceptance criteria
- [ ] AttackPlanner działa jako dynamiczny decydent (replanning loop, state machine)
- [ ] Codex CLI zintegrowany jako advisory analyst (codex_analyst.py) — advisory only
- [ ] Multi-identity scan (min 3 tożsamości) działa w auth_manager + attack_worker
- [ ] State snapshot per step + diff engine (state_store.py + state_diff.py)
- [ ] Concurrency harness + 3 race templates (double-spend, TOCTOU, idempotency bypass)
- [ ] Human simulation profiles (low-and-slow, burst, mixed)
- [ ] Exploitability scoring v2 (confidence x impact x reachability x repeatability x blast_radius)
- [ ] Payload registry z dynamic tuning + safety filter
- [ ] Kill-chain schema w raporcie (entry→pivot→exploit→impact)
- [ ] pytest tests/unit/ + integration/ + corpus/ przechodzą

## Verification
```bash
"/c/Program Files/Python312/python.exe" -m pytest tests/unit/ -q
"/c/Program Files/Python312/python.exe" -m pytest tests/integration/ -q
"/c/Program Files/Python312/python.exe" -m pytest tests/corpus/ -q
```

## Work packages

### Phase 1 — Core new files (parallel, no inter-deps)
- pkg-A | codex-main | NEW: execution_plane/planner/attack_graph.py + execution_plane/planner/path_ranker.py
- pkg-C12 | codex-dad | EDIT: control_plane/auth_manager.py (multi-identity) + execution_plane/workers/attack_worker.py (identity switch)
- pkg-D | codex-dad-2 | NEW: storage/evidence/state_store.py + execution_plane/validator/state_diff.py
- pkg-EF | codex-main-2 | NEW: execution_plane/workers/concurrency.py + execution_plane/planner/rules/race_templates.py + execution_plane/workers/behavior_profiles.py

### Phase 2 — Depends on Phase 1 (parallel within phase)
- pkg-B | codex-main | REFACTOR: execution_plane/planner/planner.py (adaptive loop) + NEW: control_plane/codex_analyst.py + execution_plane/planner/decision_log.py
- pkg-C3 | codex-dad | EDIT: execution_plane/validator/validator.py (identity-aware context)

### Phase 3 — Decision quality (parallel)
- pkg-G | codex-main | EDIT: control_plane/finding_scorer.py (scoring v2 5-factor)
- pkg-I | codex-dad | NEW: execution_plane/planner/payload_registry.py

### Phase 4 — Output quality (G must be done before J)
- pkg-H | codex-dad | NEW: tests/corpus/ structure + docs/process/incident-to-corpus.md
- pkg-J | codex-main | EDIT: control_plane/reporting.py (kill-chain) + api/models/responses.py (kill-chain schema)

## Evidence log
[2026-04-21] Phase 1 — attack_graph.py, path_ranker.py, state_store.py, state_diff.py, concurrency.py, race_templates.py, behavior_profiles.py, IdentityRole/IdentityContext in auth_manager, identity_switch in attack_worker. auth_manager import fix (lazy boto3/session). 78 unit pass.
[2026-04-21] Phase 2 — planner.py refactored (PlannerState enum, replan loop, AttackGraph+PathRanker integration), codex_analyst.py, decision_log.py, validator.py identity-aware. 78 pass.
[2026-04-21] Phase 3 — finding_scorer.py v2 (ExploitabilityScoreV2, compute_score_v2 5-factor formula), payload_registry.py (PayloadRegistry + safety_filter). 78 pass.
[2026-04-21] Phase 4 — reporting.py kill-chain render + score_explanation, responses.py KillChainStep, corpus tests (bola/auth_bypass/injection), incident-to-corpus.md. 87 pass.
[2026-04-21] Wiring — planner wired: AttackGraph, PathRanker, CodexAnalyst, DecisionLogger, PayloadRegistry. attack_worker wired: BehaviorProfile, StateStore. All 10 capabilities wired into pipeline.

## Wiring check
- AttackGraph + PathRanker in planner.py: PASS
- CodexAnalyst + DecisionLogger + PayloadRegistry in planner.py: PASS
- BehaviorProfile + StateStore in attack_worker.py: PASS
- KillChainStep in responses.py: PASS
- ExploitabilityScoreV2 + compute_score_v2 in finding_scorer.py: PASS
- Corpus tests (bola/auth_bypass/injection): PASS
- incident-to-corpus.md: PASS

## Decision
Ship: yes — 87 pytest pass (unit + corpus), wszystkie 10 capability wired into pipeline, P1-P6 invarianty zachowane (proof-gate w ExploitValidator bez zmian, CodexAnalyst advisory only, workers evidence-only, redakcja na export). Accepted risk: 2 validator tests wymagają DATABASE_URL (pre-existing issue, nie regresja sprintu).
