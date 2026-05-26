## Sprint 58 - Benchmark Detection Lift

**Goal:** Podniesc skutecznosc na benchmark lab z `0/7` do co najmniej `5/7` TP przy `0` FP, z proof artifacts dla kazdego TP.

### Architektura - dokumenty referencyjne

```bash
DAD_PROMPT="cd /mnt/d/BreachForge && Read tests/benchmark_lab/ground_truth.json, docs/architecture/validation-model.md and docs/architecture/attack-engine.md. Map each ground-truth vuln to planner rule, worker probe, validator strategy and likely gap. Table. Max 40 lines." bash ~/.claude/scripts/dad-exec.sh
```

### Workstream A - Ground truth to attack mapping

| ID | Zadanie | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| A1 | Matryca 7 podatnosci: BOLA, BFLA, tenant, privilege, race, business logic, auth bypass -> rule/strategy/scorer | `docs/BENCHMARK_README.md`, `tests/benchmark_lab/ground_truth.json` | codex-main | doc review | kazdy vuln ma expected attack path |
| A2 | Endpoint normalization: `/users/{user_id}` == runtime URL z konkretnym ID | `scripts/benchmark_lab.py`, `execution_plane/crawler/asset_map.py` | codex-main | metrics tests | TP nie przepada przez format sciezki |
| A3 | Golden failure report: lista FN z brakujacym etapem pipeline | `scripts/benchmark_lab.py` | codex-main | benchmark tests | wiadomo czy gap jest planner/worker/validator/scorer |

### Workstream B - First 5 detections

| ID | Zadanie | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| B1 | BOLA + tenant isolation benchmark detections end-to-end | `execution_plane/planner/rules/bola.py`, `tenant_isolation.py`, validator strategies | codex-main | benchmark + unit | 2 TP z differential proof |
| B2 | BFLA + privilege escalation benchmark detections end-to-end | `execution_plane/planner/rules/bfla.py`, `privilege_escalation.py`, validator strategies | codex-dad | benchmark + unit | 2 TP z role/identity proof |
| B3 | Auth bypass benchmark detection end-to-end | `execution_plane/planner/rules/auth_bypass.py`, `execution_plane/validator/strategies/auth_bypass.py` | codex-main | benchmark + unit | 1 TP z structural response proof |

### Workstream C - Noise and proof gates

| ID | Zadanie | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| C1 | FP budget gate: benchmark failuje gdy FP > 0 dla labu | `scripts/benchmark_lab.py`, integration tests | codex-main | benchmark | false positive budget egzekwowany |
| C2 | Proof artifact completeness: confidence, evidence_notes, attack_probe_id, identity context | `control_plane/finding_scorer.py`, validators | codex-main | unit + benchmark | kazdy TP ma audytowalny dowod |
| C3 | FN report w JSON: `missing_detection_stage` i `suggested_next_sprint` | `scripts/benchmark_lab.py` | codex-main | metrics tests | backlog powstaje z metryk |

### Guardrails

- Nie obnizac `DEFAULT_PROOF_CONFIDENCE_THRESHOLD`.
- Nie zaliczac TP bez proof artifact.
- Nie dopisywac special-case pod ID podatnosci; benchmark ma wykrywac wzorzec, nie manifest.

### Weryfikacja

```bash
python scripts/benchmark_lab.py --full --min-coverage 0.71 --max-fp 0
python -m pytest tests/unit/execution_plane/planner/ -q
python -m pytest tests/unit/execution_plane/validator/ -q
python -m pytest tests/unit/ -q
```

### Global acceptance criteria

- [ ] Benchmark full osiaga minimum 5 TP / 7 FN<=2.
- [ ] FP == 0.
- [ ] Kazdy TP ma proof artifact i confidence >= 0.85.
- [ ] JSON pokazuje pozostale FN oraz etap, gdzie pipeline zawiodl.

### Podzial pracy - codex-dad

B2 ida do **codex-dad** jako bounded implementation package. Reszte robi **codex-main**.
