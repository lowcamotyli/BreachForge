## Sprint 24 - Attack Playbook DSL

**Goal:** Zamienic pojedyncze reguly ataku w kontrolowane playbooki: preconditions -> probes -> validators -> evidence -> safety budget.

Ten sprint daje fundament pod scenariusze "top attacker": narzedzie ma wykonywac sekwencje hipotez i krokow, a nie tylko izolowane payloady.

### Architektura - dokumenty referencyjne

```bash
DAD_PROMPT="Read /mnt/d/BreachForge/docs/architecture/attack-engine.md and security-constraints.md. Extract constraints for attack rules, proof-gate, worker isolation, rate limits, and evidence boundaries. Bullets. Max 25 lines." bash ~/.claude/scripts/dad-exec.sh
```

### Workstream A - Playbook Model

| ID | Zadanie | Pliki | Testy | Definition of Done |
|---|---|---|---|---|
| A1 | Dodaj dataclass `AttackPlaybook` z id, attack_class, preconditions, steps, validators, safety_budget | `execution_plane/planner/playbooks.py` (new) | planner unit tests | playbook serializuje sie i waliduje deterministycznie |
| A2 | Dodaj model `PlaybookStep` z action, identity_selector, probe_template, expected_signal, max_attempts | `execution_plane/planner/playbooks.py` | unit tests | step ma jawne limity i wymagany validator |
| A3 | Dodaj parser YAML/JSON dla playbookow | `execution_plane/planner/playbook_loader.py` (new) | loader tests | malformed playbook fail-closed |

### Workstream B - Built-in Playbooks

| ID | Zadanie | Pliki | Testy | Definition of Done |
|---|---|---|---|---|
| B1 | BOLA/IDOR chain: discover ids -> cross-user read -> cross-user write candidate -> safe validation | `execution_plane/planner/playbooks/bola_idor.yaml` (new) | corpus tests | chain generuje taski z identity context |
| B2 | Privilege drift chain: low user -> role-sensitive endpoint -> admin hint -> validator | `execution_plane/planner/playbooks/privilege_drift.yaml` (new) | corpus tests | rozroznia 401/403/200/404 i role hints |
| B3 | Workflow abuse chain: create draft -> skip approval -> replay final step -> safe proof | `execution_plane/planner/playbooks/workflow_abuse.yaml` (new) | corpus tests | mutacje sa blokowane bez explicit safe fixture |
| B4 | Secret-to-impact chain: secret discovery -> classification -> bounded replay -> blast-radius handoff | existing secret modules + playbook | integration tests | laczy sprinty 17-23 bez ujawnienia sekretu |

### Workstream C - Planner Integration

| ID | Zadanie | Pliki | Testy | Definition of Done |
|---|---|---|---|---|
| C1 | `AttackPlanner` wybiera playbooki na podstawie AssetMap i signals | `execution_plane/planner/planner.py` | planner tests | playbook selection jest explainable |
| C2 | Generuj `AttackTask` z playbook stepow | planner helper | integration tests | worker dostaje jawny step context |
| C3 | Zapisuj playbook progress w decision log | `execution_plane/planner/decision_log.py` | unit tests | kazdy step ma status i reason |

### Guardrails

- Playbook nie moze podniesc limitow scope/rate/proof-gate.
- Kazdy step musi wskazywac validator albo explicit `observe_only`.
- Playbooki sa konfiguracja ataku, ale finding tworzy tylko scorer po proof-gate.
- Secret value nie moze wystapic w playbook variables, logs ani decision log.

### Weryfikacja

```bash
python -m pytest tests/unit/execution_plane/planner/ -q
python -m pytest tests/integration/ -q
python -m pytest tests/unit/ -q
```

### Global acceptance criteria

- [ ] Minimum 4 built-in playbooki sa ladowane i walidowane.
- [ ] Planner potrafi wygenerowac chain taskow z playbooka.
- [ ] Decision log pokazuje dlaczego playbook zostal uruchomiony.
- [ ] Safety budget jest egzekwowany testami.

### Post-sprint: przeglad skillow

Czy pojawil sie nowy powtarzalny pattern? Jesli tak - zaktualizuj lub dodaj skill w `.workflow/skills/` przed zamknieciem sprintu. Regula: pattern >= 2x -> skodyfikuj.
