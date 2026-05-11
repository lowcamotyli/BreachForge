## Sprint 50 - Multi-Identity Auth Matrix

**Goal:** Zastapic syntetyczne role realna macierza tozsamosci: user/admin/tenantA/tenantB maja osobne sesje, zdrowie i dowody differential.

### Architektura - dokumenty referencyjne

```bash
DAD_PROMPT="cd /mnt/d/BreachForge && Read docs/architecture/auth-architecture.md and docs/architecture/attack-engine.md. Extract: IdentityContext, SessionSnapshot, planner identity needs, BOLA/tenant/privilege flow. Bullets. Max 25 lines." bash ~/.claude/scripts/dad-exec.sh
```

### Workstream A - Scan input to stored identity matrix

| ID | Zadanie | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| A1 | `ScanCreate.identities[]` faktycznie zapisywane do AuthContext/identity store | `api/models/requests.py`, `api/routers/scans.py`, `control_plane/auth_manager.py` | codex-dad | API/auth tests | wiele identities trafia do runtime |
| A2 | Kazda identity ma `name`, `role_hint`, `tenant_hint`, `auth_state`, snapshot ref | `control_plane/auth_manager.py` | codex-dad | auth tests | AuthManager listuje realne identities |
| A3 | Credential fields szyfrowane per identity | `control_plane/auth_manager.py`, `storage/db/encryption.py` | codex-dad | encryption tests | brak plaintext credentials |

### Workstream B - Worker identity selection

| ID | Zadanie | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| B1 | Worker wybiera realny `IdentityContext` po `identity_selector`, nie naglowek syntetyczny | `execution_plane/workers/attack_worker.py` | codex-main | worker tests | request uzywa cookies/tokenow wybranej identity |
| B2 | `anonymous` nadal daje empty session | `execution_plane/workers/attack_worker.py` | codex-main | regression tests | unauth flow nie regreduje |
| B3 | Health failure identity: pause/skip zgodnie z policy, bez cichych false negative | `control_plane/auth_manager.py`, `execution_plane/workers/dispatcher.py` | codex-main | lifecycle tests | expired identity jest widoczna w scan events |

### Workstream C - Planner/validator differential

| ID | Zadanie | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| C1 | Planner dostaje identity matrix i generuje BOLA/tenant/privilege pary | `execution_plane/planner/planner.py`, `rules/bola.py`, `rules/tenant_isolation.py`, `rules/privilege_escalation.py` | codex-dad | planner tests | tasks maja explicit identity selectors |
| C2 | Validator porownuje odpowiedzi miedzy realnymi identities | `execution_plane/validator/validator.py`, relevant strategies | codex-dad | validator tests | finding wymaga differential proof |
| C3 | Raport pokazuje identities uzyte w dowodzie bez sekretow | `control_plane/reporting.py` | codex-main | reporting tests | chain/finding ma identity labels |

### Guardrails

- Nie generowac fałszywych adminow przez `X-Identity-Role`, jesli target sam tego nie wymaga.
- Identity labels moga byc raportowane, credentials nigdy.
- Expired identity nie moze byc interpretowana jako brak podatnosci.

### Weryfikacja

```bash
python -m pytest tests/unit/control_plane/test_auth_manager.py -q
python -m pytest tests/unit/execution_plane/workers/ -q
python -m pytest tests/unit/execution_plane/planner/test_bola_rule.py -q
python -m pytest tests/unit/execution_plane/validator/test_validator_identity_aware.py -q
python -m pytest tests/unit/ -q
```

### Global acceptance criteria

- [ ] Scan przyjmuje i przechowuje wiele realnych identities.
- [ ] Worker wykonuje taski pod wskazana identity.
- [ ] BOLA/tenant/privilege uzywaja realnych differential probes.
- [ ] Raport pokazuje identity context bez sekretow.

### Podzial pracy - codex-dad

A i C ida do **codex-dad** z powodu szerokiego kontekstu auth/planner/validator. B i raportowe glue robi **codex-main**.
