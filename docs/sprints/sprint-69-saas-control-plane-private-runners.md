## Sprint 69 - SaaS Control Plane And Private Runners

**Goal:** Przejsc z engineu do produktu kupowalnego przez zespoly: organizacje, projekty, RBAC, API keys, audit, private runners i bezpieczne zarzadzanie sekretami.

### Architektura - dokumenty referencyjne

```bash
{
  echo "=== FILE: data-model.md ==="; cat ~/BreachForge/docs/architecture/data-model.md
  echo "=== FILE: storage-infra.md ==="; cat ~/BreachForge/docs/architecture/storage-infra.md
  echo "=== FILE: security-constraints.md ==="; cat ~/BreachForge/docs/architecture/security-constraints.md
} | gemini --output-format text \
  -p "Files above. Extract SaaS/multi-tenant/private-runner data model gaps: org isolation, RBAC, pull-based runner protocol, secrets lifecycle, data deletion. Bullets. Max 45 lines." \
  2>&1 | grep -v "^Warning:" | grep -v "^Ripgrep"
```

### Workstream A - Product tenancy and RBAC

| ID | Zadanie | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| A1 | Org/project/service-group models with tenant isolation guarantees | `storage/db/models.py`, migrations | codex-main | model tests | dane klientow sa separowane |
| A2 | RBAC roles: owner, appsec_admin, developer, auditor, runner | API/auth middleware | codex-dad | API permission tests | uprawnienia sa egzekwowane w API |
| A3 | API keys and service tokens with scoped permissions and rotation | API/storage/encryption | codex-main | token tests | integracje nie uzywaja user password |

### Workstream B - Private runner architecture

| ID | Zadanie | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| B1 | Runner registration, heartbeat, version/capability reporting | `execution_plane/runners/`, API routers | codex-main | runner tests | customer runner jest widoczny i health-checked |
| B2 | Job lease protocol: signed scan package, pull model, no inbound customer network requirement | runners/orchestrator | codex-dad | integration tests | private runner dziala za firewallem |
| B3 | Artifact upload protocol: encrypted evidence, chunking, retry, integrity hash | evidence store/runners | codex-main | artifact tests | dowody trafiaja do control plane bez korupcji |

### Workstream C - Secrets and telemetry

| ID | Zadanie | Pliki | Worker | Testy | Definition of Done |
|---|---|---|---|---|---|
| C1 | Secrets vault abstraction for auth bundles, tokens and provider creds | storage/encryption/API | codex-main | encryption tests | secrets maja lifecycle i redakcje |
| C2 | Minimal telemetry model: performance/error/coverage metrics bez request payloadow | observability/reporting | codex-main | telemetry tests | produkt moze byc utrzymywany bez leakow |
| C3 | Tenant audit exports and data deletion workflow | API/storage/reporting | codex-dad | deletion/audit tests | enterprise compliance request jest obslugiwany |

### Dispatch pattern

**Phase 1 (parallel):** main → A1, A3, B1, B3; dad → (brak — A2 zalezy od A1, B2 od B1)
**Phase 2 (parallel, po verify):** main → C1, C2; dad → A2 → B2 → C3
**Dad sequence:** A2 (po A1 modelu) → B2 (po B1 rejestracji) → C3 (po A1+B1)
**Kluczowe zaleznosci:** A2 wymaga A1 (RBAC na modelu org); B2 wymaga B1 (job lease po rejestracji); C3 wymaga A1+B1

### Guardrails

- Private runner nigdy nie dostaje danych innych projektow/org.
- Pull-based runner preferred; brak wymogu otwierania inbound portow u klienta.
- Telemetry nie zawiera body requestow, headers z sekretami ani tokenow.
- Data deletion usuwa evidence i auth material zgodnie z retention policy.

### Weryfikacja

```bash
python -m pytest tests/unit/storage/ -q
python -m pytest tests/unit/api/test_rbac.py -q
python -m pytest tests/integration/test_private_runner.py -q
python -m pytest tests/unit/ -q
```

### TL_PROMPT

```bash
TL_PROMPT="Read ~/BreachForge/.workflow/skills/testing-lead.md and follow it.
Sprint: 69 - SaaS Control Plane And Private Runners
Changed: storage/db/models.py, api/, execution_plane/runners/, storage/encryption/
Test cases:
- Multi-tenant org/project model jest egzekwowany testami (dane klientow sa separowane)
- Private runner moze pobrac job i wyslac evidence (pull model, bez inbound portow)
- Secrets vault obsluguje rotation/deletion/redaction
- RBAC i audit sa gotowe pod enterprise beta" bash ~/.claude/scripts/testing-lead-exec.sh < /dev/null
```

### Global acceptance criteria

- [ ] Multi-tenant org/project model jest egzekwowany testami.
- [ ] Private runner moze pobrac job i wyslac evidence.
- [ ] Secrets vault obsluguje rotation/deletion/redaction.
- [ ] RBAC i audit sa gotowe pod enterprise beta.

### Podzial pracy - codex-dad

A2, B2 i C3 ida do **codex-dad**. Reszte robi **codex-main**.
