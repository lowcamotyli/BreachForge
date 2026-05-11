## Sprint 26 - Multi-Identity Differential Lab

**Goal:** System porownuje odpowiedzi i mozliwosci wielu tozsamosci, aby wykrywac BOLA, privilege escalation, tenant isolation i auth bypass na poziomie zachowania aplikacji.

To jest najwiekszy skok jakosciowy w kierunku "najlepszych hakerow": narzedzie nie pyta tylko "czy endpoint dziala", ale "dla kogo dziala i czy powinien".

### Architektura - dokumenty referencyjne

```bash
DAD_PROMPT="Read /mnt/d/BreachForge/docs/architecture/auth-architecture.md and security-constraints.md. Extract constraints for session management, identity isolation, credential handling, and worker access. Bullets. Max 25 lines." bash ~/.claude/scripts/dad-exec.sh
```

### Workstream A - Identity Matrix

| ID | Zadanie | Pliki | Testy | Definition of Done |
|---|---|---|---|---|
| A1 | Dodaj `IdentityProfile` z role, tenant, auth_state, privilege_hint, session_ref | `control_plane/auth_manager.py` lub helper | auth tests | profile nie zawieraja raw credentials |
| A2 | Dodaj `IdentityMatrix` per scan | `control_plane/auth_manager.py` | unit tests | anon/user/admin/tenantA/tenantB sa opcjonalne i jawnie oznaczone |
| A3 | API/config scan request przyjmuje wiele identity references | `api/models/requests.py` | api tests | walidacja Pydantic v2 i brak secretow w response |

### Workstream B - Differential Probing

| ID | Zadanie | Pliki | Testy | Definition of Done |
|---|---|---|---|---|
| B1 | `DifferentialProbePlan`: same request across identities | `execution_plane/planner/differential.py` (new) | planner tests | plan okresla baseline i challengers |
| B2 | Worker pobiera swiezy `SessionSnapshot` per identity per task | `execution_plane/workers/attack_worker.py` | worker tests | brak lokalnego cache sesji w workerze |
| B3 | Response comparator: status, shape, stable fields, ownership markers, content length buckets | `execution_plane/validator/differential.py` (new) | validator tests | porownanie nie wymaga exfil body |

### Workstream C - Validators

| ID | Zadanie | Pliki | Testy | Definition of Done |
|---|---|---|---|---|
| C1 | BOLA validator v2: owner can access, cross-user can access, anon cannot | validator strategies | unit tests | confidence rosnie tylko przy differential proof |
| C2 | Tenant isolation validator: tenantA vs tenantB | validator strategies | unit tests | tenant mismatch wymaga supporting evidence |
| C3 | Privilege escalation validator: low vs elevated/admin | validator strategies | unit tests | observed access oddzielone od inferred role |

### Guardrails

- `AuthManager` pozostaje jedynym wlascicielem session state.
- Worker nie cache'uje sesji i nie zapisuje raw credentials.
- Differential proof nie pobiera masowo danych; porownuje metadane i bezpieczne fragmenty.
- Jezeli `AuthManager.health_check()` failuje, scan pauzuje z `auth_expired`.

### Weryfikacja

```bash
python -m pytest tests/unit/control_plane/ -q
python -m pytest tests/unit/execution_plane/validator/ -q
python -m pytest tests/integration/ -q
python -m pytest tests/unit/ -q
```

### Global acceptance criteria

- [ ] Skan moze uzywac wielu identity profiles.
- [ ] BOLA/tenant/privilege validators korzystaja z differential proof.
- [ ] Raport rozroznia owner, attacker identity i target identity.
- [ ] Testy potwierdzaja brak session cache w workerze.

### Post-sprint: przeglad skillow

Czy pojawil sie nowy powtarzalny pattern? Jesli tak - zaktualizuj lub dodaj skill w `.workflow/skills/` przed zamknieciem sprintu. Regula: pattern >= 2x -> skodyfikuj.
