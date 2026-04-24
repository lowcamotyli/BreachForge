## Sprint 21 - Secret Lifecycle Assessment

**Goal:** Ocenic, czy sekret jest krotkozyjacy, long-lived, wygasly, czy prawdopodobnie nadal aktywny.

Ten sprint odpowiada klientowi na pytanie: "czy rotacja/revocation jest pilna i jak zmienic lifecycle sekretow?".

### Architektura - dokumenty referencyjne

```bash
DAD_PROMPT="Read /mnt/d/SimpliAppSec/docs/architecture/security-constraints.md and auth-architecture.md. Extract constraints for token lifecycle, credential purge, and safe delayed checks. Bullets. Max 25 lines." bash ~/.claude/scripts/dad-exec.sh
```

### Workstream A - TTL & Expiration

| ID | Zadanie | Pliki | Testy | Definition of Done |
|---|---|---|---|---|
| A1 | Dodaj `SecretLifecycleAssessment` | `execution_plane/validator/secret_intelligence.py` | unit tests | model zawiera ttl, expired, long_lived, missing_exp |
| A2 | TTL z JWT `exp/iat/nbf` | classifier helper | unit tests | obliczenia stabilne z kontrolowanym czasem |
| A3 | Bucketowanie TTL: expired, short, medium, long, unknown | helper | unit tests | raport nie pokazuje sekretu |

### Workstream B - Revocation Posture

| ID | Zadanie | Pliki | Testy | Definition of Done |
|---|---|---|---|---|
| B1 | Oznacz `active_during_scan` na podstawie safe replay | scorer | scorer tests | aktywnosc wynika z proof artifact |
| B2 | Opcjonalny second-check po opoznieniu z malym limitem | dispatcher/worker | integration tests | check jest bounded i read-only |
| B3 | Env config dla delay/cap z bezpiecznym defaultem off lub very low | config helper | unit tests | clamp chroni przed dlugimi skanami |

### Workstream C - Remediation

| ID | Zadanie | Pliki | Testy | Definition of Done |
|---|---|---|---|---|
| C1 | Guidance: rotate, revoke, reduce TTL, bind audience, narrow scope | `control_plane/reporting.py` | reporting tests | guidance zalezy od lifecycle |
| C2 | Raport "Expiration and Revocation" | reporting | tests | klient widzi priorytet rotacji |
| C3 | JSON export lifecycle fields | reporting JSON | tests | integracje moga filtrowac long-lived |

### Guardrails

- Second-check nie moze spamowac endpointow.
- Brak mutacji i brak testow revocation przez uniewaznianie sekretu.
- Dla API key bez exp raportuj `unknown/missing_exp`, nie zgaduj daty.

### Weryfikacja

```bash
python -m pytest tests/unit/execution_plane/validator/ -q
python -m pytest tests/unit/execution_plane/workers/ -q
python -m pytest tests/unit/ -q
```

### Global acceptance criteria

- [ ] TTL i missing-exp sa raportowane dla JWT.
- [ ] Active during scan jest oparte o safe replay proof.
- [ ] Long-lived/missing-exp generuje konkretne remediation.
- [ ] Second-check jest bounded albo domyslnie wylaczony.

### Post-sprint: przeglad skillow

Czy pojawil sie nowy powtarzalny pattern? Jesli tak - zaktualizuj lub dodaj skill w `.workflow/skills/` przed zamknieciem sprintu. Regula: pattern >= 2x -> skodyfikuj.
