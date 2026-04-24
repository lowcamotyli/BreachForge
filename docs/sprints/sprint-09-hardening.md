## Sprint 9 — Production Hardening

**Goal:** Rate limiter (Redis token bucket); KMS envelope encryption; structlog credential stripping; Docker production images; ECS task definitions.

### Architektura — dokumenty referencyjne

```bash
DAD_PROMPT="Read /mnt/d/SimpliAppSec/docs/architecture/security-constraints.md. Extract: ALL rate limits (default + production-safe), credential handling rules, scan isolation requirements, evidence redaction rules. Bullets. Max 25 lines." bash ~/.claude/scripts/dad-exec.sh
```

### Dispatch table

| Plik | Worker | Skill | Uwagi |
|------|--------|-------|-------|
| `control_plane/rate_limiter.py` | codex-main | `skill:scoped-implementation` | Redis token bucket |
| `api/middleware/logging.py` | codex-main | `skill:scoped-implementation` | structlog credential stripping |
| `storage/db/encryption.py` | codex-dad | `skill:scoped-implementation` | KMS — wrażliwe, Claude review |
| `docker/Dockerfile.api` + `Dockerfile.worker` | codex-dad | `skill:scoped-implementation` | parallel |
| `infra/ecs/api-task.json` + `worker-task.json` | codex-dad | `skill:scoped-implementation` | parallel |

### Prompty

```bash
# codex-main — rate_limiter + logging (batch)
codex exec --dangerously-bypass-approvals-and-sandbox \
'Read d:/SimpliAppSec/.workflow/skills/scoped-implementation.md and follow its procedure.
Do NOT use Gemini — write directly.
Goal: Two production hardening files:
1. d:/SimpliAppSec/control_plane/rate_limiter.py — DomainRateLimiter
   - Redis token bucket: key f"rate:{scan_id}:{domain}", refill at configured RPS
   - acquire(scan_id, domain) -> bool: returns False if budget exhausted
   - Default: 2.5 req/s total per scan (150/min), 0.5 req/s per worker (30/min)
   - production_safe mode: 1.0 req/s, excludes POST/PUT/PATCH/DELETE
   - Config from env: RATE_LIMIT_RPS, PRODUCTION_SAFE_MODE
   - from __future__ import annotations
2. d:/SimpliAppSec/api/middleware/logging.py — structlog configuration
   - configure_logging(): sets up structlog with JSON renderer
   - CredentialStripper processor: strips values of keys matching Authorization, Cookie, password, token, secret, key (case-insensitive)
   - Adds timestamp, log_level, scan_id context
   - from __future__ import annotations
Done when: both files exist with all stated functionality.'

# codex-dad — encryption + Docker + ECS (batch parallel)
DAD_PROMPT='Read /mnt/d/SimpliAppSec/.workflow/skills/scoped-implementation.md and follow its procedure.
Read /mnt/d/SimpliAppSec/docs/architecture/security-constraints.md for encryption requirements.
Read /mnt/d/SimpliAppSec/pyproject.toml for dependency reference.
Goal: 5 files:
1. /mnt/d/SimpliAppSec/storage/db/encryption.py — EnvelopeEncryption
   - encrypt_credential(plaintext: str, scan_id: UUID) -> EncryptedBlob: generates data key via KMS, encrypts with cryptography Fernet, stores encrypted data key + ciphertext
   - decrypt_credential(blob: EncryptedBlob, scan_id: UUID) -> str: decrypts data key via KMS, decrypts ciphertext
   - KMS_MASTER_KEY_ID from env
   - from __future__ import annotations
2. /mnt/d/SimpliAppSec/docker/Dockerfile.api — Python 3.12 slim, installs pyproject.toml deps, runs uvicorn
3. /mnt/d/SimpliAppSec/docker/Dockerfile.worker — Python 3.12 slim, installs playwright chromium, runs rq worker
4. /mnt/d/SimpliAppSec/infra/ecs/api-task.json — ECS Fargate task definition for API service, 512 CPU / 1024 memory
5. /mnt/d/SimpliAppSec/infra/ecs/worker-task.json — ECS Fargate task definition for attack workers, 1024 CPU / 2048 memory
Done when: all 5 files exist.' bash ~/.claude/scripts/dad-exec.sh
```

### Weryfikacja

```bash
python -m pytest tests/ -q
docker compose -f d:/SimpliAppSec/docker/docker-compose.yml build
```

### Acceptance criteria

- [ ] `DomainRateLimiter.acquire()` returns False when budget exhausted (nie crash)
- [ ] `CredentialStripper` processor strips Authorization/Cookie/password/token z każdego log event
- [ ] `EnvelopeEncryption`: data key per scan, master key z KMS — nigdy hardcoded
- [ ] `production_safe` mode wyklucza POST/PUT/PATCH/DELETE attack tasks
- [ ] `docker compose build` kończy się bez błędów

### Post-sprint: przegląd skillów

Czy pojawił się nowy powtarzalny pattern? Jeśli tak — zaktualizuj lub dodaj skill w `.workflow/skills/` przed zamknięciem sprintu. Reguła: pattern >= 2x → skodyfikuj.

