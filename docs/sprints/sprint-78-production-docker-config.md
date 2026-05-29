## Sprint 78 — Production Docker Config + Alembic Fresh Start

**Goal:** Usunąć LocalStack z docker-compose, stworzyć produkcyjny docker-compose bez hardcoded credentials,
zweryfikować że `alembic upgrade head` przechodzi od pustej DB.

### Problem

Aktualny `docker/docker-compose.yml`:
- Używa `localstack/localstack:3.8.1` dla S3 i KMS → nie ma w produkcji
- `POSTGRES_PASSWORD: proofscan` → hardcoded
- `AWS_ENDPOINT_URL: http://localstack:4566` → prod API trafi w LocalStack jeśli zły config
- Brak oddzielnego produkcyjnego compose → dev i prod config są tym samym plikiem

Dodatkowo: nigdy nie zweryfikowano że wszystkie migracje przechodzą od pustej DB w jednym kroku.

### Scope

**Tworzymy:**
- `docker/docker-compose.prod.yml` — prod target, bez LocalStack, bez hardcoded haseł
- `.env.example` — dokumentacja wszystkich wymaganych env vars
- `tests/integration/test_alembic_fresh.py` — weryfikacja że `alembic upgrade head` od zera działa

**Modyfikujemy:**
- `docker/docker-compose.yml` (dev) — wyraźne oznaczenie jako "DEV ONLY", dev passwords OK
- `docker/Dockerfile.api` — non-root user jeśli nie ma, no dev deps w prod target

**Nie zmieniamy:**
- Alembic migrations (nie dotykamy istniejących migracji)
- Kodu aplikacji

### Architektura — dokumenty referencyjne

```bash
cat ~/Projects/BreachForge/docs/architecture/storage-infra.md \
  | gemini --output-format text \
  -p "Extract: production deployment requirements, AWS services needed (S3 bucket, KMS key, RDS), required env vars. Bullets. Max 25 lines." \
  2>&1 | grep -v "^Warning:" | grep -v "^Ripgrep"
```

### Workstream A — Production compose i env vars

| ID | Zadanie | Pliki | Worker |
|---|---|---|---|
| A1 | `docker/docker-compose.prod.yml`: postgres i redis z secrets zamiast hardcoded passwords, brak localstack service, API service z `env_file: .env.prod` | `docker/docker-compose.prod.yml` (nowy) | codex-main |
| A2 | `.env.example`: wszystkie wymagane env vars z opisem (DATABASE_URL, REDIS_URL, AWS_REGION, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, S3_BUCKET_NAME, KMS_MASTER_KEY_ID, VAULT_ENCRYPTION_KEY, PROOFSCAN_DEV_MODE) | `.env.example` (nowy) | codex-main |

### Workstream B — Dockerfile hardening

| ID | Zadanie | Pliki | Worker |
|---|---|---|---|
| B1 | `docker/Dockerfile.api`: multi-stage build — `dev` stage ma dev deps, `prod` stage bez dev deps; non-root user `appuser:appuser` w prod stage | `docker/Dockerfile.api` | codex-dad |

### Workstream C — Alembic fresh start test

| ID | Zadanie | Pliki | Worker |
|---|---|---|---|
| C1 | `tests/integration/test_alembic_fresh.py`: test który startuje fresh Postgres, uruchamia `alembic upgrade head`, weryfikuje że wszystkie oczekiwane tabele istnieją | `tests/integration/test_alembic_fresh.py` (nowy) | codex-main |

### Dispatch pattern

**Parallel:** main → A1, A2, C1; dad → B1 (wszystko niezależne)

### Guardrails

- `docker-compose.prod.yml` NIE może zawierać: `localstack`, hardcoded passwords, `AWS_ENDPOINT_URL`
- `docker-compose.prod.yml` MUSI używać Docker secrets lub `env_file: .env.prod` — nie inline `environment:`
- `Dockerfile.api` prod stage: `USER appuser` na końcu, brak `pip install pytest`, brak dev tools
- `.env.example` musi zawierać: `VAULT_ENCRYPTION_KEY` (wymagany od Sprint 76), `KMS_MASTER_KEY_ID`, wszystkie AWS vars
- Test alembic musi używać oddzielnej test DB (nie dev postgres)

### Weryfikacja

```bash
# Sprawdź że LocalStack jest poza prod compose:
grep -n "localstack\|AWS_ENDPOINT_URL" docker/docker-compose.prod.yml
# Wynik: 0 linii

# Sprawdź że non-root user jest w Dockerfile:
grep -n "USER\|appuser" docker/Dockerfile.api
# Wynik: min 1 linia

# Sprawdź że .env.example ma wszystkie wymagane vars:
cat .env.example | grep -E "VAULT_ENCRYPTION_KEY|KMS_MASTER_KEY_ID|DATABASE_URL|REDIS_URL|S3_BUCKET"
# Wynik: 5 linii

# Alembic fresh start test:
python -m pytest tests/integration/test_alembic_fresh.py -v
```

### TL_PROMPT

```bash
TL_PROMPT="Read ~/Projects/BreachForge/.workflow/skills/testing-lead.md and follow it.
Sprint: 78 - Production Docker Config
Changed: docker/docker-compose.prod.yml, .env.example, docker/Dockerfile.api, tests/integration/test_alembic_fresh.py
Test cases:
- docker-compose.prod.yml nie zawiera localstack ani hardcoded passwords
- Dockerfile.api ma multi-stage build z non-root user w prod stage
- .env.example dokumentuje wszystkie wymagane env vars
- alembic upgrade head od pustej DB przechodzi bez błędów" bash ~/.claude/scripts/testing-lead-exec.sh < /dev/null
```

### Global acceptance criteria

- [ ] `docker/docker-compose.prod.yml` istnieje, brak `localstack`, brak `AWS_ENDPOINT_URL`, brak hardcoded passwords
- [ ] `docker/Dockerfile.api` ma prod stage z non-root user
- [ ] `.env.example` zawiera `VAULT_ENCRYPTION_KEY`, `KMS_MASTER_KEY_ID`, `DATABASE_URL`, `REDIS_URL`, `S3_BUCKET_NAME`
- [ ] `tests/integration/test_alembic_fresh.py` przechodzi (alembic upgrade head od pustej DB)
- [ ] `docker/docker-compose.yml` ma komentarz "DEV ONLY" na górze
