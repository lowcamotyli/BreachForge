## Sprint 76 — SecretsVault: Real Encryption + DB Persistence

**Goal:** Zastąpić fake XOR "encryption" w `SecretsVault` realnym szyfrowaniem (Fernet lub KMS envelope)
i zapisywać sekrety do bazy danych zamiast in-memory dict.

### Problem

```python
# storage/secrets/vault.py — aktualne zachowanie
def _encrypt(self, plaintext: str) -> str:
    key = secrets.token_bytes(len(plaintext_bytes))        # random key
    ciphertext = bytes(a ^ b for a, b in zip(plaintext_bytes, key))
    return key.hex() + ":" + ciphertext.hex()              # klucz i szyfr obok siebie
```

To **nie jest szyfrowanie** — klucz jest przechowywany razem z szyfrogramem w tym samym dict.
Każdy kto ma dostęp do pamięci procesu (lub DB dump) odszyfruje sekrety natychmiast.
Dodatkowo: vault jest in-memory → restart = wszystkie sekrety utracone.

### Scope

**Zmieniamy:**
- `SecretsVault._encrypt()` → Fernet (AES-128-CBC + HMAC z `cryptography` lib, już w zależnościach)
- Opcjonalnie: KMS envelope encryption gdy `KMS_MASTER_KEY_ID` ustawiony (integracja z `storage/db/encryption.py`)
- `SecretsVault` → persystuj `SecretEntry` do nowej tabeli `secrets` w DB
- Klucz Fernet: z `VAULT_ENCRYPTION_KEY` env var (32 bytes base64), NIE generowany losowo per encrypt

**Nie zmieniamy:**
- `SecretEntry`, `SecretVersion`, `SecretType`, `SecretStatus` dataclasses (API publiczne vaulta)
- Interfejs publiczny `SecretsVault` (metody: `store`, `retrieve`, `rotate`, `revoke`, `delete`)
- `storage/db/encryption.py` (nie psuć istniejącej KMS envelope encryption)

### Architektura — dokumenty referencyjne

```bash
cat ~/Projects/BreachForge/docs/architecture/storage-infra.md \
  | gemini --output-format text \
  -p "Extract: encryption at rest requirements, KMS integration pattern, secrets table design, retention rules. Bullets. Max 25 lines." \
  2>&1 | grep -v "^Warning:" | grep -v "^Ripgrep"
```

### Workstream A — Nowa migracja i ORM model

| ID | Zadanie | Pliki | Worker |
|---|---|---|---|
| A1 | Nowa migracja Alembic: tabela `secrets` (id, org_id, name, secret_type, ciphertext, status, version, created_at, expires_at, rotated_at, revoked_at, deleted_at, redacted_preview, metadata JSON) | nowa migracja `20260529000000_add_secrets_table.py` | codex-dad |
| A2 | ORM model `Secret` w `storage/db/models.py` | `storage/db/models.py` | codex-dad |

### Workstream B — Szyfrowanie i persystencja

| ID | Zadanie | Pliki | Worker |
|---|---|---|---|
| B1 | `storage/secrets/vault.py`: `_encrypt()` → Fernet z `VAULT_ENCRYPTION_KEY` env var; `_decrypt()` → Fernet decrypt; fallback: KMS envelope gdy `KMS_MASTER_KEY_ID` set | `storage/secrets/vault.py` | codex-dad |
| B2 | `storage/secrets/vault.py`: `store()`, `retrieve()`, `rotate()`, `revoke()` → async DB CRUD zamiast in-memory dict; konstruktor przyjmuje `AsyncSession` | `storage/secrets/vault.py` | codex-dad |

### Workstream C — Testy

| ID | Zadanie | Pliki | Worker |
|---|---|---|---|
| C1 | Test: `_encrypt()` produkuje różny ciphertext dla tego samego plaintext (Fernet używa IV) | `tests/unit/storage/test_vault_encryption.py` (nowy) | codex-main |
| C2 | Test: ciphertext bez klucza nie jest odszyfrowalny (klucz jest poza shyfrogramem) | `tests/unit/storage/test_vault_encryption.py` | codex-main |
| C3 | Test: `store()` + `retrieve()` przez mock AsyncSession zachowuje wartość | `tests/unit/storage/test_vault_encryption.py` | codex-main |

### Dispatch pattern

**Phase 1:** dad → A1, A2 (migracja i model najpierw)
**Phase 2 (po A1/A2):** dad → B1, B2 (szyfrowanie + persistence); main → C1-C3
**Zależność:** B2 importuje ORM model z A2

### Guardrails

- `VAULT_ENCRYPTION_KEY` musi być wymagany env var przy starcie — brak key → `RuntimeError`, nie default
- Fernet key musi być 32 bytes (URL-safe base64 encoded) — waliduj przy starcie
- `key.hex() + ":" + ciphertext.hex()` pattern musi być **całkowicie usunięty** z kodu
- `redacted_preview` jest nadal generowany przy store (pierwsze 4 znaki + "...") — nie zmienia się
- `SecretsVault` nie może importować globalnego `AsyncSession` — dependency injection przez konstruktor

### Weryfikacja

```bash
python -m pytest tests/unit/storage/ -q

# Sprawdź że XOR encryption jest usunięte:
grep -rn "token_bytes\|zip(plaintext\|key.hex()" storage/secrets/vault.py
# Wynik: 0 linii

# Sprawdź że Fernet jest używany:
grep -rn "Fernet\|VAULT_ENCRYPTION_KEY" storage/secrets/vault.py
# Wynik: min 2 linie
```

### TL_PROMPT

```bash
TL_PROMPT="Read ~/Projects/BreachForge/.workflow/skills/testing-lead.md and follow it.
Sprint: 76 - SecretsVault Real Encryption
Changed: storage/secrets/vault.py, storage/db/models.py, nowa migracja secrets table
Test cases:
- _encrypt() używa Fernet — ciphertext jest różny dla tego samego plaintextu (IV randomization)
- Klucz nie jest przechowywany obok ciphertextu — brak pattern key:ciphertext
- store() + retrieve() przez AsyncSession zwraca oryginalną wartość
- Brak VAULT_ENCRYPTION_KEY env var przy starcie → RuntimeError (nie default)" bash ~/.claude/scripts/testing-lead-exec.sh < /dev/null
```

### Global acceptance criteria

- [ ] `grep -rn "token_bytes.*zip\|key.hex()" storage/secrets/vault.py` → 0 wyników
- [ ] `grep -rn "Fernet\|VAULT_ENCRYPTION_KEY" storage/secrets/vault.py` → min 2 wyniki
- [ ] Tabela `secrets` w nowej migracji Alembic
- [ ] `store()` i `retrieve()` używają `AsyncSession`, nie in-memory dict
- [ ] Brak `VAULT_ENCRYPTION_KEY` → `RuntimeError` przy inicjalizacji vaulta
- [ ] Testy szyfrowania zielone
