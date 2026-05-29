from __future__ import annotations

import os
from typing import Any
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest
from cryptography.fernet import Fernet
from sqlalchemy.ext.asyncio import AsyncSession

from storage.db.models import Secret


TEST_KEY = Fernet.generate_key()


class _FernetVaultProbe:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session
        self._fernet = Fernet(os.environ["VAULT_ENCRYPTION_KEY"].encode())

    def encrypt(self, plaintext: str) -> str:
        return self._fernet.encrypt(plaintext.encode()).decode()

    async def retrieve(self, secret_id: object) -> str | None:
        result = await self._session.execute(secret_id)
        secret = result.scalar_one_or_none()
        if secret is None:
            return None
        return self._fernet.decrypt(secret.ciphertext.encode()).decode()


@pytest.fixture(autouse=True)
def vault_encryption_key() -> None:
    original = os.environ.get("VAULT_ENCRYPTION_KEY")
    os.environ["VAULT_ENCRYPTION_KEY"] = TEST_KEY.decode()
    yield
    if original is None:
        os.environ.pop("VAULT_ENCRYPTION_KEY", None)
        return
    os.environ["VAULT_ENCRYPTION_KEY"] = original


def _mock_async_session(secret: Secret | None = None) -> MagicMock:
    result = MagicMock()
    result.scalar_one_or_none.return_value = secret

    session = MagicMock(spec=AsyncSession)
    session.execute = AsyncMock(return_value=result)
    return session


def _secret_row(ciphertext: str, **overrides: Any) -> Secret:
    values = {
        "id": uuid4(),
        "org_id": uuid4(),
        "name": "CI token",
        "secret_type": "api_credential",
        "ciphertext": ciphertext,
        "status": "active",
        "version": 1,
    }
    values.update(overrides)
    return Secret(**values)


def test_encrypt_produces_different_ciphertext_each_time() -> None:
    session = _mock_async_session()
    vault = _FernetVaultProbe(session)
    plaintext = "same-plaintext"

    first_ciphertext = vault.encrypt(plaintext)
    second_ciphertext = vault.encrypt(plaintext)

    assert first_ciphertext != second_ciphertext


def test_ciphertext_does_not_contain_key() -> None:
    session = _mock_async_session()
    vault = _FernetVaultProbe(session)
    plaintext = "secret-value"

    ciphertext = vault.encrypt(plaintext)

    assert TEST_KEY not in ciphertext.encode()
    assert f"{TEST_KEY.hex()}:" not in ciphertext


@pytest.mark.asyncio
async def test_store_and_retrieve_roundtrip() -> None:
    session = _mock_async_session()
    vault = _FernetVaultProbe(session)
    secret_id = uuid4()
    plaintext = "roundtrip-secret"
    encrypted_value = vault.encrypt(plaintext)
    secret = _secret_row(encrypted_value, id=secret_id)
    session.execute.return_value.scalar_one_or_none.return_value = secret

    retrieved = await vault.retrieve(secret_id)

    assert retrieved == plaintext
