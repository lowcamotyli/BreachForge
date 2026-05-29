from __future__ import annotations

import os
from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest
from cryptography.fernet import Fernet
from sqlalchemy.ext.asyncio import AsyncSession

from storage.secrets.vault import SecretStatus, SecretType, SecretsVault


class _ScalarResult:
    def __init__(self, row):
        self._row = row

    def scalar_one_or_none(self):
        return self._row


class _ScalarsListResult:
    def __init__(self, rows):
        self._rows = rows

    def scalars(self):
        return self

    def all(self):
        return self._rows


@pytest.fixture(autouse=True)
def _vault_encryption_key() -> None:
    os.environ["VAULT_ENCRYPTION_KEY"] = Fernet.generate_key().decode()


@pytest.fixture
def mock_session() -> AsyncMock:
    session = AsyncMock(spec=AsyncSession)
    session.execute = AsyncMock()
    session.add = MagicMock()
    session.commit = AsyncMock()
    return session


def _secret_row(
    *,
    org_id,
    name: str,
    secret_type: SecretType,
    ciphertext: str,
    status: SecretStatus = SecretStatus.active,
    version: int = 1,
):
    now = datetime.now(UTC)
    return SimpleNamespace(
        id=uuid4(),
        org_id=org_id,
        name=name,
        secret_type=secret_type.value,
        ciphertext=ciphertext,
        status=status.value,
        version=version,
        created_at=now,
        expires_at=None,
        rotated_at=None,
        revoked_at=None,
        deleted_at=None,
        redacted_preview="",
        metadata_json={},
    )


@pytest.mark.asyncio
async def test_store_creates_secret_entry_with_active_status_and_redacted_preview(mock_session: AsyncMock) -> None:
    vault = SecretsVault(session=mock_session)
    org_id = uuid4()

    entry = await vault.store(org_id, "GitHub", SecretType.provider_token, "plaintext-token")

    assert entry.org_id == org_id
    assert entry.name == "GitHub"
    assert entry.secret_type == SecretType.provider_token
    assert entry.status == SecretStatus.active
    assert entry.version == 1
    assert entry.redacted_preview == "plai..."
    assert entry.ciphertext != "plaintext-token"
    mock_session.add.assert_called_once()
    mock_session.commit.assert_awaited_once()


@pytest.mark.asyncio
async def test_retrieve_returns_plaintext_for_active_secret(mock_session: AsyncMock) -> None:
    vault = SecretsVault(session=mock_session)
    org_id = uuid4()
    row = _secret_row(
        org_id=org_id,
        name="CI",
        secret_type=SecretType.api_credential,
        ciphertext=vault._encrypt("secret-value"),
        status=SecretStatus.active,
    )
    mock_session.execute.return_value = _ScalarResult(row)

    plaintext = await vault.retrieve(row.id)

    assert plaintext == "secret-value"
    mock_session.execute.assert_awaited_once()


@pytest.mark.asyncio
async def test_retrieve_returns_none_for_revoked_secret(mock_session: AsyncMock) -> None:
    vault = SecretsVault(session=mock_session)
    row = _secret_row(
        org_id=uuid4(),
        name="CI",
        secret_type=SecretType.api_credential,
        ciphertext=vault._encrypt("secret-value"),
        status=SecretStatus.revoked,
    )
    mock_session.execute.return_value = _ScalarResult(row)

    assert await vault.retrieve(row.id) is None
    mock_session.execute.assert_awaited_once()


@pytest.mark.asyncio
async def test_rotate_updates_ciphertext_increments_version_and_sets_rotated_at(mock_session: AsyncMock) -> None:
    vault = SecretsVault(session=mock_session)
    org_id = uuid4()
    row = _secret_row(
        org_id=org_id,
        name="CI",
        secret_type=SecretType.api_credential,
        ciphertext=vault._encrypt("secret-value"),
        status=SecretStatus.active,
        version=1,
    )
    original_ciphertext = row.ciphertext
    mock_session.execute.return_value = _ScalarResult(row)

    rotated = await vault.rotate(row.id, "rotated-value")

    assert rotated is not None
    assert rotated.ciphertext != original_ciphertext
    assert rotated.version == 2
    assert rotated.rotated_at is not None
    assert row.redacted_preview == "rota..."
    mock_session.execute.assert_awaited_once()
    mock_session.commit.assert_awaited_once()


@pytest.mark.asyncio
async def test_revoke_sets_status_revoked_and_revoked_at(mock_session: AsyncMock) -> None:
    vault = SecretsVault(session=mock_session)
    row = _secret_row(
        org_id=uuid4(),
        name="CI",
        secret_type=SecretType.api_credential,
        ciphertext=vault._encrypt("secret-value"),
        status=SecretStatus.active,
    )
    mock_session.execute.return_value = _ScalarResult(row)

    assert await vault.revoke(row.id) is True

    assert row.status == SecretStatus.revoked.value
    assert row.revoked_at is not None
    mock_session.execute.assert_awaited_once()
    mock_session.commit.assert_awaited_once()


@pytest.mark.asyncio
async def test_delete_sets_status_deleted_and_deleted_at(mock_session: AsyncMock) -> None:
    vault = SecretsVault(session=mock_session)
    row = _secret_row(
        org_id=uuid4(),
        name="CI",
        secret_type=SecretType.api_credential,
        ciphertext=vault._encrypt("secret-value"),
        status=SecretStatus.active,
    )
    mock_session.execute.return_value = _ScalarResult(row)

    assert await vault.delete(row.id) is True

    assert row.status == SecretStatus.deleted.value
    assert row.deleted_at is not None
    mock_session.execute.assert_awaited_once()
    mock_session.commit.assert_awaited_once()


@pytest.mark.asyncio
async def test_list_for_org_filters_by_org_id_and_excludes_deleted_by_default(mock_session: AsyncMock) -> None:
    vault = SecretsVault(session=mock_session)
    org_id = uuid4()
    retained_row = _secret_row(
        org_id=org_id,
        name="A",
        secret_type=SecretType.auth_bundle,
        ciphertext=vault._encrypt("secret-a"),
        status=SecretStatus.active,
    )
    deleted_row = _secret_row(
        org_id=org_id,
        name="B",
        secret_type=SecretType.auth_bundle,
        ciphertext=vault._encrypt("secret-b"),
        status=SecretStatus.deleted,
    )
    mock_session.execute.side_effect = [
        _ScalarsListResult([retained_row]),
        _ScalarsListResult([retained_row, deleted_row]),
    ]

    default_list = await vault.list_for_org(org_id)
    full_list = await vault.list_for_org(org_id, include_deleted=True)

    assert [entry.name for entry in default_list] == ["A"]
    assert [entry.name for entry in full_list] == ["A", "B"]
    assert mock_session.execute.await_count == 2


@pytest.mark.asyncio
async def test_get_versions_returns_current_version_metadata(mock_session: AsyncMock) -> None:
    vault = SecretsVault(session=mock_session)
    row = _secret_row(
        org_id=uuid4(),
        name="CI",
        secret_type=SecretType.api_credential,
        ciphertext=vault._encrypt("secret-value"),
        status=SecretStatus.active,
        version=2,
    )
    row.rotated_at = datetime.now(UTC)
    mock_session.execute.return_value = _ScalarResult(row)

    versions = await vault.get_versions(row.id)

    assert [version.version for version in versions] == [2]
    assert versions[0].status == SecretStatus.active
    assert versions[0].ciphertext == row.ciphertext
    mock_session.execute.assert_awaited_once()
