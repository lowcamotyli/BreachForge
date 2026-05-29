from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import UUID, uuid4

from cryptography.fernet import Fernet
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from storage.db.models import Secret

try:
    from storage.db.encryption import EncryptedBlob, EnvelopeEncryption
except Exception:  # pragma: no cover - optional KMS dependency path
    EncryptedBlob = None
    EnvelopeEncryption = None


class SecretType(StrEnum):
    auth_bundle = "auth_bundle"
    api_credential = "api_credential"
    provider_token = "provider_token"
    webhook_secret = "webhook_secret"


class SecretStatus(StrEnum):
    active = "active"
    rotated = "rotated"
    revoked = "revoked"
    deleted = "deleted"


@dataclass
class SecretEntry:
    secret_id: UUID
    org_id: UUID
    name: str
    secret_type: SecretType
    ciphertext: str
    status: SecretStatus
    version: int
    created_at: datetime
    expires_at: datetime | None = None
    rotated_at: datetime | None = None
    revoked_at: datetime | None = None
    deleted_at: datetime | None = None
    redacted_preview: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class SecretVersion:
    version: int
    secret_id: UUID
    ciphertext: str
    created_at: datetime
    status: SecretStatus


class SecretsVault:
    """
    Secrets vault with lifecycle management and DB persistence.
    """

    def __init__(self, session: AsyncSession, kms_client=None) -> None:
        self._session = session
        key = os.getenv("VAULT_ENCRYPTION_KEY", "")
        if not key:
            raise RuntimeError("VAULT_ENCRYPTION_KEY is required")
        self._fernet = Fernet(key)

        self._envelope = None
        master_key_id = os.getenv("KMS_MASTER_KEY_ID", "")
        if master_key_id and EnvelopeEncryption is not None:
            self._envelope = EnvelopeEncryption(kms_client=kms_client, master_key_id=master_key_id)
        self._kms_context_id: UUID | None = None

    async def store(
        self,
        org_id: UUID,
        name: str,
        secret_type: SecretType,
        plaintext: str,
        expires_at: datetime | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> SecretEntry:
        secret_id = uuid4()
        self._kms_context_id = org_id
        ciphertext = self._encrypt(plaintext)
        self._kms_context_id = None
        redacted_preview = self._redacted_preview(plaintext)
        created_at = datetime.now(UTC)

        secret_row = Secret(
            id=secret_id,
            org_id=org_id,
            name=name,
            secret_type=secret_type.value,
            ciphertext=ciphertext,
            status=SecretStatus.active.value,
            version=1,
            created_at=created_at,
            expires_at=expires_at,
            redacted_preview=redacted_preview,
            metadata_json=metadata or {},
        )
        self._session.add(secret_row)
        await self._session.commit()
        return self._to_entry(secret_row)

    async def retrieve(self, secret_id: UUID) -> str | None:
        result = await self._session.execute(select(Secret).where(Secret.id == secret_id))
        row = result.scalar_one_or_none()
        if row is None or row.status in (SecretStatus.revoked.value, SecretStatus.deleted.value):
            return None
        self._kms_context_id = row.org_id
        plaintext = self._decrypt(row.ciphertext)
        self._kms_context_id = None
        return plaintext

    async def rotate(self, secret_id: UUID, new_plaintext: str) -> SecretEntry | None:
        result = await self._session.execute(select(Secret).where(Secret.id == secret_id))
        row = result.scalar_one_or_none()
        if row is None or row.status != SecretStatus.active.value:
            return None

        self._kms_context_id = row.org_id
        new_ciphertext = self._encrypt(new_plaintext)
        self._kms_context_id = None
        now = datetime.now(UTC)
        row.ciphertext = new_ciphertext
        row.version += 1
        row.rotated_at = now
        row.redacted_preview = self._redacted_preview(new_plaintext)
        await self._session.commit()
        return self._to_entry(row)

    async def revoke(self, secret_id: UUID) -> bool:
        result = await self._session.execute(select(Secret).where(Secret.id == secret_id))
        row = result.scalar_one_or_none()
        if row is None:
            return False
        row.status = SecretStatus.revoked.value
        row.revoked_at = datetime.now(UTC)
        await self._session.commit()
        return True

    async def delete(self, secret_id: UUID) -> bool:
        result = await self._session.execute(select(Secret).where(Secret.id == secret_id))
        row = result.scalar_one_or_none()
        if row is None:
            return False
        row.status = SecretStatus.deleted.value
        row.deleted_at = datetime.now(UTC)
        await self._session.commit()
        return True

    async def list_for_org(self, org_id: UUID, include_deleted: bool = False) -> list[SecretEntry]:
        stmt = select(Secret).where(Secret.org_id == org_id)
        if not include_deleted:
            stmt = stmt.where(Secret.status != SecretStatus.deleted.value)
        result = await self._session.execute(stmt)
        return [self._to_entry(row) for row in result.scalars().all()]

    async def get_versions(self, secret_id: UUID) -> list[SecretVersion]:
        result = await self._session.execute(select(Secret).where(Secret.id == secret_id))
        row = result.scalar_one_or_none()
        if row is None:
            return []
        return [
            SecretVersion(
                version=row.version,
                secret_id=row.id,
                ciphertext=row.ciphertext,
                created_at=row.rotated_at or row.created_at,
                status=SecretStatus(row.status),
            )
        ]

    def _encrypt(self, plaintext: str) -> str:
        if self._envelope is not None:
            context_id = self._kms_context_id
            if context_id is None:
                raise RuntimeError("KMS encryption context is required")
            blob = self._envelope.encrypt_credential(plaintext, scan_id=context_id)
            return json.dumps(
                {"encrypted_data_key": blob.encrypted_data_key, "ciphertext": blob.ciphertext},
                separators=(",", ":"),
            )
        return self._fernet.encrypt(plaintext.encode()).decode()

    def _decrypt(self, ciphertext: str) -> str:
        if self._envelope is not None:
            context_id = self._kms_context_id
            if context_id is None:
                raise RuntimeError("KMS decryption context is required")
            blob_data = json.loads(ciphertext)
            if EncryptedBlob is None:
                raise RuntimeError("EnvelopeEncryption dependencies unavailable")
            blob = EncryptedBlob(
                encrypted_data_key=blob_data["encrypted_data_key"],
                ciphertext=blob_data["ciphertext"],
            )
            return self._envelope.decrypt_credential(
                blob=blob,
                scan_id=context_id,
            )
        return self._fernet.decrypt(ciphertext.encode()).decode()

    def _redacted_preview(self, plaintext: str) -> str:
        if len(plaintext) <= 4:
            return "***"
        return plaintext[:4] + "..."

    def _to_entry(self, row: Secret) -> SecretEntry:
        return SecretEntry(
            secret_id=row.id,
            org_id=row.org_id,
            name=row.name,
            secret_type=SecretType(row.secret_type),
            ciphertext=row.ciphertext,
            status=SecretStatus(row.status),
            version=row.version,
            created_at=row.created_at,
            expires_at=row.expires_at,
            rotated_at=row.rotated_at,
            revoked_at=row.revoked_at,
            deleted_at=row.deleted_at,
            redacted_preview=row.redacted_preview or "",
            metadata=row.metadata_json or {},
        )
