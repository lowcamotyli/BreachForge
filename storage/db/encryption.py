from __future__ import annotations

import base64
import os
from dataclasses import dataclass
from uuid import UUID

import boto3
from botocore.client import BaseClient
from cryptography.fernet import Fernet


@dataclass(frozen=True, slots=True)
class EncryptedBlob:
    encrypted_data_key: str
    ciphertext: str


class EnvelopeEncryption:
    def __init__(self, kms_client: BaseClient | None = None, master_key_id: str | None = None) -> None:
        self._kms = kms_client or boto3.client("kms")
        self._master_key_id = master_key_id or os.getenv("KMS_MASTER_KEY_ID", "")
        if not self._master_key_id:
            raise RuntimeError("KMS_MASTER_KEY_ID is required")

    def encrypt_credential(self, plaintext: str, scan_id: UUID, identity_name: str | None = None) -> EncryptedBlob:
        _ = identity_name
        response = self._kms.generate_data_key(
            KeyId=self._master_key_id,
            KeySpec="AES_256",
            EncryptionContext={"scan_id": str(scan_id)},
        )
        plaintext_data_key = response.get("Plaintext")
        encrypted_data_key = response.get("CiphertextBlob")
        if not isinstance(plaintext_data_key, bytes) or not isinstance(encrypted_data_key, bytes):
            raise RuntimeError("Invalid response from KMS generate_data_key")

        fernet_key = base64.urlsafe_b64encode(plaintext_data_key)
        ciphertext = Fernet(fernet_key).encrypt(plaintext.encode("utf-8"))
        return EncryptedBlob(
            encrypted_data_key=base64.b64encode(encrypted_data_key).decode("ascii"),
            ciphertext=ciphertext.decode("ascii"),
        )

    def decrypt_credential(self, blob: EncryptedBlob, scan_id: UUID, identity_name: str | None = None) -> str:
        _ = identity_name
        encrypted_data_key = base64.b64decode(blob.encrypted_data_key.encode("ascii"))
        response = self._kms.decrypt(
            CiphertextBlob=encrypted_data_key,
            EncryptionContext={"scan_id": str(scan_id)},
        )
        plaintext_data_key = response.get("Plaintext")
        if not isinstance(plaintext_data_key, bytes):
            raise RuntimeError("Invalid response from KMS decrypt")

        fernet_key = base64.urlsafe_b64encode(plaintext_data_key)
        plaintext = Fernet(fernet_key).decrypt(blob.ciphertext.encode("ascii"))
        return plaintext.decode("utf-8")
