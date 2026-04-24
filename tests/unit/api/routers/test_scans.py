from __future__ import annotations

import json
from types import SimpleNamespace
from uuid import uuid4

from api.models.requests import AuthContextCreate, ScanCreate
from api.routers import scans as scans_module


def test_build_session_snapshot_encrypts_sensitive_auth_material(monkeypatch) -> None:
    encrypted_payloads: list[str] = []

    class _FakeEncryption:
        def encrypt_credential(self, plaintext: str, scan_id):
            encrypted_payloads.append(plaintext)
            return SimpleNamespace(encrypted_data_key="key", ciphertext="cipher")

    monkeypatch.setattr(scans_module, "EnvelopeEncryption", _FakeEncryption)

    payload = ScanCreate(
        target_url="https://app.example.com",
        auth_context=AuthContextCreate(
            type="credential",
            credentials={"username": "analyst", "password": "secret-password"},
            cookies=[{"name": "sessionid", "value": "cookie-secret"}],
            bearer_token="secret-token",
            login_recipe={"steps": [{"action": "navigate", "url": "https://app.example.com/login"}]},
        ),
    )

    snapshot = scans_module._build_session_snapshot(payload, uuid4())

    assert snapshot["credentials"]["_encrypted"] == "kms_envelope_v1"
    assert snapshot["cookies"]["_encrypted"] == "kms_envelope_v1"
    assert snapshot["bearer_token"]["_encrypted"] == "kms_envelope_v1"
    assert json.dumps(snapshot).find("secret-password") == -1
    assert json.dumps(snapshot).find("secret-token") == -1
    assert json.dumps(snapshot).find("cookie-secret") == -1
    assert len(encrypted_payloads) == 3
