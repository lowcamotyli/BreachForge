from __future__ import annotations

from types import SimpleNamespace
from uuid import uuid4

from api.routers import scans


class _FakeEncryption:
    def encrypt_credential(self, plaintext: str, scan_id) -> SimpleNamespace:
        return SimpleNamespace(
            encrypted_data_key=f"edk:{scan_id}:{plaintext}",
            ciphertext=f"ct:{scan_id}:{plaintext}",
        )


def test_build_session_snapshot_encrypts_sensitive_fields(monkeypatch) -> None:
    monkeypatch.setattr(scans, "EnvelopeEncryption", _FakeEncryption)
    scan_id = uuid4()
    payload = SimpleNamespace(
        auth_context=SimpleNamespace(
            credentials={"username": "alice", "password": "secret"},
            cookies=[{"name": "sid", "value": "cookie-secret"}],
            bearer_token="bearer-secret",
            login_recipe={"steps": [{"action": "navigate", "url": "https://example.com/login"}]},
        )
    )

    snapshot = scans._build_session_snapshot(payload, scan_id)

    assert snapshot["credentials"]["_encrypted"] == "kms_envelope_v1"
    assert snapshot["cookies"]["_encrypted"] == "kms_envelope_v1"
    assert snapshot["bearer_token"]["_encrypted"] == "kms_envelope_v1"
    assert snapshot["login_recipe"] == {"steps": [{"action": "navigate", "url": "https://example.com/login"}]}
