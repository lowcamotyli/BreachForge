from __future__ import annotations

import base64
import json
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from uuid import UUID, uuid4

import pytest

from storage.db.models import AuthBundle
from storage.db import session as session_module


class _FakeResult:
    def __init__(self, one: AuthBundle | None = None, many: list[AuthBundle] | None = None) -> None:
        self._one = one
        self._many = many or []

    def scalar_one_or_none(self) -> AuthBundle | None:
        return self._one

    def scalars(self) -> SimpleNamespace:
        return SimpleNamespace(all=lambda: self._many)


class _FakeAsyncSession:
    def __init__(self) -> None:
        self._bundles: dict[UUID, AuthBundle] = {}

    def add(self, bundle: AuthBundle) -> None:
        if bundle.id is None:
            bundle.id = uuid4()
        if bundle.created_at is None:
            bundle.created_at = datetime.now(timezone.utc)
        self._bundles[bundle.id] = bundle

    async def commit(self) -> None:
        return None

    async def refresh(self, _bundle: AuthBundle) -> None:
        return None

    async def execute(self, stmt) -> _FakeResult:  # type: ignore[no-untyped-def]
        params = stmt.compile().params
        if "id_1" in params:
            return _FakeResult(one=self._bundles.get(params["id_1"]))
        if "scan_id_1" in params:
            scan_id = params["scan_id_1"]
            rows = [bundle for bundle in self._bundles.values() if bundle.scan_id == scan_id]
            rows.sort(key=lambda b: b.created_at or datetime.min.replace(tzinfo=timezone.utc), reverse=True)
            return _FakeResult(many=rows)
        return _FakeResult()


class _FakeEncryption:
    decrypt_calls = 0

    def encrypt_credential(self, plaintext: str, scan_id: UUID, identity_name: str | None = None):  # type: ignore[no-untyped-def]
        encoded = base64.b64encode(plaintext.encode("utf-8")).decode("ascii")
        return SimpleNamespace(
            encrypted_data_key=f"edk:{scan_id}:{identity_name or ''}",
            ciphertext=f"ct::{encoded}",
        )

    def decrypt_credential(self, blob, scan_id: UUID, identity_name: str | None = None) -> str:  # type: ignore[no-untyped-def]
        del scan_id, identity_name
        self.__class__.decrypt_calls += 1
        encoded = str(blob.ciphertext).replace("ct::", "", 1)
        return base64.b64decode(encoded.encode("ascii")).decode("utf-8")


@pytest.mark.asyncio
async def test_save_and_load_auth_bundle_round_trip_uses_encryption(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(session_module, "EnvelopeEncryption", _FakeEncryption)
    db = _FakeAsyncSession()
    scan_id = uuid4()
    raw_payload = '{"cookies":[{"name":"sid","value":"cookie-secret"}],"bearer_token":"token-secret"}'
    bundle = AuthBundle(
        scan_id=scan_id,
        identity_label="qa-admin",
        encrypted_payload=raw_payload.encode("utf-8"),
        redacted_preview={"cookie_count": 1, "has_bearer": True, "csrf_present": False},
    )

    bundle_id = await session_module.save_auth_bundle(db, bundle)  # type: ignore[arg-type]
    stored = db._bundles[bundle_id]
    assert stored.encrypted_payload != raw_payload.encode("utf-8")
    encrypted_doc = json.loads(stored.encrypted_payload.decode("utf-8"))
    assert encrypted_doc["_encrypted"] == "kms_envelope_v1"
    assert "cookie-secret" not in stored.encrypted_payload.decode("utf-8")
    assert "token-secret" not in stored.encrypted_payload.decode("utf-8")

    loaded = await session_module.load_auth_bundle(db, bundle_id)  # type: ignore[arg-type]
    assert loaded is not None
    assert loaded.encrypted_payload.decode("utf-8") == raw_payload


@pytest.mark.asyncio
async def test_load_auth_bundle_returns_none_when_expired(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(session_module, "EnvelopeEncryption", _FakeEncryption)
    _FakeEncryption.decrypt_calls = 0
    db = _FakeAsyncSession()
    bundle = AuthBundle(
        scan_id=uuid4(),
        identity_label="expired-user",
        encrypted_payload=b'{"_encrypted":"kms_envelope_v1","encrypted_data_key":"edk","ciphertext":"ct::raw"}',
        expires_at=datetime.now(timezone.utc) - timedelta(minutes=1),
        redacted_preview={"cookie_count": 2},
    )
    db.add(bundle)

    loaded = await session_module.load_auth_bundle(db, bundle.id)  # type: ignore[arg-type]
    assert loaded is None
    assert _FakeEncryption.decrypt_calls == 0


@pytest.mark.asyncio
async def test_redacted_preview_filters_sensitive_values(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(session_module, "EnvelopeEncryption", _FakeEncryption)
    db = _FakeAsyncSession()
    bundle = AuthBundle(
        scan_id=uuid4(),
        identity_label="ops-user",
        encrypted_payload=b'{"access_token":"raw-token","password":"raw-pass"}',
        redacted_preview={
            "cookie_count": 3,
            "has_bearer": True,
            "csrf_present": True,
            "bearer_token": "raw-token",
            "password": "raw-pass",
            "cookie_value": "session=raw",
        },
    )

    bundle_id = await session_module.save_auth_bundle(db, bundle)  # type: ignore[arg-type]
    stored = db._bundles[bundle_id]
    assert stored.redacted_preview == {"cookie_count": 3, "has_bearer": True, "csrf_present": True}
    preview_dump = json.dumps(stored.redacted_preview)
    assert "raw-token" not in preview_dump
    assert "raw-pass" not in preview_dump
    assert "session=raw" not in preview_dump
