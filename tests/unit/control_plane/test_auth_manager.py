from __future__ import annotations

import json
import sys
from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest

import control_plane.auth_manager as auth_manager_module
from api.models.requests import AuthContextCreate
from control_plane.auth_manager import AuthManager, SessionSnapshot
from storage.db.encryption import EncryptedBlob
from storage.db.models import ScanStatus


class _FailingSessionContext:
    async def __aenter__(self) -> None:
        raise AssertionError("Database access should be mocked in unit tests")

    async def __aexit__(self, exc_type, exc, tb) -> None:
        return None


def _failing_session_factory() -> _FailingSessionContext:
    return _FailingSessionContext()


@pytest.fixture(autouse=True)
def mock_playwright(monkeypatch: pytest.MonkeyPatch) -> None:
    class _PlaywrightContext:
        async def __aenter__(self) -> SimpleNamespace:
            chromium = SimpleNamespace(
                launch=AsyncMock(side_effect=AssertionError("Playwright should not be launched in these tests"))
            )
            return SimpleNamespace(chromium=chromium)

        async def __aexit__(self, exc_type, exc, tb) -> None:
            return None

    monkeypatch.setattr(auth_manager_module, "async_playwright", lambda: _PlaywrightContext())


@pytest.mark.asyncio
async def test_bootstrap_none_creates_no_authenticated_material() -> None:
    scan_id = uuid4()
    pause_scan = AsyncMock()
    manager = AuthManager(scan_id, _failing_session_factory, pause_scan)

    manager._from_cookies = MagicMock(wraps=manager._from_cookies)
    manager._from_bearer = MagicMock(wraps=manager._from_bearer)
    manager._probe_or_pause = AsyncMock()
    manager._upsert_auth_context = AsyncMock(return_value=SimpleNamespace(type="none"))
    manager._health_loop = AsyncMock(return_value=None)

    await manager.bootstrap(AuthContextCreate(type="none"))

    assert manager._session_snapshot is not None
    assert manager._session_snapshot.cookies == []
    assert manager._session_snapshot.auth_headers == {}
    manager._from_cookies.assert_not_called()
    manager._from_bearer.assert_not_called()

    await manager.close()


@pytest.mark.asyncio
async def test_bootstrap_session_calls_from_cookies_and_stores_snapshot() -> None:
    scan_id = uuid4()
    pause_scan = AsyncMock()
    manager = AuthManager(scan_id, _failing_session_factory, pause_scan)

    auth_input = AuthContextCreate(
        type="session",
        cookies=[
            {
                "name": "sessionid",
                "value": "cookie-value",
                "domain": "example.com",
                "path": "/",
            }
        ],
    )

    manager._from_cookies = MagicMock(wraps=manager._from_cookies)
    manager._from_bearer = MagicMock(wraps=manager._from_bearer)
    manager._probe_or_pause = AsyncMock()
    manager._upsert_auth_context = AsyncMock(return_value=SimpleNamespace(type="session"))
    manager._health_loop = AsyncMock(return_value=None)

    await manager.bootstrap(auth_input)

    manager._from_cookies.assert_called_once_with(auth_input)
    manager._from_bearer.assert_not_called()
    assert manager._session_snapshot is not None
    assert manager._session_snapshot.cookies[0]["value"] == "cookie-value"

    await manager.close()


@pytest.mark.asyncio
async def test_bootstrap_token_calls_from_bearer_and_stores_snapshot() -> None:
    scan_id = uuid4()
    pause_scan = AsyncMock()
    manager = AuthManager(scan_id, _failing_session_factory, pause_scan)

    auth_input = AuthContextCreate(type="token", bearer_token="token-value")

    manager._from_cookies = MagicMock(wraps=manager._from_cookies)
    manager._from_bearer = MagicMock(wraps=manager._from_bearer)
    manager._probe_or_pause = AsyncMock()
    manager._upsert_auth_context = AsyncMock(return_value=SimpleNamespace(type="token"))
    manager._health_loop = AsyncMock(return_value=None)

    await manager.bootstrap(auth_input)

    manager._from_bearer.assert_called_once_with(auth_input)
    manager._from_cookies.assert_not_called()
    assert manager._session_snapshot is not None
    assert manager._session_snapshot.auth_headers["Authorization"] == "Bearer token-value"

    await manager.close()


@pytest.mark.asyncio
async def test_get_session_snapshot_returns_copy_not_reference() -> None:
    scan_id = uuid4()
    manager = AuthManager(scan_id, _failing_session_factory, AsyncMock())

    manager._session_snapshot = SessionSnapshot(
        scan_id=scan_id,
        cookies=[{"name": "sessionid", "value": "original"}],
        auth_headers={"Authorization": "Bearer original-token"},
        csrf_tokens={"csrf_token": "csrf-original"},
        captured_at=datetime.now(UTC),
        expires_at=None,
    )

    copied_snapshot = await manager.get_session_snapshot(scan_id)
    copied_snapshot.cookies[0]["value"] = "mutated"
    copied_snapshot.auth_headers["Authorization"] = "Bearer mutated-token"

    assert copied_snapshot is not manager._session_snapshot
    assert manager._session_snapshot.cookies[0]["value"] == "original"
    assert manager._session_snapshot.auth_headers["Authorization"] == "Bearer original-token"


@pytest.mark.asyncio
async def test_health_loop_pauses_scan_with_explicit_error_when_probe_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    scan_id = uuid4()
    pause_scan = AsyncMock()
    manager = AuthManager(scan_id, _failing_session_factory, pause_scan)

    manager._auth_type = "token"
    manager._auth_input = AuthContextCreate(type="token", bearer_token="token-value")
    manager._probe_authenticated_endpoint = AsyncMock(return_value=False)
    manager._attempt_refresh = AsyncMock(return_value=False)
    manager._mark_auth_context_unhealthy = AsyncMock()

    async def _no_wait(_: float) -> None:
        return None

    monkeypatch.setattr(auth_manager_module.asyncio, "sleep", _no_wait)

    await manager._health_loop()

    pause_scan.assert_awaited_once_with(scan_id, "auth_expired")
    manager._mark_auth_context_unhealthy.assert_awaited_once_with("auth_expired")


@pytest.mark.asyncio
async def test_pause_with_error_logs_are_redacted(monkeypatch: pytest.MonkeyPatch) -> None:
    scan_id = uuid4()
    pause_scan = AsyncMock()
    manager = AuthManager(scan_id, _failing_session_factory, pause_scan)

    manager._auth_type = "credential"
    manager._auth_input = AuthContextCreate(
        type="credential",
        credentials={
            "username": "analyst",
            "password": "super-secret-password",
            "Authorization": "Bearer very-secret-auth",
        },
        cookies=[{"name": "sessionid", "value": "super-secret-cookie"}],
        bearer_token="very-secret-token",
        login_recipe={"steps": [{"action": "navigate", "url": "https://example.com/login"}]},
    )
    manager._mark_auth_context_unhealthy = AsyncMock()

    captured_logs: list[tuple[str, dict[str, object]]] = []

    def _capture_error(event: str, **kwargs: object) -> None:
        captured_logs.append((event, kwargs))

    monkeypatch.setattr(auth_manager_module, "logger", SimpleNamespace(error=_capture_error))

    await manager._pause_with_error("token leaked password exposed Cookie=secret")

    pause_scan.assert_awaited_once_with(scan_id, "[REDACTED]")
    assert captured_logs, "Expected at least one error log entry"

    _, log_payload = captured_logs[0]
    serialized = json.dumps(log_payload).lower()

    assert "super-secret-password" not in serialized
    assert "super-secret-cookie" not in serialized
    assert "very-secret-auth" not in serialized
    assert "very-secret-token" not in serialized
    assert "[redacted]" in serialized


class _ScalarResult:
    def __init__(self, value: object | None) -> None:
        self._value = value

    def scalar_one_or_none(self) -> object | None:
        return self._value


class _SessionContext:
    def __init__(self, session: object) -> None:
        self._session = session

    async def __aenter__(self) -> object:
        return self._session

    async def __aexit__(self, exc_type, exc, tb) -> None:
        return None


class _FakeEncryption:
    def __init__(self) -> None:
        self.plaintexts: list[str] = []

    def encrypt_credential(self, plaintext: str, scan_id) -> EncryptedBlob:
        self.plaintexts.append(plaintext)
        index = len(self.plaintexts)
        return EncryptedBlob(encrypted_data_key=f"key-{index}", ciphertext=f"cipher-{index}")


@pytest.mark.asyncio
async def test_default_pause_scan_persists_paused_status(monkeypatch: pytest.MonkeyPatch) -> None:
    scan_id = uuid4()
    scan = SimpleNamespace(status=ScanStatus.running, phase="auth_bootstrap")
    session = SimpleNamespace(
        execute=AsyncMock(return_value=_ScalarResult(scan)),
        commit=AsyncMock(),
    )

    monkeypatch.setitem(sys.modules, "storage.db.session", SimpleNamespace(AsyncSessionLocal=lambda: _SessionContext(session)))

    await auth_manager_module.default_pause_scan(scan_id, "auth_expired")

    assert scan.status == ScanStatus.paused
    assert scan.phase == "paused:auth_expired"
    session.commit.assert_awaited_once()


@pytest.mark.asyncio
async def test_mark_scan_recon_started_persists_running_recon(monkeypatch: pytest.MonkeyPatch) -> None:
    scan_id = uuid4()
    scan = SimpleNamespace(status=ScanStatus.running, phase="auth_bootstrap")
    session = SimpleNamespace(
        execute=AsyncMock(return_value=_ScalarResult(scan)),
        commit=AsyncMock(),
    )

    monkeypatch.setitem(sys.modules, "storage.db.session", SimpleNamespace(AsyncSessionLocal=lambda: _SessionContext(session)))

    await auth_manager_module._mark_scan_recon_started(scan_id)

    assert scan.status == ScanStatus.running
    assert scan.phase == "recon"
    session.commit.assert_awaited_once()


@pytest.mark.asyncio
async def test_mark_auth_context_unhealthy_updates_health_only() -> None:
    scan_id = uuid4()
    auth_context = SimpleNamespace(health={"status": "healthy"})
    session = SimpleNamespace(
        execute=AsyncMock(return_value=_ScalarResult(auth_context)),
        commit=AsyncMock(),
    )
    manager = AuthManager(scan_id, lambda: _SessionContext(session), AsyncMock())

    await manager._mark_auth_context_unhealthy("auth_expired")

    assert auth_context.health["status"] == "unhealthy"
    assert auth_context.health["error"] == "auth_expired"
    session.execute.assert_awaited_once()
    session.commit.assert_awaited_once()


@pytest.mark.asyncio
async def test_mark_auth_context_unhealthy_noop_when_context_missing() -> None:
    scan_id = uuid4()
    session = SimpleNamespace(
        execute=AsyncMock(return_value=_ScalarResult(None)),
        commit=AsyncMock(),
    )
    manager = AuthManager(scan_id, lambda: _SessionContext(session), AsyncMock())

    await manager._mark_auth_context_unhealthy("auth_expired")

    session.execute.assert_awaited_once()
    session.commit.assert_not_awaited()


@pytest.mark.asyncio
async def test_upsert_auth_context_persists_encrypted_session_snapshot() -> None:
    scan_id = uuid4()
    captured_auth_context: list[object] = []
    session = SimpleNamespace(
        execute=AsyncMock(
            side_effect=[
                _ScalarResult(None),
                _ScalarResult(SimpleNamespace()),
            ]
        ),
        add=MagicMock(side_effect=lambda value: captured_auth_context.append(value)),
        commit=AsyncMock(),
        refresh=AsyncMock(),
    )
    fake_encryption = _FakeEncryption()
    manager = AuthManager(
        scan_id,
        lambda: _SessionContext(session),
        AsyncMock(),
        encryption_service=fake_encryption,
    )
    snapshot = SessionSnapshot(
        scan_id=scan_id,
        cookies=[{"name": "sessionid", "value": "cookie-secret"}],
        auth_headers={"Authorization": "Bearer token-secret"},
        csrf_tokens={"X-CSRF-Token": "csrf-secret"},
        captured_at=datetime.now(UTC),
        expires_at=None,
    )

    await manager._upsert_auth_context(snapshot, "token")

    persisted = captured_auth_context[0].session_snapshot
    assert persisted["cookies"]["_encrypted"] == "kms_envelope_v1"
    assert persisted["auth_headers"]["_encrypted"] == "kms_envelope_v1"
    assert persisted["csrf_tokens"]["_encrypted"] == "kms_envelope_v1"
    serialized = json.dumps(persisted)
    assert "cookie-secret" not in serialized
    assert "token-secret" not in serialized
    assert "csrf-secret" not in serialized
    session.commit.assert_awaited_once()


@pytest.mark.asyncio
async def test_purge_credentials_if_terminal_removes_persisted_and_in_memory_secrets() -> None:
    scan_id = uuid4()
    auth_context = SimpleNamespace(session_snapshot={"cookies": {"ciphertext": "cipher"}})
    session = SimpleNamespace(
        execute=AsyncMock(
            side_effect=[
                _ScalarResult(SimpleNamespace(status=ScanStatus.complete)),
                _ScalarResult(auth_context),
            ]
        ),
        commit=AsyncMock(),
    )
    manager = AuthManager(scan_id, lambda: _SessionContext(session), AsyncMock())
    manager._session_snapshot = SessionSnapshot(
        scan_id=scan_id,
        cookies=[{"name": "sessionid", "value": "cookie-secret"}],
        auth_headers={"Authorization": "Bearer token-secret"},
        csrf_tokens={"X-CSRF-Token": "csrf-secret"},
        captured_at=datetime.now(UTC),
        expires_at=None,
    )
    manager._auth_input = AuthContextCreate(
        type="credential",
        credentials={"username": "u", "password": "p"},
        cookies=[{"name": "sessionid", "value": "cookie-secret"}],
        bearer_token="token-secret",
        login_recipe={"steps": [{"action": "navigate", "url": "https://example.com"}]},
    )

    await manager.purge_credentials_if_terminal()

    assert auth_context.session_snapshot["purged"] is True
    assert manager._session_snapshot is not None
    assert manager._session_snapshot.cookies == []
    assert manager._session_snapshot.auth_headers == {}
    assert manager._session_snapshot.csrf_tokens == {}
    assert manager._auth_input is not None
    assert manager._auth_input.credentials is None
    assert manager._auth_input.cookies is None
    assert manager._auth_input.bearer_token is None
    session.commit.assert_awaited_once()


def test_build_auth_input_from_snapshot_decrypts_encrypted_fields(monkeypatch: pytest.MonkeyPatch) -> None:
    scan_id = uuid4()

    class _FakeEncryption:
        def decrypt_credential(self, blob, decrypt_scan_id):
            assert decrypt_scan_id == scan_id
            payload = {
                "ct-credentials": '{"username":"alice","password":"secret"}',
                "ct-cookies": '[{"name":"sid","value":"cookie-secret"}]',
                "ct-bearer": "bearer-secret",
            }
            return payload[blob.ciphertext]

    monkeypatch.setattr(auth_manager_module, "EnvelopeEncryption", _FakeEncryption)

    snapshot = {
        "credentials": {
            "_encrypted": "kms_envelope_v1",
            "encrypted_data_key": "edk-credentials",
            "ciphertext": "ct-credentials",
        },
        "cookies": {
            "_encrypted": "kms_envelope_v1",
            "encrypted_data_key": "edk-cookies",
            "ciphertext": "ct-cookies",
        },
        "bearer_token": {
            "_encrypted": "kms_envelope_v1",
            "encrypted_data_key": "edk-bearer",
            "ciphertext": "ct-bearer",
        },
        "login_recipe": {"steps": [{"action": "navigate", "url": "https://example.com/login"}]},
    }

    auth_input = auth_manager_module._build_auth_input_from_snapshot("credential", snapshot, scan_id)

    assert auth_input.type == "credential"
    assert auth_input.credentials == {"username": "alice", "password": "secret"}
    assert auth_input.cookies == [{"name": "sid", "value": "cookie-secret"}]
    assert auth_input.bearer_token == "bearer-secret"
    assert auth_input.login_recipe == {"steps": [{"action": "navigate", "url": "https://example.com/login"}]}
