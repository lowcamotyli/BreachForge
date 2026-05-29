from __future__ import annotations

import time
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from fastapi import FastAPI
from fastapi.testclient import TestClient

import api.routers.session as session_module
from api.routers.session import _TTLSessionStore, _validate_public_url, validate_session_snapshot
from control_plane.auth_manager import SessionSnapshot


def _snapshot(domain: str = "example.com") -> SimpleNamespace:
    return SimpleNamespace(domain=domain, cookie_count=1, has_auth_token=False)


def test_validate_public_url_blocks_private_ip(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("api.routers.session.socket.gethostbyname", lambda _host: "127.0.0.1")

    with pytest.raises(HTTPException) as exc_info:
        _validate_public_url("https://example.com")

    assert exc_info.value.status_code == 422


def test_validate_public_url_blocks_scheme() -> None:
    with pytest.raises(HTTPException) as exc_info:
        _validate_public_url("ftp://example.com")

    assert exc_info.value.status_code == 422


def test_ttl_store_put_and_get() -> None:
    store = _TTLSessionStore(ttl_seconds=1, max_sessions=5)
    snapshot = _snapshot()

    store.put("session-1", snapshot)

    assert store.get("session-1") is snapshot


def test_ttl_store_evicts_expired() -> None:
    # ttl_seconds=-1 places expiry 1s in the past — deterministic on Windows
    store = _TTLSessionStore(ttl_seconds=-1, max_sessions=5)
    snapshot = _snapshot()

    store.put("session-1", snapshot)

    assert store.get("session-1") is None


def test_ttl_store_raises_when_full() -> None:
    store = _TTLSessionStore(ttl_seconds=1, max_sessions=2)

    store.put("session-1", _snapshot("one.example"))
    store.put("session-2", _snapshot("two.example"))

    with pytest.raises(HTTPException) as exc_info:
        store.put("session-3", _snapshot("three.example"))

    assert exc_info.value.status_code == 503
    assert exc_info.value.detail == "Session store full"


def test_ttl_store_len() -> None:
    store = _TTLSessionStore(ttl_seconds=1, max_sessions=5)

    store.put("session-1", _snapshot("one.example"))
    store.put("session-2", _snapshot("two.example"))

    assert len(store) == 2


@pytest.mark.asyncio
async def test_validate_session_snapshot_accepts_authenticated_probe(monkeypatch: pytest.MonkeyPatch) -> None:
    class _Response:
        status_code = 200

    class _Client:
        def __init__(self, **kwargs: object) -> None:
            del kwargs

        async def __aenter__(self) -> _Client:
            return self

        async def __aexit__(self, exc_type: object, exc: object, tb: object) -> None:
            return None

        async def request(self, method: str, url: str, **kwargs: object) -> _Response:
            assert method == "GET"
            assert url == "https://example.com/api/me"
            assert kwargs["cookies"] == {"sid": "secret"}
            return _Response()

    monkeypatch.setattr("api.routers.session.httpx.AsyncClient", _Client)

    result = await validate_session_snapshot(
        SessionSnapshot(cookies={"sid": "secret"}),
        "https://example.com/api/me",
    )

    assert result.valid is True
    assert result.reason == "session_valid"


@pytest.mark.asyncio
async def test_validate_session_snapshot_rejects_unauthorized_probe(monkeypatch: pytest.MonkeyPatch) -> None:
    class _Response:
        status_code = 401

    class _Client:
        def __init__(self, **kwargs: object) -> None:
            del kwargs

        async def __aenter__(self) -> _Client:
            return self

        async def __aexit__(self, exc_type: object, exc: object, tb: object) -> None:
            return None

        async def request(self, method: str, url: str, **kwargs: object) -> _Response:
            del method, url, kwargs
            return _Response()

    monkeypatch.setattr("api.routers.session.httpx.AsyncClient", _Client)

    result = await validate_session_snapshot(
        SessionSnapshot(cookies={"sid": "secret"}),
        "https://example.com/api/me",
    )

    assert result.valid is False
    assert result.reason == "auth_rejected"


def test_record_session_endpoint_stores_snapshot_and_probe_reruns(monkeypatch: pytest.MonkeyPatch) -> None:
    statuses = [204, 403]
    captured_requests: list[dict[str, object]] = []

    class _Response:
        def __init__(self, status_code: int) -> None:
            self.status_code = status_code

    class _Client:
        def __init__(self, **kwargs: object) -> None:
            del kwargs

        def __enter__(self) -> _Client:
            return self

        def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
            return None

        def get(self, url: str, **kwargs: object) -> _Response:
            captured_requests.append(
                {
                    "url": url,
                    "headers": kwargs["headers"],
                    "cookies": kwargs["cookies"],
                }
            )
            return _Response(statuses.pop(0))

    monkeypatch.setattr("api.routers.session.socket.gethostbyname", lambda _host: "93.184.216.34")
    monkeypatch.setattr("control_plane.auth_manager.httpx.Client", _Client)
    monkeypatch.setattr(session_module, "AUTH_SNAPSHOT_STORE", _TTLSessionStore(ttl_seconds=60, max_sessions=5))

    app = FastAPI()
    app.include_router(session_module.router)
    client = TestClient(app)

    record_response = client.post(
        "/sessions/record",
        json={
            "url": "https://example.com/account",
            "cookies": {"sid": "cookie-secret"},
            "storage": {"localStorage": {"token": "storage-token"}},
            "headers": {
                "Authorization": "Bearer token-secret",
                "Cookie": "sid=cookie-secret",
                "X-CSRF-Token": "csrf-secret",
                "X-Not-Auth": "ignored",
            },
        },
    )

    assert record_response.status_code == 200
    record_payload = record_response.json()
    assert record_payload["snapshot_id"]
    assert record_payload["probe_success"] is True

    probe_response = client.get(f"/sessions/{record_payload['snapshot_id']}/probe")

    assert probe_response.status_code == 200
    probe_payload = probe_response.json()
    assert probe_payload["snapshot_id"] == record_payload["snapshot_id"]
    assert probe_payload["probe_success"] is False
    assert len(captured_requests) == 2
    assert captured_requests[0]["cookies"] == {"sid": "cookie-secret"}
    assert captured_requests[0]["headers"] == {
        "Authorization": "Bearer token-secret",
        "Cookie": "sid=cookie-secret",
        "X-CSRF-Token": "csrf-secret",
    }


def test_probe_recorded_session_returns_404_for_missing_snapshot() -> None:
    app = FastAPI()
    app.include_router(session_module.router)
    client = TestClient(app)

    response = client.get("/sessions/missing/probe")

    assert response.status_code == 404
