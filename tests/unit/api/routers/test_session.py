from __future__ import annotations

import time
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from api.routers.session import _TTLSessionStore, _validate_public_url


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
