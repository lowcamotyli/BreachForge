from __future__ import annotations

import socket
import time
from ipaddress import ip_address
from threading import Lock
from urllib.parse import urlparse
from uuid import uuid4

import structlog
from fastapi import APIRouter, HTTPException, status
from playwright.async_api import Error as PlaywrightError
from pydantic import AnyHttpUrl, BaseModel, Field

from control_plane.auth_manager import BrowserSessionImporter, SessionSnapshot

router = APIRouter(prefix="/session", tags=["session"])
_log = structlog.get_logger()


class _TTLSessionStore:
    def __init__(self, ttl_seconds: int = 1800, max_sessions: int = 100) -> None:
        self._store: dict[str, tuple[SessionSnapshot, float]] = {}
        self._lock = Lock()
        self._ttl = ttl_seconds
        self._max = max_sessions

    def _evict_expired(self) -> None:
        now = time.monotonic()
        expired_session_ids = [session_id for session_id, (_, expiry) in self._store.items() if now > expiry]
        for session_id in expired_session_ids:
            del self._store[session_id]

    def put(self, session_id: str, snapshot: SessionSnapshot) -> None:
        with self._lock:
            self._evict_expired()
            if len(self._store) >= self._max:
                raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Session store full")
            self._store[session_id] = (snapshot, time.monotonic() + self._ttl)

    def get(self, session_id: str) -> SessionSnapshot | None:
        with self._lock:
            value = self._store.get(session_id)
            if value is None:
                return None

            snapshot, expiry = value
            if time.monotonic() > expiry:
                del self._store[session_id]
                return None

            return snapshot

    def __len__(self) -> int:
        with self._lock:
            self._evict_expired()
            return len(self._store)


SESSION_STORE = _TTLSessionStore()


def _validate_public_url(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Only http/https URLs are allowed")
    host = parsed.hostname or ""
    try:
        resolved = ip_address(socket.gethostbyname(host))
    except (OSError, ValueError) as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=f"Cannot resolve host: {host}") from exc
    if resolved.is_private or resolved.is_loopback or resolved.is_link_local:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Private/internal hosts are not allowed")


class SessionImportRequest(BaseModel):
    url: AnyHttpUrl
    wait_seconds: int = Field(default=5, ge=0, le=30)


class SessionImportResponse(BaseModel):
    session_id: str
    domain: str
    cookie_count: int
    has_auth_token: bool
    health_check: dict[str, bool | str]
    summary: str


@router.post("/import", response_model=SessionImportResponse, status_code=status.HTTP_200_OK)
async def import_session(payload: SessionImportRequest) -> SessionImportResponse:
    _validate_public_url(str(payload.url))
    importer = BrowserSessionImporter()
    try:
        snapshot = await importer.import_from_browser(str(payload.url), payload.wait_seconds)
    except PlaywrightError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc

    health_check_raw = await importer.check_session_health(snapshot, test_endpoints=[payload.url])
    health_check: dict[str, bool | str] = {key: value for key, value in health_check_raw.items() if isinstance(value, (bool, str))}

    session_id = str(uuid4())
    SESSION_STORE.put(session_id, snapshot)
    _log.info(
        "session_imported",
        session_id=session_id,
        domain=snapshot.domain,
        cookie_count=snapshot.cookie_count,
        has_auth_token=snapshot.has_auth_token,
    )

    summary = (
        f"Imported session for {snapshot.domain} with {snapshot.cookie_count} cookies; "
        f"auth token present: {snapshot.has_auth_token}"
    )

    return SessionImportResponse(
        session_id=session_id,
        domain=snapshot.domain,
        cookie_count=snapshot.cookie_count,
        has_auth_token=snapshot.has_auth_token,
        health_check=health_check,
        summary=summary,
    )
