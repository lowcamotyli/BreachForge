from __future__ import annotations

import socket
import time
from dataclasses import asdict
from datetime import datetime
from ipaddress import ip_address
from threading import Lock
from urllib.parse import urlparse
from uuid import uuid4

import httpx
import structlog
from fastapi import APIRouter, File, HTTPException, UploadFile, status
from playwright.async_api import Error as PlaywrightError
from pydantic import AnyHttpUrl, BaseModel, Field

from api.importers.session_importer import HarImporter, OpenApiImporter, PostmanImporter
from control_plane.auth_manager import AuthRecorder, AuthSnapshot, BrowserSessionImporter, SessionSnapshot

router = APIRouter(tags=["session"])
_log = structlog.get_logger()
_MAX_IMPORT_FILE_SIZE = 10 * 1024 * 1024


class _TTLSessionStore:
    def __init__(self, ttl_seconds: int = 1800, max_sessions: int = 100) -> None:
        self._store: dict[str, tuple[object, float]] = {}
        self._lock = Lock()
        self._ttl = ttl_seconds
        self._max = max_sessions

    def _evict_expired(self) -> None:
        now = time.monotonic()
        expired_session_ids = [session_id for session_id, (_, expiry) in self._store.items() if now > expiry]
        for session_id in expired_session_ids:
            del self._store[session_id]

    def put(self, session_id: str, snapshot: object) -> None:
        with self._lock:
            self._evict_expired()
            if len(self._store) >= self._max:
                raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Session store full")
            self._store[session_id] = (snapshot, time.monotonic() + self._ttl)

    def get(self, session_id: str) -> object | None:
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
AUTH_SNAPSHOT_STORE = _TTLSessionStore()


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


class SessionValidationRequest(BaseModel):
    session_id: str
    probe_url: AnyHttpUrl


class SessionValidationResult(BaseModel):
    valid: bool
    reason: str


class AuthRecordRequest(BaseModel):
    url: AnyHttpUrl
    cookies: dict[str, object] = Field(default_factory=dict)
    storage: dict[str, object] = Field(default_factory=dict)
    headers: dict[str, object] = Field(default_factory=dict)


class AuthRecordResponse(BaseModel):
    snapshot_id: str
    probe_success: bool


class AuthProbeResponse(BaseModel):
    snapshot_id: str
    probe_success: bool
    probed_at: datetime


def _select_auth_importer(file_content: str) -> HarImporter | PostmanImporter | OpenApiImporter:
    import json

    try:
        data = json.loads(file_content)
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid JSON import file") from exc

    if not isinstance(data, dict):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Import file must contain a JSON object")
    if isinstance(data.get("log"), dict) and isinstance(data["log"].get("entries"), list):
        return HarImporter()
    if isinstance(data.get("info"), dict) and "postman" in str(data["info"].get("schema", "")).lower():
        return PostmanImporter()
    if "openapi" in data or "swagger" in data:
        return OpenApiImporter()

    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Unsupported session import format")


def _build_probe_headers(snapshot: SessionSnapshot) -> tuple[dict[str, str], dict[str, str]]:
    headers: dict[str, str] = dict(snapshot.auth_headers or {})
    cookies: dict[str, str] = {}

    if isinstance(snapshot.cookies, dict):
        cookies = {str(key): str(value) for key, value in snapshot.cookies.items()}
    elif isinstance(snapshot.cookies, list):
        cookie_header = "; ".join(
            f"{cookie.get('name')}={cookie.get('value')}"
            for cookie in snapshot.cookies
            if isinstance(cookie, dict) and cookie.get("name") and cookie.get("value") is not None
        )
        if cookie_header:
            headers["Cookie"] = cookie_header

    headers.update({str(key): str(value) for key, value in (snapshot.csrf_tokens or {}).items()})
    return headers, cookies


async def validate_session_snapshot(
    snapshot: SessionSnapshot,
    probe_url: str,
    *,
    method: str = "GET",
    validate_public_url: bool = False,
) -> SessionValidationResult:
    if validate_public_url:
        _validate_public_url(probe_url)

    headers, cookies = _build_probe_headers(snapshot)
    if not headers and not cookies:
        return SessionValidationResult(valid=False, reason="no_auth_material")

    request_method = method.upper()
    if request_method not in {"GET", "HEAD", "OPTIONS"}:
        request_method = "HEAD"

    try:
        async with httpx.AsyncClient(timeout=15.0, follow_redirects=False, max_redirects=5) as client:
            response = await client.request(request_method, probe_url, headers=headers, cookies=cookies)
            if request_method == "HEAD" and response.status_code == status.HTTP_405_METHOD_NOT_ALLOWED:
                response = await client.get(probe_url, headers=headers, cookies=cookies)
    except httpx.HTTPError:
        return SessionValidationResult(valid=False, reason="probe_failed")

    if response.status_code in {status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN}:
        return SessionValidationResult(valid=False, reason="auth_rejected")
    if response.status_code == status.HTTP_405_METHOD_NOT_ALLOWED:
        return SessionValidationResult(valid=False, reason="probe_method_not_allowed")
    if status.HTTP_300_MULTIPLE_CHOICES <= response.status_code < status.HTTP_400_BAD_REQUEST:
        return SessionValidationResult(valid=False, reason="auth_redirected")
    if response.status_code >= status.HTTP_500_INTERNAL_SERVER_ERROR:
        return SessionValidationResult(valid=False, reason="probe_server_error")

    return SessionValidationResult(valid=True, reason="session_valid")


@router.post("/session/import", response_model=SessionImportResponse, status_code=status.HTTP_200_OK)
async def import_session(payload: SessionImportRequest) -> SessionImportResponse:
    _validate_public_url(str(payload.url))
    importer = BrowserSessionImporter()
    try:
        snapshot = await importer.import_from_browser(str(payload.url), payload.wait_seconds)
    except PlaywrightError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc

    health_check_raw = await importer.check_session_health(snapshot, test_endpoints=[payload.url])
    health_check: dict[str, bool | str] = {
        key: value for key, value in health_check_raw.items() if isinstance(value, (bool, str))
    }

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


@router.post("/sessions/import", status_code=status.HTTP_200_OK)
async def import_session_auth_material(file: UploadFile = File(...)) -> dict[str, object]:
    content = await file.read(_MAX_IMPORT_FILE_SIZE + 1)
    if len(content) > _MAX_IMPORT_FILE_SIZE:
        raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail="Import file exceeds 10MB")

    try:
        file_content = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Import file must be UTF-8 JSON") from exc

    importer = _select_auth_importer(file_content)
    try:
        material = importer.extract_auth(file_content)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    return asdict(material)


@router.post("/session/validate", response_model=SessionValidationResult, status_code=status.HTTP_200_OK)
async def validate_session(payload: SessionValidationRequest) -> SessionValidationResult:
    stored_snapshot = SESSION_STORE.get(payload.session_id)
    if stored_snapshot is None:
        return SessionValidationResult(valid=False, reason="session_not_found_or_expired")
    if not isinstance(stored_snapshot, SessionSnapshot):
        return SessionValidationResult(valid=False, reason="session_not_found_or_expired")

    result = await validate_session_snapshot(
        stored_snapshot,
        str(payload.probe_url),
        method="GET",
        validate_public_url=True,
    )
    _log.info(
        "session_validation_completed",
        session_id=payload.session_id,
        valid=result.valid,
        reason=result.reason,
    )
    return result


@router.post("/sessions/record", response_model=AuthRecordResponse, status_code=status.HTTP_200_OK)
async def record_auth_session(payload: AuthRecordRequest) -> AuthRecordResponse:
    _validate_public_url(str(payload.url))
    recorder = AuthRecorder()
    snapshot = recorder.record_session(
        str(payload.url),
        cookies=payload.cookies,
        storage=payload.storage,
        headers=payload.headers,
    )
    snapshot_id = str(uuid4())
    AUTH_SNAPSHOT_STORE.put(snapshot_id, snapshot)
    _log.info(
        "auth_session_recorded",
        snapshot_id=snapshot_id,
        cookie_count=len(snapshot.cookies),
        header_count=len(snapshot.headers),
        probe_success=snapshot.probe_success,
    )
    return AuthRecordResponse(snapshot_id=snapshot_id, probe_success=snapshot.probe_success)


@router.get("/sessions/{snapshot_id}/probe", response_model=AuthProbeResponse, status_code=status.HTTP_200_OK)
async def probe_recorded_auth_session(snapshot_id: str) -> AuthProbeResponse:
    stored_snapshot = AUTH_SNAPSHOT_STORE.get(snapshot_id)
    if stored_snapshot is None or not isinstance(stored_snapshot, AuthSnapshot):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Session snapshot not found or expired")

    recorder = AuthRecorder()
    probe_success = recorder.verify_auth_probe(stored_snapshot)
    _log.info(
        "auth_session_probe_completed",
        snapshot_id=snapshot_id,
        probe_success=probe_success,
    )
    return AuthProbeResponse(
        snapshot_id=snapshot_id,
        probe_success=probe_success,
        probed_at=stored_snapshot.probed_at,
    )
