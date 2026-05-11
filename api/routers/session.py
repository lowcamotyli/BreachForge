from __future__ import annotations

from uuid import uuid4

from fastapi import APIRouter, HTTPException, status
from playwright.async_api import Error as PlaywrightError
from pydantic import BaseModel, Field

from control_plane.auth_manager import BrowserSessionImporter, SessionSnapshot

router = APIRouter(prefix="/session", tags=["session"])

SESSION_STORE: dict[str, SessionSnapshot] = {}


class SessionImportRequest(BaseModel):
    url: str
    wait_seconds: int = Field(default=5)


class SessionImportResponse(BaseModel):
    session_id: str
    domain: str
    cookie_count: int
    has_auth_token: bool
    health_check: dict[str, bool | str]
    summary: str


@router.post("/import", response_model=SessionImportResponse, status_code=status.HTTP_200_OK)
async def import_session(payload: SessionImportRequest) -> SessionImportResponse:
    importer = BrowserSessionImporter()
    try:
        snapshot = await importer.import_from_browser(payload.url, payload.wait_seconds)
    except PlaywrightError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc

    health_check_raw = await importer.check_session_health(snapshot, test_endpoints=[payload.url])
    health_check: dict[str, bool | str] = {key: value for key, value in health_check_raw.items() if isinstance(value, (bool, str))}

    session_id = str(uuid4())
    SESSION_STORE[session_id] = snapshot

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
