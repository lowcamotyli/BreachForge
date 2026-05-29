from __future__ import annotations

from copy import deepcopy
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel


app = FastAPI(title="Benchmark Lab B3 - Auth OAuth")

BASE_USERS: dict[str, dict[str, Any]] = {
    "alice": {
        "id": "alice",
        "username": "alice",
        "password": "alice123",
        "role": "user",
        "tenant": "tenant_a",
        "token": "tok_ao_alice",
        "is_expired": False,
    },
    "bob": {
        "id": "bob",
        "username": "bob",
        "password": "bob123",
        "role": "admin",
        "tenant": "tenant_a",
        "token": "tok_ao_bob",
        "is_expired": False,
    },
    "expired": {
        "id": "expired",
        "username": "alice",
        "password": "alice123",
        "role": "user",
        "tenant": "tenant_a",
        "token": "tok_ao_expired",
        "is_expired": True,
    },
    "loggedout": {
        "id": "loggedout",
        "username": "alice",
        "password": "alice123",
        "role": "user",
        "tenant": "tenant_a",
        "token": "tok_ao_loggedout",
        "is_expired": False,
    },
}

USERS: dict[str, dict[str, Any]] = deepcopy(BASE_USERS)
REVOKED_TOKENS: set[str] = set()
OAUTH_STATES: dict[str, str] = {}
VALID_REDIRECT_URIS = {"https://app.example.com/callback"}
BLACKLISTED_SESSIONS: set[str] = set()
FIXED_CSRF_TOKEN = "test-csrf-token-abc123"

BENCHMARK_AUTH: dict[str, dict[str, str]] = {
    "alice": {"token": "tok_ao_alice", "role": "user", "tenant": "tenant_a"},
    "bob": {"token": "tok_ao_bob", "role": "admin", "tenant": "tenant_a"},
    "expired": {"token": "tok_ao_expired", "role": "user", "tenant": "tenant_a"},
    "logged_out": {"token": "tok_ao_loggedout", "role": "user", "tenant": "tenant_a"},
}


class LoginRequest(BaseModel):
    username: str
    password: str


def reset_state() -> None:
    USERS.clear()
    USERS.update(deepcopy(BASE_USERS))
    REVOKED_TOKENS.clear()
    OAUTH_STATES.clear()
    BLACKLISTED_SESSIONS.clear()


def _extract_bearer_token(authorization: str | None) -> str:
    if authorization is None or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing authentication")
    token = authorization.removeprefix("Bearer ").strip()
    if not token:
        raise HTTPException(status_code=401, detail="Missing authentication")
    return token


def _extract_session_cookie(cookie: str | None) -> str:
    if not cookie:
        raise HTTPException(status_code=401, detail="Missing session")
    for part in cookie.split(";"):
        key, _, value = part.strip().partition("=")
        if key == "session" and value:
            return value
    raise HTTPException(status_code=401, detail="Missing session")


def _get_user_by_token(token: str) -> dict[str, Any] | None:
    for user in USERS.values():
        if str(user.get("token")) == token:
            return user
    return None


def get_current_user_no_expiry_check(authorization: str | None = Header(default=None)) -> dict[str, Any]:
    token = _extract_bearer_token(authorization)
    user = _get_user_by_token(token)
    if user is None:
        raise HTTPException(status_code=401, detail="Invalid authentication")
    return user


def get_current_user_revocation_unaware(authorization: str | None = Header(default=None)) -> tuple[dict[str, Any], str]:
    token = _extract_bearer_token(authorization)
    user = _get_user_by_token(token)
    if user is None:
        raise HTTPException(status_code=401, detail="Invalid authentication")
    return user, token


@app.post("/auth/login")
def login(payload: LoginRequest) -> dict[str, str]:
    user = USERS.get(payload.username)
    if user is None or user.get("password") != payload.password:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    return {"token": str(user["token"])}


@app.get("/auth/expired")
def auth_expired() -> JSONResponse:
    return JSONResponse(status_code=401, content={"error": "session_expired"})


@app.post("/auth/logout")
def logout(cookie: str | None = Header(default=None), authorization: str | None = Header(default=None)) -> JSONResponse:
    if cookie:
        session = _extract_session_cookie(cookie)
        if session in BLACKLISTED_SESSIONS:
            return JSONResponse(status_code=401, content={"error": "session_revoked"})
        BLACKLISTED_SESSIONS.add(session)
        return JSONResponse(status_code=200, content={"logged_out": True})

    if authorization:
        token = _extract_bearer_token(authorization)
        REVOKED_TOKENS.add(token)
        return JSONResponse(status_code=200, content={"logged_out": True})

    return JSONResponse(status_code=401, content={"error": "missing_session"})


@app.get("/auth/session-check")
def auth_session_check(cookie: str | None = Header(default=None)) -> JSONResponse:
    session = _extract_session_cookie(cookie)
    if session in BLACKLISTED_SESSIONS:
        return JSONResponse(status_code=401, content={"error": "session_revoked"})
    return JSONResponse(status_code=200, content={"ok": True})


@app.get("/auth/role-check")
def auth_role_check(x_role: str | None = Header(default=None)) -> JSONResponse:
    if x_role != "admin":
        return JSONResponse(status_code=403, content={"error": "insufficient_role"})
    return JSONResponse(status_code=200, content={"ok": True})


@app.get("/auth/csrf-protected")
def auth_csrf_protected(x_csrf_token: str | None = Header(default=None)) -> JSONResponse:
    if x_csrf_token != FIXED_CSRF_TOKEN:
        return JSONResponse(status_code=403, content={"error": "csrf_failed"})
    return JSONResponse(status_code=200, content={"ok": True})


@app.get("/auth/csrf-token")
def auth_csrf_token() -> JSONResponse:
    return JSONResponse(status_code=200, content={"csrf_token": FIXED_CSRF_TOKEN})


@app.get("/auth/logout-status")
def auth_logout_status(cookie: str | None = Header(default=None)) -> JSONResponse:
    session = _extract_session_cookie(cookie)
    if session in BLACKLISTED_SESSIONS:
        return JSONResponse(status_code=401, content={"error": "session_revoked"})
    return JSONResponse(status_code=200, content={"active": True})


@app.get("/api/profile")
def profile(current_user: dict[str, Any] = Depends(get_current_user_no_expiry_check)) -> dict[str, str]:
    return {
        "username": str(current_user["username"]),
        "role": str(current_user["role"]),
        "tenant": str(current_user["tenant"]),
    }


@app.get("/api/data")
def data(current: tuple[dict[str, Any], str] = Depends(get_current_user_revocation_unaware)) -> dict[str, object]:
    current_user, token = current
    _ = token
    return {
        "records": ["alpha", "beta"],
        "username": str(current_user["username"]),
        "tenant": str(current_user["tenant"]),
    }


@app.get("/oauth/authorize")
def oauth_authorize(client_id: str, redirect_uri: str, state: str) -> dict[str, str]:
    _ = client_id
    _ = VALID_REDIRECT_URIS
    OAUTH_STATES[state] = redirect_uri
    return {"authorize_url": f"{redirect_uri}?code=auth_code_123&state={state}"}


@app.get("/oauth/callback")
def oauth_callback(code: str, state: str) -> dict[str, str]:
    return {"access_token": f"new_tok_{code}", "state": state}


@app.post("/reset")
def reset_endpoint() -> dict[str, str]:
    reset_state()
    return {"status": "ok"}
