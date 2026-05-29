from __future__ import annotations

from copy import deepcopy
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel


app = FastAPI(title="Benchmark Lab A3 - SPA HAR")

BASE_USERS: dict[str, dict[str, Any]] = {
    "alice": {
        "id": "alice",
        "username": "alice",
        "password": "alice123",
        "role": "user",
        "tenant": "tenant_a",
        "token": "tok_sh_alice",
    },
    "bob": {
        "id": "bob",
        "username": "bob",
        "password": "bob123",
        "role": "admin",
        "tenant": "tenant_a",
        "token": "tok_sh_bob",
    },
}

USERS: dict[str, dict[str, Any]] = deepcopy(BASE_USERS)

BENCHMARK_AUTH: dict[str, dict[str, str]] = {
    username: {"token": user["token"], "role": user["role"], "tenant": user["tenant"]}
    for username, user in BASE_USERS.items()
}


class LoginRequest(BaseModel):
    username: str
    password: str


def reset_state() -> None:
    USERS.clear()
    USERS.update(deepcopy(BASE_USERS))


def _extract_bearer_token(authorization: str | None) -> str:
    if authorization is None or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing authentication")
    token = authorization.removeprefix("Bearer ").strip()
    if not token:
        raise HTTPException(status_code=401, detail="Missing authentication")
    return token


def _get_user_by_token(token: str) -> dict[str, Any] | None:
    for user in USERS.values():
        if user["token"] == token:
            return user
    return None


def get_current_user(authorization: str | None = Header(default=None)) -> dict[str, Any]:
    token = _extract_bearer_token(authorization)
    user = _get_user_by_token(token)
    if user is None:
        raise HTTPException(status_code=401, detail="Invalid authentication")
    return user


@app.get("/", response_class=PlainTextResponse)
def index() -> PlainTextResponse:
    html = '<!doctype html><html><body><script src="/static/app.js"></script></body></html>'
    return PlainTextResponse(html)


@app.get("/static/app.js", response_class=PlainTextResponse)
def static_app_js() -> PlainTextResponse:
    js = 'const ENDPOINTS = {users: "/api/users", adminStats: "/api/admin/stats", metrics: "/api/internal/metrics"};'
    return PlainTextResponse(js)


@app.post("/api/auth/login")
def login(payload: LoginRequest) -> dict[str, str]:
    user = USERS.get(payload.username)
    if user is None or user["password"] != payload.password:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    return {"token": user["token"]}


@app.get("/api/users")
def users() -> list[dict[str, str]]:
    return [
        {"id": "alice", "username": "alice"},
        {"id": "bob", "username": "bob"},
    ]


@app.get("/api/profile")
def profile(current_user: dict[str, Any] = Depends(get_current_user)) -> dict[str, str]:
    return {
        "id": current_user["id"],
        "username": current_user["username"],
        "role": current_user["role"],
        "tenant": current_user["tenant"],
    }


@app.get("/api/admin/stats")
def admin_stats(current_user: dict[str, Any] = Depends(get_current_user)) -> dict[str, Any]:
    _ = current_user
    return {"active_users": len(USERS), "tenant": "tenant_a"}


@app.get("/api/internal/metrics")
def internal_metrics() -> dict[str, float]:
    return {"cpu": 0.1, "mem": 0.5}
