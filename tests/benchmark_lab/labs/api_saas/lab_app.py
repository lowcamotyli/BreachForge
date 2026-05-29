from __future__ import annotations

from copy import deepcopy
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel


app = FastAPI(title="Benchmark Lab A2 - API SaaS")

BASE_USERS: dict[str, dict[str, Any]] = {
    "alice": {
        "id": "alice",
        "username": "alice",
        "password": "alice123",
        "role": "user",
        "tenant": "tenant_a",
        "token": "tok_as_alice",
        "is_admin": False,
    },
    "bob": {
        "id": "bob",
        "username": "bob",
        "password": "bob123",
        "role": "admin",
        "tenant": "tenant_a",
        "token": "tok_as_bob",
        "is_admin": True,
    },
    "carol": {
        "id": "carol",
        "username": "carol",
        "password": "carol123",
        "role": "user",
        "tenant": "tenant_b",
        "token": "tok_as_carol",
        "is_admin": False,
    },
}

BASE_RESOURCES: dict[str, dict[str, Any]] = {
    "res-1": {"id": "res-1", "owner": "alice", "tenant": "tenant_a", "payload": "alpha"},
    "res-2": {"id": "res-2", "owner": "bob", "tenant": "tenant_a", "payload": "beta"},
    "res-3": {"id": "res-3", "owner": "carol", "tenant": "tenant_b", "payload": "gamma"},
}

BASE_WORKSPACES: dict[str, dict[str, Any]] = {
    "ws-1": {"id": "ws-1", "tenant": "tenant_a", "data": "secret_a"},
    "ws-2": {"id": "ws-2", "tenant": "tenant_b", "data": "secret_b"},
}

USERS: dict[str, dict[str, Any]] = deepcopy(BASE_USERS)
RESOURCES: dict[str, dict[str, Any]] = deepcopy(BASE_RESOURCES)
WORKSPACES: dict[str, dict[str, Any]] = deepcopy(BASE_WORKSPACES)

BENCHMARK_AUTH: dict[str, dict[str, str]] = {
    username: {"token": user["token"], "role": user["role"], "tenant": user["tenant"]}
    for username, user in BASE_USERS.items()
}


class LoginRequest(BaseModel):
    username: str
    password: str


class UserPatchRequest(BaseModel):
    is_admin: bool | None = None
    role: str | None = None


def reset_state() -> None:
    USERS.clear()
    USERS.update(deepcopy(BASE_USERS))

    RESOURCES.clear()
    RESOURCES.update(deepcopy(BASE_RESOURCES))

    WORKSPACES.clear()
    WORKSPACES.update(deepcopy(BASE_WORKSPACES))


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


@app.post("/api/v1/auth/login")
def login(payload: LoginRequest) -> dict[str, str]:
    user = USERS.get(payload.username)
    if user is None or user["password"] != payload.password:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    return {"token": user["token"]}


@app.get("/api/v1/resources/{resource_id}")
def get_resource(resource_id: str, current_user: dict[str, Any] = Depends(get_current_user)) -> dict[str, Any]:
    _ = current_user
    resource = RESOURCES.get(resource_id)
    if resource is None:
        raise HTTPException(status_code=404, detail="Resource not found")
    return resource


@app.post("/api/v1/admin/bulk-export")
def bulk_export(current_user: dict[str, Any] = Depends(get_current_user)) -> dict[str, Any]:
    _ = current_user
    return {"status": "export_started", "resources": list(RESOURCES.keys())}


@app.get("/api/v1/internal/debug")
def internal_debug() -> dict[str, Any]:
    return {"env": "benchmark", "users": len(USERS), "resources": len(RESOURCES)}


@app.get("/api/v1/workspaces/{workspace_id}/data")
def workspace_data(workspace_id: str, current_user: dict[str, Any] = Depends(get_current_user)) -> dict[str, Any]:
    _ = current_user
    workspace = WORKSPACES.get(workspace_id)
    if workspace is None:
        raise HTTPException(status_code=404, detail="Workspace not found")
    return {"workspace_id": workspace_id, "tenant": workspace["tenant"], "data": workspace["data"]}


@app.patch("/api/v1/users/me")
def patch_me(payload: UserPatchRequest, current_user: dict[str, Any] = Depends(get_current_user)) -> dict[str, Any]:
    if payload.is_admin is not None:
        current_user["is_admin"] = payload.is_admin
    if payload.role is not None:
        current_user["role"] = payload.role
    return {
        "id": current_user["id"],
        "username": current_user["username"],
        "role": current_user["role"],
        "tenant": current_user["tenant"],
        "is_admin": current_user["is_admin"],
    }


@app.get("/api/v1/openapi-spec")
def openapi_spec() -> dict[str, list[str]]:
    return {
        "documented_endpoints": [
            "/api/v1/resources/{resource_id}",
            "/api/v1/admin/bulk-export",
            "/api/v1/workspaces/{workspace_id}/data",
            "/api/v1/users/me",
            "/api/v1/auth/login",
        ]
    }


@app.post("/reset")
def reset_endpoint() -> dict[str, str]:
    reset_state()
    return {"status": "ok"}
