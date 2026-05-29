from __future__ import annotations

from copy import deepcopy
from typing import Any

from fastapi import FastAPI, Header, HTTPException, Request


app = FastAPI(title="GraphQL Benchmark Lab")

BASE_USERS: dict[str, dict[str, Any]] = {
    "alice": {
        "id": "alice",
        "username": "alice",
        "role": "user",
        "tenant": "tenant_a",
        "token": "tok_gql_alice",
    },
    "bob": {
        "id": "bob",
        "username": "bob",
        "role": "admin",
        "tenant": "tenant_a",
        "token": "tok_gql_bob",
    },
    "carol": {
        "id": "carol",
        "username": "carol",
        "role": "user",
        "tenant": "tenant_b",
        "token": "tok_gql_carol",
    },
}

BASE_ADMIN_CONFIG: dict[str, Any] = {"secret": "admin_secret_value", "maxUsers": 100}
BASE_SCHEMA: dict[str, Any] = {
    "types": [
        {"name": "Query"},
        {"name": "User"},
        {"name": "AdminConfig"},
        {"name": "Order"},
        {"name": "OrderItem"},
        {"name": "Product"},
        {"name": "Category"},
    ]
}
BASE_NESTED_USER: dict[str, Any] = {
    "orders": [{"items": [{"product": {"category": {"name": "Electronics"}}}]}]
}

USERS: dict[str, dict[str, Any]] = deepcopy(BASE_USERS)
ADMIN_CONFIG: dict[str, Any] = deepcopy(BASE_ADMIN_CONFIG)
SCHEMA: dict[str, Any] = deepcopy(BASE_SCHEMA)
NESTED_USER: dict[str, Any] = deepcopy(BASE_NESTED_USER)

BENCHMARK_AUTH: dict[str, dict[str, str]] = {
    username: {"token": user["token"], "role": user["role"], "tenant": user["tenant"]}
    for username, user in BASE_USERS.items()
}


def reset_state() -> None:
    USERS.clear()
    USERS.update(deepcopy(BASE_USERS))

    ADMIN_CONFIG.clear()
    ADMIN_CONFIG.update(deepcopy(BASE_ADMIN_CONFIG))

    SCHEMA.clear()
    SCHEMA.update(deepcopy(BASE_SCHEMA))

    NESTED_USER.clear()
    NESTED_USER.update(deepcopy(BASE_NESTED_USER))


def _extract_bearer_token(authorization: str | None) -> str:
    if authorization is None or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing authentication")
    token = authorization.removeprefix("Bearer ").strip()
    if not token:
        raise HTTPException(status_code=401, detail="Missing authentication")
    return token


def _get_user_by_token(token: str) -> dict[str, Any] | None:
    for user in USERS.values():
        if user.get("token") == token:
            return user
    return None


def _get_current_user(authorization: str | None) -> dict[str, Any]:
    token = _extract_bearer_token(authorization)
    user = _get_user_by_token(token)
    if user is None:
        raise HTTPException(status_code=401, detail="Invalid authentication")
    return user


def _public_user(user: dict[str, Any]) -> dict[str, str]:
    return {
        "id": str(user["id"]),
        "username": str(user["username"]),
        "role": str(user["role"]),
        "tenant": str(user["tenant"]),
    }


def _execute_query(operation: dict[str, Any], authorization: str | None) -> dict[str, Any]:
    query = str(operation.get("query", ""))

    if "__schema" in query:
        return {"data": {"__schema": deepcopy(SCHEMA)}}

    if "adminConfig" in query:
        return {"data": {"adminConfig": deepcopy(ADMIN_CONFIG)}}

    if "users" in query and "viewer" not in query:
        return {"data": {"users": [_public_user(user) for user in USERS.values()]}}

    if "viewer" in query:
        current_user = _get_current_user(authorization)
        return {"data": {"viewer": _public_user(current_user)}}

    if "orders" in query or "category" in query or "product" in query:
        return {"data": {"user": deepcopy(NESTED_USER)}}

    raise HTTPException(status_code=400, detail="Unsupported query")


@app.post("/graphql")
async def graphql_endpoint(request: Request, authorization: str | None = Header(default=None)) -> Any:
    payload = await request.json()

    if isinstance(payload, list):
        return [_execute_query(operation, authorization) for operation in payload]

    if isinstance(payload, dict):
        return _execute_query(payload, authorization)

    raise HTTPException(status_code=400, detail="Malformed GraphQL request")
