from __future__ import annotations

from copy import deepcopy
from itertools import count
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel


app = FastAPI(title="ProofScan Benchmark Lab")

BASE_USERS: dict[str, dict[str, Any]] = {
    "alice": {
        "id": "alice",
        "username": "alice",
        "password": "alice123",
        "role": "user",
        "tenant": "tenant_a",
        "token": "tok_alice",
        "is_expired": False,
    },
    "bob": {
        "id": "bob",
        "username": "bob",
        "password": "bob123",
        "role": "admin",
        "tenant": "tenant_a",
        "token": "tok_bob",
        "is_expired": False,
    },
    "carol": {
        "id": "carol",
        "username": "carol",
        "password": "carol123",
        "role": "user",
        "tenant": "tenant_b",
        "token": "tok_carol",
        "is_expired": False,
    },
    "eve": {
        "id": "eve",
        "username": "eve",
        "password": "eve123",
        "role": "admin",
        "tenant": "tenant_b",
        "token": "tok_eve",
        "is_expired": False,
    },
    "expired": {
        "id": "expired",
        "username": "expired",
        "password": "expired123",
        "role": "user",
        "tenant": "tenant_a",
        "token": "tok_expired",
        "is_expired": True,
    },
}

BASE_ORDERS: dict[str, dict[str, Any]] = {
    "order-1": {"id": "order-1", "tenant": "tenant_a", "user": "alice", "amount": 99.99, "approved": False},
    "order-2": {"id": "order-2", "tenant": "tenant_a", "user": "bob", "amount": 149.99, "approved": False},
    "order-3": {"id": "order-3", "tenant": "tenant_b", "user": "carol", "amount": 79.99, "approved": False},
}

USERS: dict[str, dict[str, Any]] = deepcopy(BASE_USERS)
ORDERS: dict[str, dict[str, Any]] = deepcopy(BASE_ORDERS)
CARTS: dict[str, list[dict[str, Any]]] = {username: [] for username in BASE_USERS}
API_TOKENS: dict[str, list[dict[str, str]]] = {username: [] for username in BASE_USERS}
JOBS: dict[str, dict[str, str]] = {}

_token_counter = count(1)
_job_counter = count(1)


class LoginRequest(BaseModel):
    username: str
    password: str


class RoleUpdateRequest(BaseModel):
    role: str


class CartItemRequest(BaseModel):
    item_id: str
    quantity: int


class GraphQLRequest(BaseModel):
    query: str


def reset_state() -> None:
    USERS.clear()
    USERS.update(deepcopy(BASE_USERS))

    ORDERS.clear()
    ORDERS.update(deepcopy(BASE_ORDERS))

    CARTS.clear()
    CARTS.update({username: [] for username in BASE_USERS})

    API_TOKENS.clear()
    API_TOKENS.update({username: [] for username in BASE_USERS})

    JOBS.clear()


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


def get_current_user(authorization: str | None = Header(default=None)) -> dict[str, Any]:
    token = _extract_bearer_token(authorization)
    user = _get_user_by_token(token)
    if user is None:
        raise HTTPException(status_code=401, detail="Invalid authentication")
    if bool(user.get("is_expired", False)):
        raise HTTPException(status_code=401, detail="Token expired")
    return user


def get_current_user_allow_expired(authorization: str | None = Header(default=None)) -> dict[str, Any]:
    token = _extract_bearer_token(authorization)
    user = _get_user_by_token(token)
    if user is None:
        raise HTTPException(status_code=401, detail="Invalid authentication")
    return user


@app.post("/auth/login")
def login(payload: LoginRequest) -> dict[str, Any]:
    user = USERS.get(payload.username)
    if user is None or user.get("password") != payload.password:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    return {"token": user["token"], "role": user["role"], "tenant": user["tenant"]}


@app.get("/users/{user_id}")
def get_user(user_id: str, current_user: dict[str, Any] = Depends(get_current_user)) -> dict[str, Any]:
    _ = current_user
    user = USERS.get(user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return {
        "id": user["id"],
        "username": user["username"],
        "role": user["role"],
        "tenant": user["tenant"],
        "is_expired": user["is_expired"],
    }


@app.patch("/users/{user_id}/profile")
def update_profile(
    user_id: str,
    payload: RoleUpdateRequest,
    current_user: dict[str, Any] = Depends(get_current_user),
) -> dict[str, Any]:
    _ = current_user
    user = USERS.get(user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    user["role"] = payload.role
    return {"id": user["id"], "username": user["username"], "role": user["role"], "tenant": user["tenant"]}


@app.get("/orders/{order_id}")
def get_order(order_id: str, current_user: dict[str, Any] = Depends(get_current_user)) -> dict[str, Any]:
    _ = current_user
    order = ORDERS.get(order_id)
    if order is None:
        raise HTTPException(status_code=404, detail="Order not found")
    return order


@app.get("/users")
def list_users(current_user: dict[str, Any] = Depends(get_current_user)) -> dict[str, list[dict[str, Any]]]:
    tenant = current_user["tenant"]
    visible = [
        {"id": user["id"], "username": user["username"], "role": user["role"], "tenant": user["tenant"]}
        for user in USERS.values()
        if user["tenant"] == tenant
    ]
    return {"users": visible}


@app.post("/admin/users/{user_id}/ban")
def ban_user(user_id: str, current_user: dict[str, Any] = Depends(get_current_user)) -> dict[str, Any]:
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin required")
    user = USERS.get(user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    user["banned"] = True
    return {"status": "banned", "user_id": user_id}


@app.post("/admin/orders/{order_id}/approve")
def approve_order(order_id: str, current_user: dict[str, Any] = Depends(get_current_user)) -> dict[str, Any]:
    _ = current_user
    order = ORDERS.get(order_id)
    if order is None:
        raise HTTPException(status_code=404, detail="Order not found")
    order["approved"] = True
    return {"status": "approved", "order_id": order_id}


@app.get("/cart")
def get_cart(current_user: dict[str, Any] = Depends(get_current_user)) -> dict[str, Any]:
    username = current_user["username"]
    items = CARTS.setdefault(username, [])
    return {"user": username, "items": items}


@app.post("/cart/items")
def add_cart_item(payload: CartItemRequest, current_user: dict[str, Any] = Depends(get_current_user)) -> dict[str, Any]:
    username = current_user["username"]
    item = {"item_id": payload.item_id, "quantity": payload.quantity}
    CARTS.setdefault(username, []).append(item)
    return {"status": "added", "item": item}


@app.post("/cart/checkout")
def checkout(current_user: dict[str, Any] = Depends(get_current_user)) -> dict[str, Any]:
    username = current_user["username"]
    items = CARTS.setdefault(username, [])
    total_items = sum(item["quantity"] for item in items)
    result = {"status": "processed", "user": username, "items_processed": total_items}
    CARTS[username] = []
    return result


@app.post("/api-tokens")
def create_api_token(current_user: dict[str, Any] = Depends(get_current_user)) -> dict[str, Any]:
    username = current_user["username"]
    token_id = f"api-{next(_token_counter)}"
    token_value = f"{username}-{token_id}"
    token_obj = {"token_id": token_id, "token": token_value}
    API_TOKENS.setdefault(username, []).append(token_obj)
    return token_obj


@app.get("/api-tokens")
def list_api_tokens(current_user: dict[str, Any] = Depends(get_current_user)) -> dict[str, Any]:
    username = current_user["username"]
    return {"tokens": API_TOKENS.setdefault(username, [])}


@app.delete("/api-tokens/{token_id}")
def delete_api_token(token_id: str, current_user: dict[str, Any] = Depends(get_current_user)) -> dict[str, Any]:
    username = current_user["username"]
    tokens = API_TOKENS.setdefault(username, [])
    API_TOKENS[username] = [token for token in tokens if token["token_id"] != token_id]
    return {"deleted": True, "token_id": token_id}


@app.post("/jobs/export")
def start_export_job(current_user: dict[str, Any] = Depends(get_current_user_allow_expired)) -> dict[str, Any]:
    job_id = f"job-{next(_job_counter)}"
    JOBS[job_id] = {"status": "queued", "owner": current_user["username"]}
    return {"job_id": job_id, "status": "queued"}


@app.get("/jobs/{job_id}/status")
def get_job_status(job_id: str, current_user: dict[str, Any] = Depends(get_current_user)) -> dict[str, Any]:
    _ = current_user
    job = JOBS.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Job not found")
    return {"job_id": job_id, "status": job["status"]}


@app.post("/graphql")
def graphql_endpoint(payload: GraphQLRequest, current_user: dict[str, Any] = Depends(get_current_user)) -> dict[str, Any]:
    query = payload.query.strip()

    if "viewer" in query:
        return {
            "data": {
                "viewer": {
                    "id": current_user["id"],
                    "username": current_user["username"],
                    "role": current_user["role"],
                }
            }
        }

    if "user(" in query:
        marker = 'id: "'
        start = query.find(marker)
        if start == -1:
            raise HTTPException(status_code=400, detail="Malformed user query")
        start += len(marker)
        end = query.find('"', start)
        if end == -1:
            raise HTTPException(status_code=400, detail="Malformed user query")
        user_id = query[start:end]
        user = USERS.get(user_id)
        if user is None:
            return {"data": {"user": None}}
        return {
            "data": {
                "user": {
                    "id": user["id"],
                    "username": user["username"],
                    "tenant": user["tenant"],
                }
            }
        }

    if "orders" in query:
        return {
            "data": {
                "orders": [
                    {"id": order["id"], "amount": order["amount"], "tenant": order["tenant"]}
                    for order in ORDERS.values()
                ]
            }
        }

    raise HTTPException(status_code=400, detail="Unsupported query")
