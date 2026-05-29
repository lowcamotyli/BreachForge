from __future__ import annotations

from copy import deepcopy
from typing import Any
from uuid import uuid4

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel


app = FastAPI(title="Business Race Benchmark Lab")

BASE_USERS: dict[str, dict[str, Any]] = {
    "alice": {
        "id": "alice",
        "username": "alice",
        "password": "alice123",
        "role": "user",
        "tenant": "tenant_a",
        "token": "tok_br_alice",
    },
    "bob": {
        "id": "bob",
        "username": "bob",
        "password": "bob123",
        "role": "admin",
        "tenant": "tenant_a",
        "token": "tok_br_bob",
    },
}

BASE_COUPONS: dict[str, dict[str, Any]] = {
    "SAVE10": {"code": "SAVE10", "discount": 0.10, "max_uses": 1, "used_by": []}
}
BASE_COUPON_REDEEMED_BY: dict[str, list[str]] = {}
BASE_INVENTORY: dict[str, dict[str, Any]] = {"item-1": {"id": "item-1", "stock": 5}}
BASE_ORDERS: dict[str, dict[str, Any]] = {}
BASE_PENDING_APPROVALS: dict[str, dict[str, Any]] = {}
BASE_CARTS: dict[str, dict[str, int]] = {username: {} for username in BASE_USERS}

USERS: dict[str, dict[str, Any]] = deepcopy(BASE_USERS)
COUPONS: dict[str, dict[str, Any]] = deepcopy(BASE_COUPONS)
COUPON_REDEEMED_BY: dict[str, list[str]] = deepcopy(BASE_COUPON_REDEEMED_BY)
INVENTORY: dict[str, dict[str, Any]] = deepcopy(BASE_INVENTORY)
ORDERS: dict[str, dict[str, Any]] = deepcopy(BASE_ORDERS)
PENDING_APPROVALS: dict[str, dict[str, Any]] = deepcopy(BASE_PENDING_APPROVALS)
CARTS: dict[str, dict[str, int]] = deepcopy(BASE_CARTS)

BENCHMARK_AUTH: dict[str, dict[str, str]] = {
    username: {"token": user["token"], "role": user["role"], "tenant": user["tenant"]}
    for username, user in BASE_USERS.items()
}


class LoginRequest(BaseModel):
    username: str
    password: str


class CouponRedeemRequest(BaseModel):
    coupon_code: str
    order_amount: float


class OrderCreateRequest(BaseModel):
    item_id: str
    quantity: int


class CartAddRequest(BaseModel):
    item_id: str
    quantity: int


def reset_state() -> None:
    USERS.clear()
    USERS.update(deepcopy(BASE_USERS))

    COUPONS.clear()
    COUPONS.update(deepcopy(BASE_COUPONS))

    COUPON_REDEEMED_BY.clear()
    COUPON_REDEEMED_BY.update(deepcopy(BASE_COUPON_REDEEMED_BY))

    INVENTORY.clear()
    INVENTORY.update(deepcopy(BASE_INVENTORY))

    ORDERS.clear()
    ORDERS.update(deepcopy(BASE_ORDERS))

    PENDING_APPROVALS.clear()
    PENDING_APPROVALS.update(deepcopy(BASE_PENDING_APPROVALS))

    CARTS.clear()
    CARTS.update(deepcopy(BASE_CARTS))


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
    return user


@app.post("/api/auth/login")
def login(payload: LoginRequest) -> dict[str, str]:
    user = USERS.get(payload.username)
    if user is None or user.get("password") != payload.password:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    return {"token": user["token"]}


@app.post("/api/coupons/redeem")
def redeem_coupon(
    payload: CouponRedeemRequest,
    current_user: dict[str, Any] = Depends(get_current_user),
) -> dict[str, Any]:
    coupon = COUPONS.get(payload.coupon_code)
    if coupon is None:
        raise HTTPException(status_code=404, detail="Coupon not found")

    used_by = coupon.setdefault("used_by", [])
    discount = float(coupon["discount"])

    # Vulnerable by design: duplicate user redemptions are not rejected, and
    # callers can observe success even after max_uses has been exceeded.
    if len(used_by) < int(coupon["max_uses"]):
        used_by.append(current_user["username"])
    COUPON_REDEEMED_BY.setdefault(payload.coupon_code, []).append(current_user["username"])

    discounted_amount = payload.order_amount * (1 - discount)
    return {
        "coupon_code": coupon["code"],
        "discount": discount,
        "discounted_amount": discounted_amount,
        "used_by": used_by,
    }


@app.get("/api/coupons/check-balance")
def check_coupon_balance(
    coupon_code: str,
    current_user: dict[str, Any] = Depends(get_current_user),
) -> dict[str, Any]:
    _ = current_user
    coupon = COUPONS.get(coupon_code)
    if coupon is None:
        raise HTTPException(status_code=404, detail="Coupon not found")

    # Vulnerable by design: reported balance/redeemability stays stale even
    # after redemption state has been recorded in COUPON_REDEEMED_BY.
    _ = COUPON_REDEEMED_BY.get(coupon_code, [])
    return {"balance": 100, "redeemable": True}


@app.post("/api/orders")
def create_order(
    payload: OrderCreateRequest,
    current_user: dict[str, Any] = Depends(get_current_user),
) -> dict[str, Any]:
    item = INVENTORY.get(payload.item_id)
    if item is None:
        raise HTTPException(status_code=404, detail="Item not found")

    order_id = f"order-{uuid4()}"
    order = {
        "id": order_id,
        "order_id": order_id,
        "user": current_user["username"],
        "tenant": current_user["tenant"],
        "item_id": payload.item_id,
        "quantity": payload.quantity,
        "status": "created",
    }
    ORDERS[order_id] = order
    return order


@app.post("/api/cart/add")
def add_to_cart(
    payload: CartAddRequest,
    current_user: dict[str, Any] = Depends(get_current_user),
) -> dict[str, Any]:
    if payload.item_id not in INVENTORY:
        raise HTTPException(status_code=404, detail="Item not found")

    username = current_user["username"]
    cart = CARTS.setdefault(username, {})
    cart[payload.item_id] = cart.get(payload.item_id, 0) + payload.quantity
    return {"user": username, "cart": cart}


@app.post("/api/orders/{order_id}/submit-for-approval")
def submit_for_approval(
    order_id: str,
    current_user: dict[str, Any] = Depends(get_current_user),
) -> dict[str, Any]:
    order = ORDERS.get(order_id)
    if order is None:
        raise HTTPException(status_code=404, detail="Order not found")

    order["status"] = "pending_approval"
    PENDING_APPROVALS[order_id] = {
        "order_id": order_id,
        "submitted_by": current_user["username"],
        "tenant": current_user["tenant"],
    }
    return {"order_id": order_id, "status": order["status"]}


@app.post("/api/orders/{order_id}/final-confirm")
def final_confirm(
    order_id: str,
    current_user: dict[str, Any] = Depends(get_current_user),
) -> dict[str, Any]:
    _ = current_user
    order = ORDERS.get(order_id)
    if order is None:
        raise HTTPException(status_code=404, detail="Order not found")

    order["status"] = "confirmed"
    return {"order_id": order_id, "status": order["status"], "order": order}


@app.post("/reset")
def reset_endpoint() -> dict[str, str]:
    reset_state()
    return {"status": "ok"}
