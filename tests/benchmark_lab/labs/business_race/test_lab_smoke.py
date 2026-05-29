from __future__ import annotations

from fastapi.testclient import TestClient

from tests.benchmark_lab.labs.business_race.lab_app import app, reset_state


client = TestClient(app)


def _auth_headers() -> dict[str, str]:
    return {"Authorization": "Bearer tok_br_alice"}


def _redeem_coupon() -> None:
    response = client.post(
        "/api/coupons/redeem",
        json={"coupon_code": "SAVE10", "order_amount": 100.0},
        headers=_auth_headers(),
    )
    assert response.status_code == 200


def setup_function() -> None:
    reset_state()


def test_login_returns_token() -> None:
    response = client.post("/api/auth/login", json={"username": "alice", "password": "alice123"})

    assert response.status_code == 200
    assert response.json() == {"token": "tok_br_alice"}


def test_race_condition_present() -> None:
    payload = {"coupon_code": "SAVE10", "order_amount": 100.0}

    first = client.post("/api/coupons/redeem", json=payload, headers=_auth_headers())
    second = client.post("/api/coupons/redeem", json=payload, headers=_auth_headers())

    assert first.status_code == 200
    assert second.status_code == 200


def test_idempotency_vuln() -> None:
    payload = {"item_id": "item-1", "quantity": 1}

    first = client.post("/api/orders", json=payload, headers=_auth_headers())
    second = client.post("/api/orders", json=payload, headers=_auth_headers())

    assert first.status_code == 200
    assert second.status_code == 200
    assert first.json()["order_id"] != second.json()["order_id"]


def test_negative_quantity_allowed() -> None:
    response = client.post(
        "/api/cart/add",
        json={"item_id": "item-1", "quantity": -5},
        headers=_auth_headers(),
    )

    assert response.status_code == 200
    assert response.json()["cart"]["item-1"] == -5


def test_approval_skip_present() -> None:
    create_response = client.post(
        "/api/orders",
        json={"item_id": "item-1", "quantity": 1},
        headers=_auth_headers(),
    )
    order_id = create_response.json()["order_id"]

    confirm_response = client.post(f"/api/orders/{order_id}/final-confirm", headers=_auth_headers())

    assert confirm_response.status_code == 200
    assert confirm_response.json()["status"] == "confirmed"
    assert confirm_response.json()["order"]["status"] == "confirmed"


def test_check_balance_returns_stale_after_redeem() -> None:
    reset_state()
    _redeem_coupon()

    response = client.get(
        "/api/coupons/check-balance",
        params={"coupon_code": "SAVE10"},
        headers=_auth_headers(),
    )

    assert response.status_code == 200
    assert response.json()["redeemable"] is True


def test_check_balance_fresh_coupon() -> None:
    reset_state()

    response = client.get(
        "/api/coupons/check-balance",
        params={"coupon_code": "SAVE10"},
        headers=_auth_headers(),
    )

    assert response.status_code == 200
    assert response.json()["balance"] == 100
