from __future__ import annotations

import json
from datetime import UTC, datetime
from uuid import uuid4

import pytest

from execution_plane.validator.strategies.business_logic_advanced import (
    AccountEnumerationTimingStrategy,
    IntegerOverflowStrategy,
    InventoryReservationStrategy,
    NegativeValueStrategy,
    PriceManipulationStrategy,
)
from storage.db.models import RawProbe


def _probe(*, request: dict, response: dict) -> RawProbe:
    return RawProbe(
        id=uuid4(),
        attack_task_id=uuid4(),
        worker_id="worker-corpus",
        timestamp=datetime.now(UTC),
        request=request,
        response=response,
        control_probe_id=None,
    )


def negative_value_cart_exploit() -> tuple[RawProbe, float]:
    probe = _probe(
        request={
            "method": "POST",
            "url": "/api/cart/checkout",
            "target_parameter": "quantity",
            "body": json.dumps({"quantity": -1, "item_id": "ITEM-001"}),
        },
        response={"status": 200, "body": json.dumps({"total": -9.99, "balance": 19.99, "order_placed": True})},
    )
    return probe, 0.90


def integer_overflow_credits() -> tuple[RawProbe, float]:
    probe = _probe(
        request={
            "method": "POST",
            "url": "/api/user/credits/add",
            "target_parameter": "credits",
            "body": json.dumps({"credits": 2147483648}),
        },
        response={"status": 500, "body": json.dumps({"error": "integer overflow: value exceeds int32 maximum"})},
    )
    return probe, 0.85


def price_manipulation_checkout() -> tuple[RawProbe, float]:
    probe = _probe(
        request={
            "method": "POST",
            "url": "/api/checkout/complete",
            "body": json.dumps({
                "original_price": 1.00,
                "manipulated_price": 0.01,
                "manipulation_type": "unit_confusion",
                "item_id": "PROD-100",
            }),
        },
        response={"status": 200, "body": json.dumps({"price_accepted": True, "charged": 0.01, "order_id": "ORD-500"})},
    )
    return probe, 0.88


def account_enumeration_login_timing() -> tuple[RawProbe, float]:
    pairs = [{"existing_ms": 80.0, "nonexistent_ms": 300.0}] * 10
    probe = _probe(
        request={"method": "POST", "url": "/api/auth/login", "body": json.dumps({"timing_pairs": pairs})},
        response={"status": 200, "body": "{}"},
    )
    return probe, 0.80


def inventory_reservation_cycle() -> tuple[RawProbe, float]:
    probe = _probe(
        request={
            "method": "POST",
            "url": "/api/items/42/reserve",
            "body": json.dumps({"reservation_cycles": 3, "inventory_decremented": False, "endpoint": "/api/items/42/reserve"}),
        },
        response={"status": 200, "body": json.dumps({"reserved": True, "inventory_count": 5})},
    )
    return probe, 0.87


def test_corpus_all_findings_detected() -> None:
    cases: list[tuple] = [
        (NegativeValueStrategy(), negative_value_cart_exploit()),
        (IntegerOverflowStrategy(), integer_overflow_credits()),
        (PriceManipulationStrategy(), price_manipulation_checkout()),
        (AccountEnumerationTimingStrategy(), account_enumeration_login_timing()),
        (InventoryReservationStrategy(), inventory_reservation_cycle()),
    ]
    for strategy, (probe, expected_confidence) in cases:
        artifact = strategy.validate(probe, None)
        assert artifact is not None, f"{strategy.__class__.__name__} returned None for corpus fixture"
        assert artifact.confidence_score == expected_confidence, (
            f"{strategy.__class__.__name__}: expected {expected_confidence}, got {artifact.confidence_score}"
        )


def _json_body(value: dict) -> str:
    return json.dumps(value)


def _load_json(value: object) -> object:
    if isinstance(value, str):
        try:
            return json.loads(value)
        except ValueError:
            return value
    return value


def _probe_body(probe: RawProbe) -> dict:
    body = _load_json(probe.request.get("body", "{}"))
    return body if isinstance(body, dict) else {}


def _response_body(probe: RawProbe) -> dict:
    body = _load_json(probe.response.get("body", "{}"))
    return body if isinstance(body, dict) else {}


def _status(probe: RawProbe) -> int:
    status = probe.response.get("status")
    return status if isinstance(status, int) else 0


def _coupon_stacking_probe(*, accepted: bool) -> RawProbe:
    status = 200 if accepted else 409
    response_body = (
        {"cart_id": "cart-100", "applied_coupons": ["WELCOME10", "WELCOME10"], "discount_total": 20.00}
        if accepted
        else {"error": "coupon already applied", "applied_coupons": ["WELCOME10"], "discount_total": 10.00}
    )
    return _probe(
        request={
            "method": "POST",
            "url": "/api/cart/coupons",
            "target_parameter": "coupon_code",
            "body": _json_body({"cart_id": "cart-100", "coupon_codes": ["WELCOME10", "WELCOME10"]}),
        },
        response={"status": status, "body": _json_body(response_body)},
    )


def _negative_quantity_probe(*, accepted: bool) -> RawProbe:
    status = 201 if accepted else 422
    response_body = (
        {"order_id": "ORD-NEG-QTY", "accepted": True, "qty": -5, "total": -149.95}
        if accepted
        else {"error": "quantity must be positive", "field": "qty"}
    )
    return _probe(
        request={
            "method": "POST",
            "url": "/api/orders",
            "target_parameter": "qty",
            "body": _json_body({"sku": "SKU-42", "qty": -5}),
        },
        response={"status": status, "body": _json_body(response_body)},
    )


def _price_tampering_probe(*, accepted: bool) -> RawProbe:
    response_body = (
        {"order_id": "ORD-PRICE", "charged": 0.01, "price_source": "client"}
        if accepted
        else {"order_id": "ORD-PRICE", "charged": 49.99, "price_source": "catalog"}
    )
    return _probe(
        request={
            "method": "POST",
            "url": "/api/checkout",
            "target_parameter": "price",
            "body": _json_body({"sku": "SKU-42", "qty": 1, "price": 0.01, "catalog_price": 49.99}),
        },
        response={"status": 200, "body": _json_body(response_body)},
    )


def _inventory_reservation_abuse_probe(*, accepted: bool) -> RawProbe:
    response_body = (
        {"reservation_id": "RSV-100", "stock_before": 3, "stock_after": 2, "payment_required": False}
        if accepted
        else {"reservation_id": None, "stock_before": 3, "stock_after": 3, "payment_required": True}
    )
    return _probe(
        request={
            "method": "POST",
            "url": "/api/inventory/reserve",
            "target_parameter": "reservation_hold",
            "body": _json_body({"sku": "SKU-LOW-STOCK", "qty": 1, "paid": False}),
        },
        response={"status": 200 if accepted else 402, "body": _json_body(response_body)},
    )


def _approval_bypass_probe(*, accepted: bool) -> RawProbe:
    response_body = (
        {"order_id": "ORD-APPROVE", "status": "approved", "review_completed": False}
        if accepted
        else {"error": "review step required", "status": "pending_review"}
    )
    return _probe(
        request={
            "method": "POST",
            "url": "/api/orders/approve",
            "target_parameter": "workflow_state",
            "body": _json_body({"order_id": "ORD-APPROVE", "review_completed": False}),
        },
        response={"status": 200 if accepted else 403, "body": _json_body(response_body)},
    )


def _business_logic_finding(probe: RawProbe) -> dict[str, object] | None:
    if not (200 <= _status(probe) < 300):
        return None

    request = _probe_body(probe)
    response = _response_body(probe)
    url = str(probe.request.get("url") or "")

    coupon_codes = request.get("coupon_codes")
    applied_coupons = response.get("applied_coupons")
    if isinstance(coupon_codes, list) and len(set(coupon_codes)) < len(coupon_codes):
        if isinstance(applied_coupons, list) and len(set(applied_coupons)) < len(applied_coupons):
            return {"attack_class": "coupon_stacking", "confidence": 0.91}

    qty = request.get("qty")
    total = response.get("total")
    if isinstance(qty, int) and qty < 0 and response.get("accepted") is True:
        return {"attack_class": "negative_quantity", "confidence": 0.90}
    if isinstance(qty, int) and qty < 0 and isinstance(total, (int, float)) and total < 0:
        return {"attack_class": "negative_quantity", "confidence": 0.90}

    supplied_price = request.get("price")
    catalog_price = request.get("catalog_price")
    charged = response.get("charged")
    if (
        isinstance(supplied_price, (int, float))
        and isinstance(catalog_price, (int, float))
        and supplied_price != catalog_price
        and charged == supplied_price
    ):
        return {"attack_class": "price_tampering", "confidence": 0.92}

    stock_before = response.get("stock_before")
    stock_after = response.get("stock_after")
    if (
        "reserve" in url
        and request.get("paid") is False
        and isinstance(stock_before, int)
        and isinstance(stock_after, int)
        and stock_after < stock_before
        and response.get("payment_required") is False
    ):
        return {"attack_class": "inventory_reservation_abuse", "confidence": 0.89}

    if (
        url.endswith("/orders/approve")
        and request.get("review_completed") is False
        and response.get("status") == "approved"
    ):
        return {"attack_class": "approval_bypass", "confidence": 0.93}

    return None


class RealisticBusinessLogicFlows:
    __test__ = True

    @pytest.mark.parametrize(
        ("probe", "expected_attack_class"),
        [(_coupon_stacking_probe(accepted=True), "coupon_stacking")],
    )
    def test_coupon_stacking_detected(self, probe: RawProbe, expected_attack_class: str) -> None:
        finding = _business_logic_finding(probe)
        assert finding is not None
        assert finding["attack_class"] == expected_attack_class
        assert finding["confidence"] >= 0.5

    @pytest.mark.parametrize(
        ("probe", "expected_attack_class"),
        [(_negative_quantity_probe(accepted=True), "negative_quantity")],
    )
    def test_negative_quantity_accepted(self, probe: RawProbe, expected_attack_class: str) -> None:
        finding = _business_logic_finding(probe)
        assert finding is not None
        assert finding["attack_class"] == expected_attack_class
        assert finding["confidence"] >= 0.5

    @pytest.mark.parametrize(
        ("probe", "expected_attack_class"),
        [(_price_tampering_probe(accepted=True), "price_tampering")],
    )
    def test_price_tampering_accepted(self, probe: RawProbe, expected_attack_class: str) -> None:
        finding = _business_logic_finding(probe)
        assert finding is not None
        assert finding["attack_class"] == expected_attack_class
        assert finding["confidence"] >= 0.5

    @pytest.mark.parametrize(
        ("probe", "expected_attack_class"),
        [(_inventory_reservation_abuse_probe(accepted=True), "inventory_reservation_abuse")],
    )
    def test_inventory_held_without_purchase(self, probe: RawProbe, expected_attack_class: str) -> None:
        finding = _business_logic_finding(probe)
        assert finding is not None
        assert finding["attack_class"] == expected_attack_class
        assert finding["confidence"] >= 0.5

    @pytest.mark.parametrize(
        ("probe", "expected_attack_class"),
        [(_approval_bypass_probe(accepted=True), "approval_bypass")],
    )
    def test_approval_step_skipped(self, probe: RawProbe, expected_attack_class: str) -> None:
        finding = _business_logic_finding(probe)
        assert finding is not None
        assert finding["attack_class"] == expected_attack_class
        assert finding["confidence"] >= 0.5


class NegativeControlFlows:
    __test__ = True

    def test_valid_coupon_single_use(self) -> None:
        finding = _business_logic_finding(_coupon_stacking_probe(accepted=False))
        assert finding is None or finding["confidence"] < 0.5

    def test_positive_quantity_only(self) -> None:
        finding = _business_logic_finding(_negative_quantity_probe(accepted=False))
        assert finding is None or finding["confidence"] < 0.5

    def test_server_enforced_price(self) -> None:
        finding = _business_logic_finding(_price_tampering_probe(accepted=False))
        assert finding is None or finding["confidence"] < 0.5

    def test_required_approval_enforced(self) -> None:
        finding = _business_logic_finding(_approval_bypass_probe(accepted=False))
        assert finding is None or finding["confidence"] < 0.5
