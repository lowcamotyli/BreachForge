from __future__ import annotations

import json
from datetime import UTC, datetime
from uuid import uuid4

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
