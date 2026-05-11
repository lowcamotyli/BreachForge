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
        worker_id="worker-test",
        timestamp=datetime.now(UTC),
        request=request,
        response=response,
        control_probe_id=None,
    )


def test_negative_value_accepted_returns_artifact() -> None:
    probe = _probe(
        request={
            "method": "POST",
            "url": "/api/cart/checkout",
            "target_parameter": "total",
            "body": json.dumps({"total": -1}),
        },
        response={"status": 200, "body": json.dumps({"total": -50, "message": "order placed"})},
    )
    artifact = NegativeValueStrategy().validate(probe, None)
    assert artifact is not None
    assert artifact.confidence_score == 0.90


def test_negative_value_rejected_returns_none() -> None:
    probe = _probe(
        request={
            "method": "POST",
            "url": "/api/cart/checkout",
            "target_parameter": "total",
            "body": json.dumps({"total": -1}),
        },
        response={"status": 400, "body": json.dumps({"error": "invalid amount"})},
    )
    assert NegativeValueStrategy().validate(probe, None) is None


def test_negative_value_non_numeric_response_returns_none() -> None:
    probe = _probe(
        request={"method": "POST", "url": "/api/cart/checkout", "target_parameter": "total"},
        response={"status": 200, "body": json.dumps({"status": "ok", "items": ["a", "b"]})},
    )
    assert NegativeValueStrategy().validate(probe, None) is None


def test_integer_overflow_error_message_reveals_type() -> None:
    probe = _probe(
        request={
            "method": "POST",
            "url": "/api/credits/add",
            "target_parameter": "credits",
            "body": json.dumps({"credits": 2147483648}),
        },
        response={"status": 500, "body": json.dumps({"error": "integer overflow in credits field"})},
    )
    artifact = IntegerOverflowStrategy().validate(probe, None)
    assert artifact is not None
    assert artifact.confidence_score == 0.85


def test_integer_overflow_wrapped_value_detected() -> None:
    probe = _probe(
        request={
            "method": "POST",
            "url": "/api/credits/add",
            "target_parameter": "balance",
            "body": json.dumps({"balance": 9223372036854775807}),
        },
        response={"status": 200, "body": json.dumps({"balance": -2147483648})},
    )
    assert IntegerOverflowStrategy().validate(probe, None) is not None


def test_integer_overflow_clean_response_returns_none() -> None:
    probe = _probe(
        request={"method": "POST", "url": "/api/credits/add", "target_parameter": "balance"},
        response={"status": 200, "body": json.dumps({"balance": 100})},
    )
    assert IntegerOverflowStrategy().validate(probe, None) is None


def test_price_manipulation_unit_confusion_accepted() -> None:
    probe = _probe(
        request={
            "method": "POST",
            "url": "/api/checkout",
            "body": json.dumps({"original_price": 1.00, "manipulated_price": 0.01, "manipulation_type": "unit_confusion"}),
        },
        response={"status": 200, "body": json.dumps({"price_accepted": True, "charged": 0.01})},
    )
    artifact = PriceManipulationStrategy().validate(probe, None)
    assert artifact is not None
    assert artifact.confidence_score == 0.88


def test_price_manipulation_currency_swap_accepted() -> None:
    probe = _probe(
        request={
            "method": "POST",
            "url": "/api/pay",
            "body": json.dumps({"manipulation_type": "currency_swap", "original_price": 100.00}),
        },
        response={"status": 200, "body": json.dumps({"currency_accepted": True, "amount": 100})},
    )
    assert PriceManipulationStrategy().validate(probe, None) is not None


def test_price_manipulation_rejected_returns_none() -> None:
    probe = _probe(
        request={
            "method": "POST",
            "url": "/api/checkout",
            "body": json.dumps({"manipulation_type": "unit_confusion"}),
        },
        response={"status": 400, "body": json.dumps({"error": "invalid price"})},
    )
    assert PriceManipulationStrategy().validate(probe, None) is None


def test_timing_oracle_above_threshold_returns_artifact() -> None:
    pairs = [{"existing_ms": 100.0, "nonexistent_ms": 350.0}] * 10
    probe = _probe(
        request={"method": "POST", "url": "/api/login", "body": json.dumps({"timing_pairs": pairs})},
        response={"status": 200, "body": "{}"},
    )
    artifact = AccountEnumerationTimingStrategy().validate(probe, None)
    assert artifact is not None
    assert artifact.confidence_score == 0.80


def test_timing_oracle_insufficient_pairs_returns_none() -> None:
    pairs = [{"existing_ms": 100.0, "nonexistent_ms": 350.0}] * 5
    probe = _probe(
        request={"method": "POST", "url": "/api/login", "body": json.dumps({"timing_pairs": pairs})},
        response={"status": 200, "body": "{}"},
    )
    assert AccountEnumerationTimingStrategy().validate(probe, None) is None


def test_timing_oracle_small_delta_returns_none() -> None:
    pairs = [{"existing_ms": 100.0, "nonexistent_ms": 101.0}] * 10
    probe = _probe(
        request={"method": "POST", "url": "/api/login", "body": json.dumps({"timing_pairs": pairs})},
        response={"status": 200, "body": "{}"},
    )
    assert AccountEnumerationTimingStrategy().validate(probe, None) is None


def test_reservation_cycle_exploit_returns_artifact() -> None:
    probe = _probe(
        request={
            "method": "POST",
            "url": "/api/products/1/reserve",
            "body": json.dumps({"reservation_cycles": 3, "inventory_decremented": False, "endpoint": "/api/products/1/reserve"}),
        },
        response={"status": 200, "body": "{}"},
    )
    artifact = InventoryReservationStrategy().validate(probe, None)
    assert artifact is not None
    assert artifact.confidence_score == 0.87


def test_reservation_single_cycle_returns_none() -> None:
    probe = _probe(
        request={
            "method": "POST",
            "url": "/api/products/1/reserve",
            "body": json.dumps({"reservation_cycles": 1, "inventory_decremented": False}),
        },
        response={"status": 200, "body": "{}"},
    )
    assert InventoryReservationStrategy().validate(probe, None) is None


def test_reservation_with_decrement_returns_none() -> None:
    probe = _probe(
        request={
            "method": "POST",
            "url": "/api/products/1/reserve",
            "body": json.dumps({"reservation_cycles": 3, "inventory_decremented": True}),
        },
        response={"status": 200, "body": "{}"},
    )
    assert InventoryReservationStrategy().validate(probe, None) is None
