from __future__ import annotations

from execution_plane.validator.strategies.bola import BolaStrategy
from execution_plane.validator.strategies.business_logic_advanced import (
    AccountEnumerationTimingStrategy,
    IntegerOverflowStrategy,
    InventoryReservationStrategy,
    NegativeValueStrategy,
    PriceManipulationStrategy,
)
from execution_plane.validator.strategies.workflow_abuse import WorkflowAbuseStrategy


def test_workflow_abuse_requires_state_effect() -> None:
    assert WorkflowAbuseStrategy().requires_state_effect() is True


def test_negative_value_requires_state_effect() -> None:
    assert NegativeValueStrategy().requires_state_effect() is True


def test_price_manipulation_requires_state_effect() -> None:
    assert PriceManipulationStrategy().requires_state_effect() is True


def test_integer_overflow_requires_state_effect() -> None:
    assert IntegerOverflowStrategy().requires_state_effect() is True


def test_inventory_reservation_requires_state_effect() -> None:
    assert InventoryReservationStrategy().requires_state_effect() is True


def test_account_enumeration_timing_does_not_require_state_effect() -> None:
    assert AccountEnumerationTimingStrategy().requires_state_effect() is False


def test_strategy_without_override_defaults_to_false() -> None:
    assert BolaStrategy().requires_state_effect() is False
