from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import pytest

from execution_plane.validator.strategies.race_advanced import (
    DistributedLockEvasionStrategy,
    DoubleSpendStrategy,
    IdempotencyBypassStrategy,
    InventoryReservationStrategy,
    LimitOverrideRaceStrategy,
)
from storage.db.models import ProofArtifact, RawProbe


def _probe(*, request: dict[str, Any], response: dict[str, Any]) -> RawProbe:
    return RawProbe(
        id=uuid4(),
        attack_task_id=uuid4(),
        worker_id="worker-test",
        timestamp=datetime.now(UTC),
        request=request,
        response=response,
        control_probe_id=None,
    )


STRATEGY_CASES = (
    pytest.param(
        LimitOverrideRaceStrategy,
        "limit_override_race",
        0.92,
        {
            "requests_sent": 5,
            "allowed_limit": 1,
        },
        {
            "accepted_count": 2,
            "allowed_limit": 1,
        },
        id="limit-override-race",
    ),
    pytest.param(
        DoubleSpendStrategy,
        "double_spend",
        0.94,
        {
            "safe_fixture": True,
            "transaction_id": "txn-safe-fixture",
        },
        {
            "first_response": {"status": 200, "amount": 70},
            "second_response": {"status": 200, "amount": 70},
            "original_balance": 100,
        },
        id="double-spend",
    ),
    pytest.param(
        IdempotencyBypassStrategy,
        "idempotency_bypass",
        0.88,
        {
            "idempotency_key": "idem-safe-fixture",
            "first_params": {"quantity": 1},
            "second_params": {"quantity": 2},
        },
        {
            "first_response": {"status": 200, "order_id": "order-1", "quantity": 1},
            "second_response": {"status": 200, "order_id": "order-2", "quantity": 2},
        },
        id="idempotency-bypass",
    ),
    pytest.param(
        DistributedLockEvasionStrategy,
        "distributed_lock_evasion",
        0.87,
        {
            "safe_fixture": True,
            "lock_key": "inventory-safe-fixture",
            "cycles": 3,
        },
        {
            "cycles": 3,
            "reserved_count": 2,
            "inventory_limit": 1,
        },
        id="distributed-lock-evasion",
    ),
)


@pytest.mark.parametrize(
    ("strategy_cls", "attack_class", "expected_confidence", "signal_request", "signal_response"),
    STRATEGY_CASES,
)
def test_advanced_race_strategy_single_burst_is_capped_below_threshold(
    strategy_cls: type,
    attack_class: str,
    expected_confidence: float,
    signal_request: dict[str, Any],
    signal_response: dict[str, Any],
) -> None:
    del expected_confidence
    strategy = strategy_cls()
    probe = _probe(
        request={**signal_request, "reproduction_count": 1, "reproduced": False},
        response=signal_response,
    )

    artifact = strategy.validate(probe, None)

    assert strategy.expected_attack_class() == attack_class
    assert artifact is None


@pytest.mark.parametrize(
    ("strategy_cls", "attack_class", "expected_confidence", "signal_request", "signal_response"),
    STRATEGY_CASES,
)
def test_advanced_race_strategy_reproduction_count_returns_artifact(
    strategy_cls: type,
    attack_class: str,
    expected_confidence: float,
    signal_request: dict[str, Any],
    signal_response: dict[str, Any],
) -> None:
    strategy = strategy_cls()
    probe = _probe(
        request={**signal_request, "reproduction_count": 2, "reproduced": False},
        response=signal_response,
    )

    artifact = strategy.validate(probe, None)

    assert isinstance(artifact, ProofArtifact)
    assert strategy.expected_attack_class() == attack_class
    assert artifact.proof_type == strategy.expected_proof_type()
    assert artifact.confidence_score == expected_confidence
    assert artifact.attack_probe_id == probe.id
    assert artifact.control_probe_id is None


@pytest.mark.parametrize(
    ("strategy_cls", "attack_class", "expected_confidence", "signal_request", "signal_response"),
    STRATEGY_CASES,
)
def test_advanced_race_strategy_reproduced_flag_returns_artifact(
    strategy_cls: type,
    attack_class: str,
    expected_confidence: float,
    signal_request: dict[str, Any],
    signal_response: dict[str, Any],
) -> None:
    strategy = strategy_cls()
    probe = _probe(
        request={**signal_request, "reproduction_count": 1, "reproduced": True},
        response=signal_response,
    )

    artifact = strategy.validate(probe, None)

    assert isinstance(artifact, ProofArtifact)
    assert strategy.expected_attack_class() == attack_class
    assert artifact.confidence_score == expected_confidence


@pytest.mark.parametrize(
    ("strategy_cls", "attack_class", "expected_confidence", "signal_request", "signal_response"),
    STRATEGY_CASES,
)
def test_advanced_race_strategy_missing_proof_signal_returns_none(
    strategy_cls: type,
    attack_class: str,
    expected_confidence: float,
    signal_request: dict[str, Any],
    signal_response: dict[str, Any],
) -> None:
    del attack_class, expected_confidence, signal_response
    strategy = strategy_cls()
    probe = _probe(
        request={**signal_request, "reproduction_count": 2, "reproduced": True},
        response={"status": 200, "body": {"ok": True}},
    )

    assert strategy.validate(probe, None) is None


@pytest.mark.parametrize(
    ("strategy_cls", "attack_class", "expected_confidence", "signal_request", "signal_response"),
    (
        STRATEGY_CASES[1],
        STRATEGY_CASES[3],
    ),
)
def test_mutating_advanced_race_strategy_requires_safe_fixture(
    strategy_cls: type,
    attack_class: str,
    expected_confidence: float,
    signal_request: dict[str, Any],
    signal_response: dict[str, Any],
) -> None:
    del attack_class, expected_confidence
    strategy = strategy_cls()
    probe = _probe(
        request={**signal_request, "safe_fixture": False, "reproduction_count": 2, "reproduced": True},
        response=signal_response,
    )

    assert strategy.validate(probe, None) is None


def test_inventory_reservation_strategy_detects_overallocation() -> None:
    probe = _probe(
        request={"reproduced": True},
        response={
            "status_code": 200,
            "accepted_count": 3,
            "available_stock": 1,
            "final_state": {"reserved": 3},
        },
    )

    artifact = InventoryReservationStrategy().validate(probe, None)

    assert isinstance(artifact, ProofArtifact)
    assert artifact.confidence_score >= 0.85


def test_race_strategy_rejects_status_only_probe() -> None:
    probe = _probe(
        request={"reproduced": True},
        response={
            "status_code": 200,
            "accepted_count": 2,
            "allowed_limit": 1,
        },
    )

    assert LimitOverrideRaceStrategy().validate(probe, None) is None
