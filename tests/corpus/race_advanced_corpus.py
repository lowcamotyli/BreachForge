from __future__ import annotations

import json
from datetime import UTC, datetime
from uuid import uuid4

from execution_plane.validator.strategies.race_advanced import (
    DistributedLockEvasionStrategy,
    DoubleSpendStrategy,
    IdempotencyBypassStrategy,
    LimitOverrideRaceStrategy,
)
from storage.db.models import ProofArtifact, RawProbe


def _probe(*, request: dict[str, object], response: dict[str, object]) -> RawProbe:
    return RawProbe(
        id=uuid4(),
        attack_task_id=uuid4(),
        worker_id="corpus-race-advanced",
        timestamp=datetime.now(UTC),
        request=request,
        response=response,
        control_probe_id=None,
    )


def test_limit_override_race_finding() -> None:
    probe = _probe(
        request={
            "method": "POST",
            "url": "https://api.example.test/api/coupons/redeem",
            "probe_type": "race_concurrent",
            "target_parameter": "limit",
            "burst_concurrency": 5,
            "requests_sent": 5,
            "allowed_limit": 1,
            "reproduced": True,
            "body": json.dumps({"coupon_id": "LIMIT-ONE", "limit": 1}),
        },
        response={
            "status": 200,
            "accepted_count": 3,
            "allowed_limit": 1,
            "body": json.dumps(
                {
                    "requests_sent": 5,
                    "accepted_count": 3,
                    "allowed_limit": 1,
                    "responses": [
                        {"status": 200, "accepted": True, "redemption_id": "r-1"},
                        {"status": 200, "accepted": True, "redemption_id": "r-2"},
                        {"status": 200, "accepted": True, "redemption_id": "r-3"},
                        {"status": 409, "accepted": False},
                        {"status": 409, "accepted": False},
                    ],
                }
            ),
        },
    )

    strategy = LimitOverrideRaceStrategy()
    artifact = strategy.validate(probe, None)

    assert isinstance(artifact, ProofArtifact)
    assert artifact.confidence_score >= 0.85
    assert strategy.expected_attack_class() == "limit_override_race"
    assert "requests_sent=5" in artifact.evidence_notes
    assert "accepted_count=3" in artifact.evidence_notes
    assert "allowed_limit=1" in artifact.evidence_notes


def test_double_spend_finding() -> None:
    first_response = {"status": 200, "transfer_id": "tx-1", "amount": 75, "accepted": True}
    second_response = {"status": 200, "transfer_id": "tx-2", "amount": 75, "accepted": True}
    probe = _probe(
        request={
            "method": "POST",
            "url": "https://api.example.test/api/wallet/transfer",
            "probe_type": "race_concurrent",
            "safe_fixture": True,
            "reproduced": True,
            "body": json.dumps({"from": "fixture-wallet-a", "to": "fixture-wallet-b", "amount": 75}),
        },
        response={
            "status": 200,
            "first_response": first_response,
            "second_response": second_response,
            "transfer_sum": 150,
            "original_balance": 100,
            "body": json.dumps(
                {
                    "responses": [first_response, second_response],
                    "first_response": first_response,
                    "second_response": second_response,
                    "transfer_sum": 150,
                    "original_balance": 100,
                }
            ),
        },
    )

    strategy = DoubleSpendStrategy()
    artifact = strategy.validate(probe, None)

    assert isinstance(artifact, ProofArtifact)
    assert artifact.confidence_score >= 0.85
    assert strategy.expected_attack_class() == "double_spend"
    assert "first_response" in artifact.evidence_notes
    assert "second_response" in artifact.evidence_notes
    assert "transfer_sum=150" in artifact.evidence_notes
    assert "original_balance=100" in artifact.evidence_notes


def test_idempotency_bypass_finding() -> None:
    first_response = {"status": 201, "operation_id": "op-1", "amount": 10}
    second_response = {"status": 201, "operation_id": "op-2", "amount": 20}
    probe = _probe(
        request={
            "method": "POST",
            "url": "https://api.example.test/api/orders",
            "probe_type": "race_idempotency_bypass",
            "headers": {"Idempotency-Key": "corpus-idempotency-key-1"},
            "reproduced": True,
            "first_params": {"sku": "sku-1", "quantity": 1},
            "second_params": {"sku": "sku-1", "quantity": 2},
            "body": json.dumps(
                {
                    "first_request": {"sku": "sku-1", "quantity": 1},
                    "second_request": {"sku": "sku-1", "quantity": 2},
                }
            ),
        },
        response={
            "status": 201,
            "first_response": first_response,
            "second_response": second_response,
            "response_diff": {"operation_id": ["op-1", "op-2"], "amount": [10, 20]},
            "body": json.dumps(
                {
                    "idempotency_key": "corpus-idempotency-key-1",
                    "first_response": first_response,
                    "second_response": second_response,
                    "response_diff": {"operation_id": ["op-1", "op-2"], "amount": [10, 20]},
                }
            ),
        },
    )

    strategy = IdempotencyBypassStrategy()
    artifact = strategy.validate(probe, None)

    assert isinstance(artifact, ProofArtifact)
    assert artifact.confidence_score >= 0.85
    assert strategy.expected_attack_class() == "idempotency_bypass"
    assert "first_response" in artifact.evidence_notes
    assert "second_response" in artifact.evidence_notes
    assert "op-1" in artifact.evidence_notes
    assert "op-2" in artifact.evidence_notes


def test_distributed_lock_evasion_finding() -> None:
    probe = _probe(
        request={
            "method": "POST",
            "url": "https://api.example.test/api/inventory/reserve",
            "probe_type": "race_concurrent",
            "safe_fixture": True,
            "reproduced": True,
            "body": json.dumps({"sku": "fixture-sku-1", "cycles": 3}),
        },
        response={
            "status": 200,
            "cycles": 3,
            "reserved_count": 2,
            "inventory_limit": 1,
            "body": json.dumps(
                {
                    "inventory_limit": 1,
                    "reserved_count": 2,
                    "cycles": 3,
                    "lock_evaded": True,
                    "responses": [
                        {"status": 200, "reserved": True, "reservation_id": "res-1"},
                        {"status": 200, "cancelled": True, "reservation_id": "res-1"},
                        {"status": 200, "reserved": True, "reservation_id": "res-2"},
                    ],
                }
            ),
        },
    )

    strategy = DistributedLockEvasionStrategy()
    artifact = strategy.validate(probe, None)

    assert isinstance(artifact, ProofArtifact)
    assert artifact.confidence_score >= 0.85
    assert strategy.expected_attack_class() == "distributed_lock_evasion"
