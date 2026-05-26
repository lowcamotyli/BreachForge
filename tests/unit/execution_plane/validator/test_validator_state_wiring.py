from __future__ import annotations

import json
from unittest.mock import Mock
from uuid import uuid4

import pytest

from execution_plane.validator.strategies.base import ValidationStrategy
from storage.db.models import RawProbe

pytest.importorskip("redis")
pytest.importorskip("rq")

from execution_plane.validator.validator import ExploitValidator


class _NoopStrategy(ValidationStrategy):
    def validate(self, attack_probe: RawProbe, control_probe: RawProbe | None):
        return None

    def expected_proof_type(self) -> str:
        return "none"

    def expected_attack_class(self) -> str:
        return "bola"


def _validator() -> ExploitValidator:
    redis_client = Mock()
    evidence_store = Mock()
    return ExploitValidator(redis_client=redis_client, evidence_store=evidence_store, strategies={"bola": _NoopStrategy()})


def test_extract_state_snapshots_valid_payload() -> None:
    validator = _validator()
    scan_id = uuid4()
    attack_task_id = uuid4()
    payload = {
        "state_evidence": json.dumps(
            {
                "before": {"resource_count": 1, "status": "pending"},
                "after": {"resource_count": 2, "status": "updated"},
            }
        )
    }

    before_snap, after_snap = validator._extract_state_snapshots_from_payload(payload, scan_id, attack_task_id)

    assert before_snap is not None
    assert after_snap is not None
    assert before_snap.scan_id == str(scan_id)
    assert after_snap.scan_id == str(scan_id)
    assert before_snap.step_id == str(attack_task_id)
    assert after_snap.step_id == str(attack_task_id)
    assert before_snap.state_dict == {"resource_count": 1, "status": "pending"}
    assert after_snap.state_dict == {"resource_count": 2, "status": "updated"}
    assert before_snap.version == 1
    assert after_snap.version == 2


def test_extract_state_snapshots_missing_key() -> None:
    validator = _validator()

    before_snap, after_snap = validator._extract_state_snapshots_from_payload({}, uuid4(), uuid4())

    assert before_snap is None
    assert after_snap is None


def test_extract_state_snapshots_invalid_json() -> None:
    validator = _validator()
    payload = {"state_evidence": "not-json"}

    before_snap, after_snap = validator._extract_state_snapshots_from_payload(payload, uuid4(), uuid4())

    assert before_snap is None
    assert after_snap is None


def test_extract_state_snapshots_non_dict_before() -> None:
    validator = _validator()
    payload = {
        "state_evidence": json.dumps(
            {
                "before": ["not", "a", "dict"],
                "after": {"status": "ok"},
            }
        )
    }

    before_snap, after_snap = validator._extract_state_snapshots_from_payload(payload, uuid4(), uuid4())

    assert before_snap is None
    assert after_snap is None
