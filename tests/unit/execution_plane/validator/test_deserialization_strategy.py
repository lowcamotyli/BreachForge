from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

from execution_plane.validator.strategies.deserialization import (
    DeserializationProbeStrategy,
    YamlDeserializationStrategy,
)
from storage.db.models import RawProbe


def _probe(
    *,
    request: dict[str, object],
    response: dict[str, object],
    attack_task_id=None,
) -> RawProbe:
    return RawProbe(
        id=uuid4(),
        attack_task_id=attack_task_id or uuid4(),
        worker_id="worker-test",
        timestamp=datetime.now(UTC),
        request=request,
        response=response,
        control_probe_id=None,
    )


def test_deser_java_ioexception_returns_085() -> None:
    strategy = DeserializationProbeStrategy()
    attack_probe = _probe(
        request={"method": "POST", "url": "https://app.example.test/import"},
        response={"status": 500, "body": "java.io.IOException: invalid stream header"},
    )

    artifact = strategy.validate(attack_probe=attack_probe, control_probe=None)

    assert artifact is not None
    assert artifact.confidence_score == 0.85


def test_deser_java_stream_corrupted_returns_085() -> None:
    strategy = DeserializationProbeStrategy()
    attack_probe = _probe(
        request={"method": "POST", "url": "https://app.example.test/import"},
        response={"status": 500, "body": "java.io.StreamCorruptedException"},
    )

    artifact = strategy.validate(attack_probe=attack_probe, control_probe=None)

    assert artifact is not None
    assert artifact.confidence_score == 0.85


def test_deser_python_pickle_error_returns_085() -> None:
    strategy = DeserializationProbeStrategy()
    attack_probe = _probe(
        request={"method": "POST", "url": "https://app.example.test/import"},
        response={"status": 500, "body": "pickle.UnpicklingError"},
    )

    artifact = strategy.validate(attack_probe=attack_probe, control_probe=None)

    assert artifact is not None
    assert artifact.confidence_score == 0.85


def test_deser_php_unserialize_returns_085() -> None:
    strategy = DeserializationProbeStrategy()
    attack_probe = _probe(
        request={"method": "POST", "url": "https://app.example.test/import"},
        response={"status": 500, "body": "__PHP_Incomplete_Class"},
    )

    artifact = strategy.validate(attack_probe=attack_probe, control_probe=None)

    assert artifact is not None
    assert artifact.confidence_score == 0.85


def test_deser_no_signal_returns_none() -> None:
    strategy = DeserializationProbeStrategy()
    attack_probe = _probe(
        request={"method": "POST", "url": "https://app.example.test/import"},
        response={"status": 200, "body": "OK normal response"},
    )

    artifact = strategy.validate(attack_probe=attack_probe, control_probe=None)

    assert artifact is None


def test_yaml_error_disclosure_returns_085() -> None:
    strategy = YamlDeserializationStrategy()
    attack_probe = _probe(
        request={"method": "POST", "url": "https://app.example.test/import"},
        response={"status": 500, "body": "yaml.constructor.ConstructorError"},
    )

    artifact = strategy.validate(attack_probe=attack_probe, control_probe=None)

    assert artifact is not None
    assert artifact.confidence_score == 0.85


def test_yaml_timeout_returns_072() -> None:
    strategy = YamlDeserializationStrategy()
    task_id = uuid4()
    control_probe = _probe(
        request={"method": "POST", "url": "https://app.example.test/import"},
        response={"status": 200, "body": "ok", "latency_ms": 100},
        attack_task_id=task_id,
    )
    attack_probe = _probe(
        request={"method": "POST", "url": "https://app.example.test/import"},
        response={"status": 504, "body": "", "latency_ms": 3500},
        attack_task_id=task_id,
    )

    artifact = strategy.validate(attack_probe=attack_probe, control_probe=control_probe)

    assert artifact is not None
    assert artifact.confidence_score == 0.72


def test_yaml_no_signal_returns_none() -> None:
    strategy = YamlDeserializationStrategy()
    attack_probe = _probe(
        request={"method": "POST", "url": "https://app.example.test/import"},
        response={"status": 200, "body": "OK normal response", "latency_ms": 100},
    )

    artifact = strategy.validate(attack_probe=attack_probe, control_probe=None)

    assert artifact is None
