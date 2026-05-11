from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

from execution_plane.validator.strategies.xxe import XxeBlindStrategy, XxeClassicStrategy, XxeErrorStrategy
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


def test_xxe_classic_passwd_hit_returns_095() -> None:
    strategy = XxeClassicStrategy()
    attack_probe = _probe(
        request={"method": "POST", "url": "https://app.example.test/xml", "payload": "file:///etc/passwd"},
        response={"status": 200, "body": "root:x:0:0:root:/root:/bin/bash"},
    )

    artifact = strategy.validate(attack_probe=attack_probe, control_probe=None)

    assert artifact is not None
    assert artifact.confidence_score == 0.95
    assert artifact.proof_type == "absolute"


def test_xxe_classic_daemon_hit_returns_095() -> None:
    strategy = XxeClassicStrategy()
    attack_probe = _probe(
        request={"method": "POST", "url": "https://app.example.test/xml", "payload": "file:///etc/passwd"},
        response={"status": 200, "body": "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin"},
    )

    artifact = strategy.validate(attack_probe=attack_probe, control_probe=None)

    assert artifact is not None
    assert artifact.confidence_score == 0.95


def test_xxe_classic_nobody_hit_returns_095() -> None:
    strategy = XxeClassicStrategy()
    attack_probe = _probe(
        request={"method": "POST", "url": "https://app.example.test/xml", "payload": "file:///etc/passwd"},
        response={"status": 200, "body": "nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin"},
    )

    artifact = strategy.validate(attack_probe=attack_probe, control_probe=None)

    assert artifact is not None
    assert artifact.confidence_score == 0.95


def test_xxe_classic_no_signal_returns_none() -> None:
    strategy = XxeClassicStrategy()
    attack_probe = _probe(
        request={"method": "POST", "url": "https://app.example.test/xml", "payload": "file:///etc/passwd"},
        response={"status": 200, "body": "<html><body>ok</body></html>"},
    )

    artifact = strategy.validate(attack_probe=attack_probe, control_probe=None)

    assert artifact is None


def test_xxe_error_path_disclosure_returns_080() -> None:
    strategy = XxeErrorStrategy()
    attack_probe = _probe(
        request={"method": "POST", "url": "https://app.example.test/xml"},
        response={"status": 500, "body": "/etc/passwd: No such file or directory"},
    )

    artifact = strategy.validate(attack_probe=attack_probe, control_probe=None)

    assert artifact is not None
    assert artifact.confidence_score == 0.80


def test_xxe_error_parser_class_returns_080() -> None:
    strategy = XxeErrorStrategy()
    attack_probe = _probe(
        request={"method": "POST", "url": "https://app.example.test/xml"},
        response={"status": 500, "body": "SAXParser exception"},
    )

    artifact = strategy.validate(attack_probe=attack_probe, control_probe=None)

    assert artifact is not None
    assert artifact.confidence_score == 0.80


def test_xxe_error_javax_xml_returns_080() -> None:
    strategy = XxeErrorStrategy()
    attack_probe = _probe(
        request={"method": "POST", "url": "https://app.example.test/xml"},
        response={"status": 500, "body": "javax.xml.parsers"},
    )

    artifact = strategy.validate(attack_probe=attack_probe, control_probe=None)

    assert artifact is not None
    assert artifact.confidence_score == 0.80


def test_xxe_error_no_signal_returns_none() -> None:
    strategy = XxeErrorStrategy()
    attack_probe = _probe(
        request={"method": "POST", "url": "https://app.example.test/xml"},
        response={"status": 500, "body": "Internal Server Error"},
    )

    artifact = strategy.validate(attack_probe=attack_probe, control_probe=None)

    assert artifact is None


async def test_xxe_blind_timing_over_2s_returns_065() -> None:
    strategy = XxeBlindStrategy()
    task_id = uuid4()
    control_probe = _probe(
        request={"method": "POST", "url": "https://app.example.test/xml"},
        response={"status": 200, "body": "ok", "latency_ms": 100},
        attack_task_id=task_id,
    )
    attack_probe = _probe(
        request={"method": "POST", "url": "https://app.example.test/xml"},
        response={"status": 504, "body": "", "latency_ms": 2500},
        attack_task_id=task_id,
    )

    artifact = await strategy.validate(attack_probe=attack_probe, control_probe=control_probe)

    assert artifact is not None
    assert artifact.confidence_score == 0.65
    assert "confidence_capped=true" in artifact.evidence_notes


async def test_xxe_blind_no_control_probe_returns_none() -> None:
    strategy = XxeBlindStrategy()
    attack_probe = _probe(
        request={"method": "POST", "url": "https://app.example.test/xml"},
        response={"status": 504, "body": "", "latency_ms": 2500},
    )

    artifact = await strategy.validate(attack_probe=attack_probe, control_probe=None)

    assert artifact is None


async def test_xxe_blind_timing_under_2s_returns_none() -> None:
    strategy = XxeBlindStrategy()
    task_id = uuid4()
    control_probe = _probe(
        request={"method": "POST", "url": "https://app.example.test/xml"},
        response={"status": 200, "body": "ok", "latency_ms": 100},
        attack_task_id=task_id,
    )
    attack_probe = _probe(
        request={"method": "POST", "url": "https://app.example.test/xml"},
        response={"status": 200, "body": "ok", "latency_ms": 1900},
        attack_task_id=task_id,
    )

    artifact = await strategy.validate(attack_probe=attack_probe, control_probe=control_probe)

    assert artifact is None
