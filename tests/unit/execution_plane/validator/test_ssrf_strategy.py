from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest

from execution_plane.validator.strategies.ssrf import SsrfStrategy
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


@pytest.mark.asyncio
async def test_metadata_hit_returns_absolute_confidence_095() -> None:
    strategy = SsrfStrategy()
    attack_probe = _probe(
        request={
            "method": "GET",
            "url": "https://app.example.test/fetch?url=...",
            "ssrf_target_url": "http://169.254.169.254/latest/meta-data/",
        },
        response={"status": 200, "body": "ami-id\ninstance-id\niam/security-credentials/"},
    )

    artifact = await strategy.validate(attack_probe=attack_probe, control_probe=None, oob_manager=None)

    assert artifact is not None
    assert artifact.proof_type == "absolute"
    assert artifact.confidence_score == 0.95
    assert "iam/security-credentials" in artifact.evidence_notes


@pytest.mark.asyncio
async def test_internal_ip_timing_delta_is_capped_at_072() -> None:
    strategy = SsrfStrategy()
    task_id = uuid4()
    control_probe = _probe(
        request={"method": "GET", "url": "https://app.example.test/fetch"},
        response={"status": 200, "body": "ok", "latency_ms": 150},
        attack_task_id=task_id,
    )
    attack_probe = _probe(
        request={
            "method": "GET",
            "url": "https://app.example.test/fetch?url=...",
            "ssrf_target_url": "http://10.0.0.1/",
        },
        response={"status": 504, "body": "", "latency_ms": 2600},
        attack_task_id=task_id,
    )

    artifact = await strategy.validate(
        attack_probe=attack_probe,
        control_probe=control_probe,
        oob_manager=None,
    )

    assert artifact is not None
    assert artifact.confidence_score <= 0.65
    assert "needs_oob_for_high_confidence=true" in artifact.evidence_notes


@pytest.mark.asyncio
async def test_protocol_probe_rejected_without_explicit_allowlist() -> None:
    strategy = SsrfStrategy()
    attack_probe = _probe(
        request={
            "method": "GET",
            "ssrf_target_url": "file:///etc/passwd",
        },
        response={"status": 200, "body": "hostname\ninstance-id"},
    )

    artifact = await strategy.validate(attack_probe=attack_probe, control_probe=None, oob_manager=None)

    assert artifact is None


@pytest.mark.asyncio
async def test_external_ip_probe_blocked_by_scope_guard() -> None:
    strategy = SsrfStrategy()
    attack_probe = _probe(
        request={
            "method": "GET",
            "ssrf_target_url": "http://203.0.113.10/",
        },
        response={"status": 200, "body": "instance-id"},
    )

    artifact = await strategy.validate(attack_probe=attack_probe, control_probe=None, oob_manager=None)

    assert artifact is None


@pytest.mark.asyncio
async def test_public_endpoint_evidence_notes_show_no_auth_branch() -> None:
    strategy = SsrfStrategy()
    attack_probe = _probe(
        request={
            "method": "GET",
            "url": "https://app.example.test/image?url=...",
            "headers": {},
            "ssrf_target_url": "http://metadata.google.internal/",
            "unauth_baseline_status": 200,
        },
        response={"status": 200, "body": "hostname"},
    )

    artifact = await strategy.validate(attack_probe=attack_probe, control_probe=None, oob_manager=None)

    assert artifact is not None
    assert "request_has_auth=False" in artifact.evidence_notes


@pytest.mark.asyncio
async def test_blind_ssrf_without_oob_has_low_confidence() -> None:
    strategy = SsrfStrategy()
    attack_probe = _probe(
        request={
            "method": "GET",
            "url": "https://app.example.test/fetch?url=...",
            "ssrf_target_url": "http://10.0.0.2/",
            "baseline_latency_ms": 100,
        },
        response={"status": 504, "body": "", "latency_ms": 3200},
    )

    artifact = await strategy.validate(
        attack_probe=attack_probe,
        control_probe=None,
        oob_manager=None,
    )

    assert artifact is None or artifact.confidence_score <= 0.65


def test_expected_attack_class_is_ssrf() -> None:
    assert SsrfStrategy().expected_attack_class() == "ssrf"
