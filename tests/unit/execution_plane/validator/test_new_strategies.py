from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

from execution_plane.validator.strategies.injection import InjectionStrategy
from execution_plane.validator.strategies.misconfiguration import MisconfigurationStrategy
from execution_plane.validator.strategies.rate_limit_abuse import RateLimitAbuseStrategy
from execution_plane.validator.strategies.session_misuse import SessionMisuseStrategy
from storage.db.models import RawProbe


def _probe(
    *,
    method: str = "GET",
    url: str = "https://example.test/api/resource",
    path: str | None = None,
    probe_type: str | None = None,
    status: int = 200,
    body: object = "",
    headers: dict[str, object] | None = None,
    latency_ms: float | int | None = None,
    statuses: list[int] | None = None,
    attack_task_id=None,
) -> RawProbe:
    task_id = attack_task_id or uuid4()

    request_payload: dict[str, object] = {"method": method, "url": url}
    if path is not None:
        request_payload["path"] = path
    if probe_type is not None:
        request_payload["probe_type"] = probe_type

    response_payload: dict[str, object] = {"status": status, "body": body}
    if headers is not None:
        response_payload["headers"] = headers
    if latency_ms is not None:
        response_payload["latency_ms"] = latency_ms
    if statuses is not None:
        response_payload["statuses"] = statuses

    return RawProbe(
        id=uuid4(),
        attack_task_id=task_id,
        worker_id="worker-test",
        timestamp=datetime.now(UTC),
        request=request_payload,
        response=response_payload,
        control_probe_id=None,
    )


def test_session_replay_returns_finding_on_200_response() -> None:
    strategy = SessionMisuseStrategy()
    attack_probe = _probe(probe_type="replay", status=200, body={"user": "data"})

    artifact = strategy.validate(attack_probe=attack_probe, control_probe=None)

    assert artifact is not None
    assert artifact.confidence_score >= 0.85


def test_session_replay_returns_none_on_401() -> None:
    strategy = SessionMisuseStrategy()
    attack_probe = _probe(probe_type="replay", status=401, body={"error": "unauthorized"})

    artifact = strategy.validate(attack_probe=attack_probe, control_probe=None)

    assert artifact is None


def test_stale_session_detected_on_200() -> None:
    strategy = SessionMisuseStrategy()
    attack_probe = _probe(probe_type="stale_session", status=200, body={"ok": True})

    artifact = strategy.validate(attack_probe=attack_probe, control_probe=None)

    assert artifact is not None
    assert artifact.confidence_score >= 0.85


def test_burst_no_throttling_returns_finding() -> None:
    strategy = RateLimitAbuseStrategy()
    attack_probe = _probe(probe_type="burst", status=200, statuses=[200, 200, 200])

    artifact = strategy.validate(attack_probe=attack_probe, control_probe=None)

    assert artifact is not None
    assert artifact.confidence_score >= 0.85


def test_burst_with_429_returns_none() -> None:
    strategy = RateLimitAbuseStrategy()
    attack_probe = _probe(probe_type="burst", status=429, statuses=[200, 429])

    artifact = strategy.validate(attack_probe=attack_probe, control_probe=None)

    assert artifact is None


def test_cors_wildcard_detected() -> None:
    strategy = MisconfigurationStrategy()
    attack_probe = _probe(
        probe_type="cors_wildcard",
        status=200,
        headers={"Access-Control-Allow-Origin": "*"},
    )

    artifact = strategy.validate(attack_probe=attack_probe, control_probe=None)

    assert artifact is not None
    assert artifact.confidence_score >= 0.90


def test_debug_endpoint_responsive() -> None:
    strategy = MisconfigurationStrategy()
    attack_probe = _probe(
        probe_type="debug_endpoint",
        status=200,
        path="/debug/config",
        url="https://example.test/debug/config",
        body={"ok": True},
    )

    artifact = strategy.validate(attack_probe=attack_probe, control_probe=None)

    assert artifact is not None
    assert artifact.confidence_score >= 0.85


def test_sql_error_detected() -> None:
    strategy = InjectionStrategy()
    attack_probe = _probe(probe_type="error_based", status=200, body="SQL syntax error near SELECT")

    artifact = strategy.validate(attack_probe=attack_probe, control_probe=None)

    assert artifact is not None
    assert artifact.confidence_score >= 0.90


def test_timing_based_detected() -> None:
    strategy = InjectionStrategy()
    attack_probe = _probe(probe_type="timing_based", status=200, latency_ms=5000, body="ok")

    artifact = strategy.validate(attack_probe=attack_probe, control_probe=None)

    assert artifact is not None
    assert artifact.confidence_score >= 0.86


def test_clean_response_returns_none() -> None:
    strategy = InjectionStrategy()
    attack_probe = _probe(probe_type="error_based", status=200, latency_ms=100, body="all good")

    artifact = strategy.validate(attack_probe=attack_probe, control_probe=None)

    assert artifact is None
