from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

from execution_plane.validator.strategies.cache_poisoning import CachePoisoningStrategy, WebCacheDeceptionStrategy
from execution_plane.validator.strategies.http_smuggling import (
    HttpMethodOverrideStrategy,
    HttpParameterPollutionStrategy,
    HttpSmugglingStrategy,
)
from storage.db.models import RawProbe


def _probe(*, request: dict[str, object], response: dict[str, object]) -> RawProbe:
    return RawProbe(
        id=uuid4(),
        attack_task_id=uuid4(),
        worker_id="worker-test",
        timestamp=datetime.now(UTC),
        request=request,
        response=response,
        control_probe_id=None,
    )


def test_web_cache_deception_detects_private_fields_on_static_path() -> None:
    probe = _probe(
        request={"method": "GET", "url": "https://api.example.test/user/profile/test.css"},
        response={"status": 200, "body": '{"email":"test@example.com","user_id":"123"}'},
    )

    artifact = WebCacheDeceptionStrategy().validate(probe, None)

    assert artifact is not None
    assert artifact.confidence_score == 0.90
    assert "email" in artifact.state_diff["detected_field_names"]
    assert "test@example.com" not in str(artifact.state_diff)


def test_web_cache_deception_rejects_non_static_extension_path() -> None:
    probe = _probe(
        request={"method": "GET", "url": "https://api.example.test/user/profile"},
        response={"status": 200, "body": '{"email":"test@example.com"}'},
    )

    artifact = WebCacheDeceptionStrategy().validate(probe, None)

    assert artifact is None


def test_cache_poisoning_detects_host_reflection_in_response_header() -> None:
    probe = _probe(
        request={
            "method": "GET",
            "url": "https://api.example.test/",
            "headers": {"X-Forwarded-Host": "evil-probe.invalid"},
        },
        response={"status": 302, "headers": {"location": "https://evil-probe.invalid/redirect"}, "body": ""},
    )

    artifact = CachePoisoningStrategy().validate(probe, None)

    assert artifact is not None
    assert artifact.confidence_score == 0.87
    assert artifact.state_diff["reflection_location"].startswith("header:")


def test_cache_poisoning_no_reflection_returns_none() -> None:
    probe = _probe(
        request={
            "method": "GET",
            "url": "https://api.example.test/",
            "headers": {"X-Forwarded-Host": "evil-probe.invalid"},
        },
        response={"status": 302, "headers": {"location": "https://api.example.test/redirect"}, "body": ""},
    )

    artifact = CachePoisoningStrategy().validate(probe, None)

    assert artifact is None


def test_http_smuggling_requires_allow_smuggling_probes_flag() -> None:
    probe = _probe(request={"probe_type": "cl_te_probe"}, response={"status": 200})

    artifact = HttpSmugglingStrategy().validate(probe, None)

    assert artifact is None


def test_http_smuggling_detects_timeout_differential() -> None:
    attack_probe = _probe(
        request={
            "probe_type": "cl_te_probe",
            "allow_smuggling_probes_required": True,
            "url": "https://api.example.test/",
        },
        response={"status": 200, "latency_ms": 6000},
    )
    control_probe = _probe(
        request={
            "probe_type": "cl_te_probe",
            "allow_smuggling_probes_required": True,
            "url": "https://api.example.test/",
        },
        response={"status": 200, "latency_ms": 100},
    )

    artifact = HttpSmugglingStrategy().validate(attack_probe, control_probe)

    assert artifact is not None
    assert artifact.confidence_score == 0.88
    assert artifact.state_diff["timeout_differential"] is True


def test_http_method_override_detects_delete_execution() -> None:
    probe = _probe(
        request={
            "probe_type": "method_override",
            "override_value": "DELETE",
            "url": "https://api.example.test/resource/1",
        },
        response={"status": 204},
    )

    artifact = HttpMethodOverrideStrategy().validate(probe, None)

    assert artifact is not None
    assert artifact.confidence_score == 0.90
    assert artifact.state_diff["override_verb"] == "DELETE"


def test_http_parameter_pollution_detects_response_difference() -> None:
    attack_probe = _probe(
        request={"probe_type": "hpp", "param_name": "id", "url": "https://api.example.test/"},
        response={"status": 200, "body": "id=2"},
    )
    control_probe = _probe(
        request={"probe_type": "hpp", "url": "https://api.example.test/"},
        response={"status": 200, "body": "id=1"},
    )

    artifact = HttpParameterPollutionStrategy().validate(attack_probe, control_probe)

    assert artifact is not None
    assert artifact.confidence_score == 0.80
    assert artifact.state_diff["body_diff"] is True
