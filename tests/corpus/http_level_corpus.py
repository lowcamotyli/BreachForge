from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

from execution_plane.validator.strategies.cache_poisoning import CachePoisoningStrategy, WebCacheDeceptionStrategy
from execution_plane.validator.strategies.http_smuggling import HttpMethodOverrideStrategy, HttpParameterPollutionStrategy
from storage.db.models import RawProbe


def _probe(*, request: dict[str, object], response: dict[str, object]) -> RawProbe:
    return RawProbe(
        id=uuid4(),
        attack_task_id=uuid4(),
        worker_id="corpus-http-level",
        timestamp=datetime.now(UTC),
        request=request,
        response=response,
        control_probe_id=None,
    )


def test_web_cache_deception_corpus_fixture() -> None:
    probe = _probe(
        request={"method": "GET", "url": "https://api.example.test/api/user/profile.css"},
        response={"status": 200, "body": '{"email":"user@corp.test","account":"premium","user_id":"42"}'},
    )

    artifact = WebCacheDeceptionStrategy().validate(probe, None)

    assert artifact is not None
    assert artifact.confidence_score == 0.90


def test_cache_poisoning_corpus_fixture() -> None:
    probe = _probe(
        request={
            "method": "GET",
            "url": "https://api.example.test/",
            "headers": {"X-Forwarded-Host": "attacker.invalid"},
        },
        response={"status": 200, "body": "cached page from attacker.invalid"},
    )

    artifact = CachePoisoningStrategy().validate(probe, None)

    assert artifact is not None
    assert artifact.confidence_score == 0.87


def test_http_method_override_corpus_fixture() -> None:
    probe = _probe(
        request={
            "method": "POST",
            "url": "https://api.example.test/api/items/99",
            "probe_type": "method_override",
            "override_value": "DELETE",
        },
        response={"status": 204},
    )

    artifact = HttpMethodOverrideStrategy().validate(probe, None)

    assert artifact is not None
    assert artifact.confidence_score == 0.90


def test_http_parameter_pollution_corpus_fixture() -> None:
    attack_probe = _probe(
        request={
            "method": "POST",
            "url": "https://api.example.test/api/search",
            "probe_type": "hpp",
            "param_name": "id",
        },
        response={"status": 200, "body": "using id=2"},
    )
    control_probe = _probe(
        request={"method": "POST", "url": "https://api.example.test/api/search", "probe_type": "hpp"},
        response={"status": 200, "body": "using id=1"},
    )

    artifact = HttpParameterPollutionStrategy().validate(attack_probe, control_probe)

    assert artifact is not None
    assert artifact.confidence_score == 0.80
