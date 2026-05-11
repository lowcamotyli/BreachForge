from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID, uuid4

from execution_plane.validator.strategies.misconfiguration import MisconfigurationStrategy
from execution_plane.validator.strategies.rate_limit_abuse import RateLimitAbuseStrategy
from execution_plane.validator.strategies.sensitive_exposure import SensitiveExposureStrategy
from storage.db.models import ProofArtifact, RawProbe


@dataclass(frozen=True)
class PublicEndpoint:
    method: str
    url: str
    attack_class: str
    probe_type: str
    response: dict[str, object]


PUBLIC_ENDPOINTS: tuple[PublicEndpoint, ...] = (
    PublicEndpoint(
        method="GET",
        url="https://public.example.test/api/config",
        attack_class="sensitive_exposure",
        probe_type="unauth_baseline",
        response={
            "status": 200,
            "content_type": "application/json",
            "body": {"client_secret": "public-leaked-secret-value", "support_email": "ops@example.test"},
        },
    ),
    PublicEndpoint(
        method="GET",
        url="https://public.example.test/api/profile",
        attack_class="misconfiguration",
        probe_type="cors_wildcard",
        response={"status": 200, "headers": {"Access-Control-Allow-Origin": "*"}},
    ),
    PublicEndpoint(
        method="POST",
        url="https://public.example.test/api/login",
        attack_class="rate_limit_abuse",
        probe_type="burst",
        response={"status": 200, "statuses": [200, 200, 200, 200, 200]},
    ),
)


def _probe(endpoint: PublicEndpoint, *, attack_task_id: UUID | None = None) -> RawProbe:
    return RawProbe(
        id=uuid4(),
        attack_task_id=attack_task_id or uuid4(),
        worker_id="unauth-corpus",
        timestamp=datetime.now(UTC),
        request={
            "method": endpoint.method,
            "url": endpoint.url,
            "path": endpoint.url,
            "probe_type": endpoint.probe_type,
        },
        response=endpoint.response,
        control_probe_id=None,
    )


def _validate(endpoint: PublicEndpoint) -> ProofArtifact | None:
    strategies = {
        "sensitive_exposure": SensitiveExposureStrategy(),
        "misconfiguration": MisconfigurationStrategy(),
        "rate_limit_abuse": RateLimitAbuseStrategy(),
    }
    return strategies[endpoint.attack_class].validate(attack_probe=_probe(endpoint), control_probe=None)


def test_unauth_public_endpoint_corpus_produces_at_least_three_high_confidence_findings() -> None:
    artifacts = [artifact for endpoint in PUBLIC_ENDPOINTS if (artifact := _validate(endpoint)) is not None]

    assert len(artifacts) >= 3
    assert all(artifact.confidence_score >= 0.85 for artifact in artifacts)


def test_unauth_corpus_covers_expected_attack_classes() -> None:
    confirmed_classes = {
        endpoint.attack_class
        for endpoint in PUBLIC_ENDPOINTS
        if (artifact := _validate(endpoint)) is not None and artifact.confidence_score >= 0.85
    }

    assert confirmed_classes == {"sensitive_exposure", "misconfiguration", "rate_limit_abuse"}
