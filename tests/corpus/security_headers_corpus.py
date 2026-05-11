from __future__ import annotations

from dataclasses import dataclass, field
from uuid import UUID, uuid4

from execution_plane.validator.strategies.security_headers import (
    CorsAnalysisStrategy,
    SecurityHeadersStrategy,
    TlsAnalysisStrategy,
)


@dataclass
class Probe:
    response: dict[str, object]
    request: dict[str, object] = field(default_factory=dict)
    attack_task_id: UUID = field(default_factory=uuid4)
    id: UUID = field(default_factory=uuid4)


def test_corpus_missing_headers() -> None:
    probe = Probe(response={"headers": {}})

    artifact = SecurityHeadersStrategy().validate(probe, None)

    assert artifact is not None


def test_corpus_cors_wildcard_credentials() -> None:
    probe = Probe(
        response={
            "headers": {
                "access-control-allow-origin": "*",
                "access-control-allow-credentials": "true",
            },
        },
    )

    artifact = CorsAnalysisStrategy().validate(probe, None)

    assert artifact is not None
    assert artifact.confidence_score >= 0.95


def test_corpus_tls_weak() -> None:
    probe = Probe(response={"tls_version": "TLSv1"})

    artifact = TlsAnalysisStrategy().validate(probe, None)

    assert artifact is not None


def test_corpus_clean_response() -> None:
    probe = Probe(
        response={
            "headers": {
                "strict-transport-security": "max-age=31536000",
                "content-security-policy": "default-src self",
                "x-frame-options": "DENY",
                "x-content-type-options": "nosniff",
                "permissions-policy": "geolocation=()",
            },
            "tls_version": "TLSv1.3",
        },
    )

    security_artifact = SecurityHeadersStrategy().validate(probe, None)
    cors_artifact = CorsAnalysisStrategy().validate(probe, None)
    tls_artifact = TlsAnalysisStrategy().validate(probe, None)

    assert security_artifact is None
    assert cors_artifact is None
    assert tls_artifact is None
