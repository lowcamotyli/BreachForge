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


def _headers_probe(headers: dict[str, str]) -> Probe:
    return Probe(response={"headers": headers})


def _tls_probe(tls_version: str) -> Probe:
    return Probe(response={"tls_version": tls_version})


def test_hsts_missing() -> None:
    artifact = SecurityHeadersStrategy().validate(_headers_probe({}), None)

    assert artifact is not None
    assert artifact.confidence_score >= 0.90


def test_csp_missing() -> None:
    artifact = SecurityHeadersStrategy().validate(
        _headers_probe({"strict-transport-security": "max-age=31536000"}),
        None,
    )

    assert artifact is not None


def test_csp_unsafe_inline() -> None:
    artifact = SecurityHeadersStrategy().validate(
        _headers_probe(
            {
                "strict-transport-security": "max-age=31536000",
                "content-security-policy": "default-src self; script-src unsafe-inline",
            },
        ),
        None,
    )

    assert artifact is not None


def test_x_frame_options_missing() -> None:
    artifact = SecurityHeadersStrategy().validate(
        _headers_probe(
            {
                "strict-transport-security": "max-age=31536000",
                "content-security-policy": "default-src self",
            },
        ),
        None,
    )

    assert artifact is not None


def test_all_security_headers_present() -> None:
    artifact = SecurityHeadersStrategy().validate(
        _headers_probe(
            {
                "strict-transport-security": "max-age=31536000",
                "content-security-policy": "default-src self",
                "x-frame-options": "DENY",
                "x-content-type-options": "nosniff",
                "permissions-policy": "geolocation=()",
            },
        ),
        None,
    )

    assert artifact is None


def test_cors_wildcard_with_credentials() -> None:
    artifact = CorsAnalysisStrategy().validate(
        _headers_probe(
            {
                "access-control-allow-origin": "*",
                "access-control-allow-credentials": "true",
            },
        ),
        None,
    )

    assert artifact is not None
    assert artifact.confidence_score >= 0.95


def test_cors_null_origin() -> None:
    artifact = CorsAnalysisStrategy().validate(
        _headers_probe({"access-control-allow-origin": "null"}),
        None,
    )

    assert artifact is not None
    assert artifact.confidence_score >= 0.90


def test_cors_no_issue() -> None:
    artifact = CorsAnalysisStrategy().validate(_headers_probe({}), None)

    assert artifact is None


def test_tls_10_accepted() -> None:
    artifact = TlsAnalysisStrategy().validate(_tls_probe("TLSv1"), None)

    assert artifact is not None
    assert artifact.confidence_score >= 0.85


def test_tls_11_accepted() -> None:
    artifact = TlsAnalysisStrategy().validate(_tls_probe("TLSv1.1"), None)

    assert artifact is not None


def test_tls_modern() -> None:
    artifact = TlsAnalysisStrategy().validate(_tls_probe("TLSv1.3"), None)

    assert artifact is None
