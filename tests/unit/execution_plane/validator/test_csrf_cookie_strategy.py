from __future__ import annotations

from dataclasses import dataclass, field
from uuid import UUID, uuid4

from execution_plane.validator.strategies.cookie_analysis import CookieAnalysisStrategy
from execution_plane.validator.strategies.csrf import CsrfStrategy


@dataclass
class Probe:
    response: dict[str, object]
    request: dict[str, object] = field(default_factory=dict)
    attack_task_id: UUID = field(default_factory=uuid4)
    id: UUID = field(default_factory=uuid4)


def _csrf_probe(*, status_code: int, probe_type: str = "csrf_no_token") -> Probe:
    return Probe(
        request={
            "hypothesis": {"probe_type": probe_type},
            "method": "POST",
            "path": "/api/users",
        },
        response={"status_code": status_code},
    )


def _cookie_probe(set_cookie: str | None) -> Probe:
    headers = {} if set_cookie is None else {"set-cookie": set_cookie}
    return Probe(response={"headers": headers})


def test_csrf_no_token_2xx_returns_finding() -> None:
    artifact = CsrfStrategy().validate(_csrf_probe(status_code=200), None)

    assert artifact is not None
    assert artifact.confidence_score == 0.90
    assert artifact.proof_type == "csrf_missing_protection"
    assert "probe_type=csrf_no_token" in artifact.evidence_notes
    assert "method=POST" in artifact.evidence_notes
    assert "status=200" in artifact.evidence_notes


def test_csrf_no_token_302_returns_none() -> None:
    artifact = CsrfStrategy().validate(_csrf_probe(status_code=302), None)

    assert artifact is None


def test_csrf_no_token_403_returns_none() -> None:
    artifact = CsrfStrategy().validate(_csrf_probe(status_code=403), None)

    assert artifact is None


def test_csrf_double_submit_mismatch_2xx() -> None:
    artifact = CsrfStrategy().validate(
        _csrf_probe(status_code=200, probe_type="csrf_double_submit"),
        None,
    )

    assert artifact is not None
    assert artifact.confidence_score == 0.88
    assert "probe_type=csrf_double_submit" in artifact.evidence_notes


def test_cookie_session_missing_httponly_high() -> None:
    artifact = CookieAnalysisStrategy().validate(
        _cookie_probe("sessionid=abc; Secure; SameSite=Lax"),
        None,
    )

    assert artifact is not None
    assert artifact.confidence_score >= 0.90
    assert "issue=missing_httponly" in artifact.evidence_notes


def test_cookie_missing_secure_high() -> None:
    artifact = CookieAnalysisStrategy().validate(
        _cookie_probe("data=xyz; HttpOnly; SameSite=Lax"),
        None,
    )

    assert artifact is not None
    assert artifact.confidence_score >= 0.90
    assert "issue=missing_secure" in artifact.evidence_notes


def test_cookie_samesite_none_without_secure_high() -> None:
    artifact = CookieAnalysisStrategy().validate(
        _cookie_probe("token=abc; SameSite=None; HttpOnly"),
        None,
    )

    assert artifact is not None
    assert artifact.confidence_score >= 0.90


def test_cookie_samesite_missing_medium() -> None:
    artifact = CookieAnalysisStrategy().validate(
        _cookie_probe("token=abc; HttpOnly; Secure"),
        None,
    )

    assert artifact is not None
    assert 0.65 <= artifact.confidence_score <= 0.85
    assert "issue=missing_samesite" in artifact.evidence_notes


def test_cookie_analysis_no_set_cookie_returns_none() -> None:
    artifact = CookieAnalysisStrategy().validate(_cookie_probe(None), None)

    assert artifact is None


def test_cookie_analysis_unauth_path() -> None:
    artifact = CookieAnalysisStrategy().validate(
        _cookie_probe("data=xyz; HttpOnly; SameSite=Lax"),
        None,
    )

    assert artifact is not None
    assert artifact.confidence_score >= 0.90


def test_cookie_all_flags_present_no_finding() -> None:
    # __Host- prefix satisfies the session-cookie naming check too
    artifact = CookieAnalysisStrategy().validate(
        _cookie_probe("__Host-token=abc; HttpOnly; Secure; SameSite=Strict"),
        None,
    )

    assert artifact is None
