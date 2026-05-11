from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

from execution_plane.validator.strategies.cookie_analysis import CookieAnalysisStrategy
from execution_plane.validator.strategies.csrf import CsrfStrategy
from storage.db.models import RawProbe


def _probe(*, request: dict[str, object], response: dict[str, object]) -> RawProbe:
    return RawProbe(
        id=uuid4(),
        attack_task_id=uuid4(),
        worker_id="corpus-csrf-cookie",
        timestamp=datetime.now(UTC),
        request=request,
        response=response,
        control_probe_id=None,
    )


def test_csrf_unprotected_post() -> None:
    attack_probe = _probe(
        request={
            "method": "POST",
            "path": "/api/users/update",
            "headers": {},
            "probe_type": "csrf_no_token",
        },
        response={"status_code": 200, "body": {"ok": True}},
    )
    control_probe = None

    artifact = CsrfStrategy().validate(attack_probe, control_probe)

    assert artifact is not None
    assert artifact.confidence_score >= 0.85
    assert artifact.confidence_score == 0.90


def test_csrf_protected_403() -> None:
    attack_probe = _probe(
        request={
            "method": "POST",
            "path": "/api/users/update",
            "headers": {},
            "probe_type": "csrf_no_token",
        },
        response={"status_code": 403, "body": "Forbidden"},
    )
    control_probe = None

    artifact = CsrfStrategy().validate(attack_probe, control_probe)

    assert artifact is None


def test_csrf_protected_redirect() -> None:
    attack_probe = _probe(
        request={
            "method": "POST",
            "path": "/api/login",
            "headers": {},
            "probe_type": "csrf_no_token",
        },
        response={"status_code": 302, "headers": {"Location": "/login"}},
    )
    control_probe = None

    artifact = CsrfStrategy().validate(attack_probe, control_probe)

    assert artifact is None


def test_cookie_session_all_issues() -> None:
    attack_probe = _probe(
        request={"method": "GET", "path": "/login"},
        response={"status_code": 200, "headers": {"Set-Cookie": "session=abc"}},
    )
    control_probe = None

    artifact = CookieAnalysisStrategy().validate(attack_probe, control_probe)

    assert artifact is not None
    assert artifact.confidence_score >= 0.85
    assert "issue=missing_httponly" in artifact.evidence_notes
    assert "is_session_cookie=True" in artifact.evidence_notes


def test_cookie_token_missing_httponly() -> None:
    attack_probe = _probe(
        request={"method": "GET", "path": "/login"},
        response={"status_code": 200, "headers": {"Set-Cookie": "token=xyz; Secure; SameSite=Lax"}},
    )
    control_probe = None

    artifact = CookieAnalysisStrategy().validate(attack_probe, control_probe)

    assert artifact is not None
    assert artifact.confidence_score >= 0.85
    assert "issue=missing_httponly" in artifact.evidence_notes
    assert "is_session_cookie=True" in artifact.evidence_notes


def test_cookie_all_flags_secure() -> None:
    attack_probe = _probe(
        request={"method": "GET", "path": "/login"},
        response={
            "status_code": 200,
            "headers": {"Set-Cookie": "token=abc; HttpOnly; Secure; SameSite=Strict"},
        },
    )
    control_probe = None

    artifact = CookieAnalysisStrategy().validate(attack_probe, control_probe)

    assert artifact is None


def test_cookie_samesite_none_no_secure() -> None:
    attack_probe = _probe(
        request={"method": "GET", "path": "/login"},
        response={
            "status_code": 200,
            "headers": {"Set-Cookie": "data=xyz; SameSite=None; HttpOnly"},
        },
    )
    control_probe = None

    artifact = CookieAnalysisStrategy().validate(attack_probe, control_probe)

    assert artifact is not None
    assert artifact.confidence_score >= 0.85
    assert "issue=missing_secure" in artifact.evidence_notes
