from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

from execution_plane.validator.strategies.oauth import (
    OauthErrorDisclosureStrategy,
    OauthRedirectStrategy,
    OauthStateCsrfStrategy,
    OauthTokenReuseStrategy,
)
from storage.db.models import RawProbe


def _probe(
    *,
    request: dict[str, object] | None = None,
    response: dict[str, object] | None = None,
    attack_task_id=None,
) -> RawProbe:
    task_id = attack_task_id or uuid4()
    return RawProbe(
        id=uuid4(),
        attack_task_id=task_id,
        worker_id="worker-test",
        timestamp=datetime.now(UTC),
        request=request or {},
        response=response or {},
        control_probe_id=None,
    )


def test_oauth_redirect_absolute_confidence_for_manipulated_302() -> None:
    strategy = OauthRedirectStrategy()
    probe = _probe(
        request={"manipulated_redirect_host": "evil.example.com"},
        response={"status": 302, "headers": {"Location": "https://evil.example.com/cb?code=abc"}},
    )

    artifact = strategy.validate(probe, None)

    assert artifact is not None
    assert artifact.proof_type == "absolute"
    assert artifact.confidence_score == 0.95


def test_oauth_redirect_partial_match_uses_088_confidence() -> None:
    strategy = OauthRedirectStrategy()
    probe = _probe(
        request={"manipulated_redirect_host": "example.com.evil.test", "partial_match_probe": True},
        response={"status": 302, "headers": {"Location": "https://example.com.evil.test/cb"}},
    )

    artifact = strategy.validate(probe, None)

    assert artifact is not None
    assert artifact.confidence_score == 0.88


def test_oauth_state_csrf_accepts_authorization_without_state() -> None:
    strategy = OauthStateCsrfStrategy()
    probe = _probe(
        request={"state_omitted": True},
        response={"status": 302, "headers": {"Location": "https://app.example.test/callback?code=xyz"}},
    )

    artifact = strategy.validate(probe, None)

    assert artifact is not None
    assert artifact.proof_type == "absolute"
    assert artifact.confidence_score == 0.9


def test_oauth_token_reuse_differential_confidence_after_logout() -> None:
    strategy = OauthTokenReuseStrategy()
    probe = _probe(
        request={"after_logout": True},
        response={"status": 200, "body": "still authorized"},
    )

    artifact = strategy.validate(probe, None)

    assert artifact is not None
    assert artifact.proof_type == "differential"
    assert artifact.confidence_score == 0.92


def test_oauth_token_reuse_rejected_on_401_or_403_after_logout() -> None:
    strategy = OauthTokenReuseStrategy()

    rejected_401 = strategy.validate(
        _probe(request={"after_logout": True}, response={"status": 401}),
        None,
    )
    rejected_403 = strategy.validate(
        _probe(request={"after_logout": True}, response={"status": 403}),
        None,
    )

    assert rejected_401 is None
    assert rejected_403 is None


def test_oauth_error_disclosure_reports_allowed_redirect_and_client_id_leak() -> None:
    strategy = OauthErrorDisclosureStrategy()
    probe = _probe(
        response={
            "status": 400,
            "body": "invalid_request: allowed_redirect_uris mismatch for client_id abc at /internal/oauth/authorize",
        }
    )

    artifact = strategy.validate(probe, None)

    assert artifact is not None
    assert artifact.proof_type == "absolute"
    assert artifact.confidence_score == 0.85
    assert "allowed_redirect_uris" in artifact.evidence_notes
