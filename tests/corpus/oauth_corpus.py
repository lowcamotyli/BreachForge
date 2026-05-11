from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

from execution_plane.validator.strategies.oauth import OauthRedirectStrategy, OauthStateCsrfStrategy
from storage.db.models import RawProbe


class OAuthCorpus:
    def vulnerable_redirect_response(self) -> dict[str, object]:
        return {
            "status": 302,
            "headers": {
                "Location": "https://example.com.evil.test/callback?code=mock-code",
            },
        }

    def missing_state_accepted_response(self) -> dict[str, object]:
        return {
            "status": 302,
            "headers": {
                "Location": "https://app.example.test/auth/callback?code=state-missing-code",
            },
        }


def _probe(*, request: dict[str, object], response: dict[str, object], attack_task_id) -> RawProbe:
    return RawProbe(
        id=uuid4(),
        attack_task_id=attack_task_id,
        worker_id="corpus-oauth",
        timestamp=datetime.now(UTC),
        request=request,
        response=response,
    )


def test_mock_oauth_server_with_partial_redirect_match_confirms_redirect_manipulation() -> None:
    corpus = OAuthCorpus()
    task_id = uuid4()
    probe = _probe(
        attack_task_id=task_id,
        request={
            "method": "GET",
            "url": "https://app.example.test/oauth/authorize",
            "original_redirect_uri": "https://app.example.test/auth/callback",
            "manipulated_redirect_uri": "https://example.com.evil.test/callback",
            "manipulated_redirect_host": "example.com.evil.test",
            "partial_match_probe": True,
            "exchange_authorization_code": False,
        },
        response=corpus.vulnerable_redirect_response(),
    )

    artifact = OauthRedirectStrategy().validate(attack_probe=probe, control_probe=None)

    assert artifact is not None
    assert artifact.confidence_score == 0.88
    assert "original_redirect_uri=https://app.example.test/auth/callback" in artifact.evidence_notes
    assert "manipulated_redirect_uri=https://example.com.evil.test/callback" in artifact.evidence_notes
    assert "status=302" in artifact.evidence_notes


def test_mock_oauth_server_without_state_requirement_confirms_state_csrf() -> None:
    corpus = OAuthCorpus()
    task_id = uuid4()
    probe = _probe(
        attack_task_id=task_id,
        request={
            "method": "GET",
            "url": "https://app.example.test/oauth/authorize",
            "state_omitted": True,
        },
        response=corpus.missing_state_accepted_response(),
    )

    artifact = OauthStateCsrfStrategy().validate(attack_probe=probe, control_probe=None)

    assert artifact is not None
    assert artifact.confidence_score == 0.9
    assert artifact.proof_type == "absolute"
