from __future__ import annotations

from execution_plane.workers.dispatcher import (
    DEFAULT_AUTONOMOUS_ATTACK_ROUNDS,
    _autonomous_attack_rounds,
    _extract_replayable_secret,
    _redacted_follow_up_payload,
    _sensitive_exposure_follow_up_payloads,
)


def test_autonomous_attack_rounds_defaults_and_clamps() -> None:
    assert _autonomous_attack_rounds(None) == DEFAULT_AUTONOMOUS_ATTACK_ROUNDS
    assert _autonomous_attack_rounds("not-an-int") == DEFAULT_AUTONOMOUS_ATTACK_ROUNDS
    assert _autonomous_attack_rounds("-2") == 0
    assert _autonomous_attack_rounds("99") == 5


def test_sensitive_exposure_follow_ups_expand_by_evidence_type() -> None:
    follow_ups = _sensitive_exposure_follow_up_payloads(
        finding_id="finding-1",
        evidence_notes="matches=credential, token, pii; request_has_auth=False",
    )

    target_parameters = [target_parameter for target_parameter, _payload in follow_ups]
    probe_types = [payload["probe_type"] for _target_parameter, payload in follow_ups]

    assert target_parameters == [
        "impact.unauthenticated_repeat.finding-1",
        "impact.secret_classification.finding-1",
        "impact.data_abuse.finding-1",
    ]
    assert probe_types == [
        "impact_unauthenticated_repeat",
        "impact_secret_classification",
        "impact_data_abuse",
    ]
    assert all(payload["safe_mode"] is True for _target_parameter, payload in follow_ups)


def test_extract_replayable_secret_prefers_token_material() -> None:
    secret = _extract_replayable_secret(
        {
            "response": {
                "body": '{"access_token":"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature"}',
            }
        }
    )

    assert secret == ("bearer", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature")


def test_redacted_follow_up_payload_does_not_persist_secret_value() -> None:
    payload = {
        "probe_type": "impact_secret_replay",
        "secret_kind": "bearer",
        "secret_value": "live-token",
    }

    assert _redacted_follow_up_payload(payload)["secret_value"] == "[REDACTED]"
