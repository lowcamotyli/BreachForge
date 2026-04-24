from __future__ import annotations

from control_plane.reporting import ReportingService


def test_redact_report_redacts_sensitive_keys() -> None:
    service = ReportingService(db=None)
    report = {
        "findings": [
            {
                "request": {
                    "headers": {
                        "Authorization": "Bearer top-secret",
                        "Cookie": "sid=session-secret",
                    },
                    "body": {"password": "my-password", "refresh_token": "refresh-secret", "ok": "value"},
                }
            }
        ]
    }

    redacted = service._redact_report(report)

    request = redacted["findings"][0]["request"]
    assert request["headers"]["Authorization"] == "[REDACTED]"
    assert request["headers"]["Cookie"] == "[REDACTED]"
    assert request["body"]["password"] == "[REDACTED]"
    assert request["body"]["refresh_token"] == "[REDACTED]"
    assert request["body"]["ok"] == "value"


def test_redact_report_redacts_sensitive_value_patterns() -> None:
    service = ReportingService(db=None)
    report = {
        "findings": [
            {
                "response": {
                    "body": "access_token=abc123",
                    "json": {
                        "message": "secret: hidden",
                        "nested": ["safe-value", "Bearer something-secret"],
                    },
                }
            }
        ]
    }

    redacted = service._redact_report(report)
    response = redacted["findings"][0]["response"]

    assert response["body"] == "[REDACTED]"
    assert response["json"]["message"] == "[REDACTED]"
    assert response["json"]["nested"][0] == "safe-value"
    assert response["json"]["nested"][1] == "[REDACTED]"


def test_redact_evidence_redacts_request_headers() -> None:
    service = ReportingService(db=None)
    evidence = {
        "request_headers": {
            "Authorization": "Bearer top-secret",
            "Cookie": "sid=session-secret",
            "X-Api-Key": "api-key-secret",
            "X-Request-Id": "safe-id",
        },
        "headers": {
            "authorization": "Bearer nested-secret",
            "accept": "application/json",
        },
    }

    redacted = service._redact_evidence(evidence)
    assert redacted["request_headers"]["Authorization"] == "[REDACTED]"
    assert redacted["request_headers"]["Cookie"] == "[REDACTED]"
    assert redacted["request_headers"]["X-Api-Key"] == "[REDACTED]"
    assert redacted["request_headers"]["X-Request-Id"] == "safe-id"
    assert redacted["headers"]["authorization"] == "[REDACTED]"
    assert redacted["headers"]["accept"] == "application/json"


def test_build_attack_path_parses_request_chain() -> None:
    service = ReportingService(db=None)
    artifacts = [
        {
            "evidence_notes": "request_chain=GET /api/start -> POST /api/approve -> POST /api/complete",
        }
    ]

    attack_path = service._build_attack_path(
        attack_class="workflow_abuse",
        endpoint_method="post",
        endpoint_url="/api/complete",
        artifacts=artifacts,
    )

    assert len(attack_path) == 3
    assert attack_path[0]["step"] == 1
    assert attack_path[0]["method"] == "GET"
    assert attack_path[0]["url"] == "/api/start"
    assert attack_path[2]["step"] == 3
    assert attack_path[2]["method"] == "POST"
    assert attack_path[2]["url"] == "/api/complete"


def test_build_attack_path_falls_back_to_affected_endpoint() -> None:
    service = ReportingService(db=None)
    attack_path = service._build_attack_path(
        attack_class="bola",
        endpoint_method="get",
        endpoint_url="/api/users/{id}",
        artifacts=[{"evidence_notes": "status=200"}],
    )

    assert attack_path == [
        {
            "step": 1,
            "method": "GET",
            "url": "/api/users/{id}",
            "description": "Primary affected endpoint for bola",
        }
    ]


def test_build_kill_chain_contains_four_phases() -> None:
    service = ReportingService(db=None)
    kill_chain = service._build_kill_chain(
        attack_class="bola",
        endpoint_method="get",
        endpoint_url="/api/users/{id}",
        finding_description="Object data from another tenant was returned.",
        artifacts=[
            {
                "artifact_id": "artifact-1",
                "identity_role": "user",
                "summary": "Changed object id and received foreign record.",
                "evidence_notes": "status=200",
                "confidence_score": 0.93,
            }
        ],
    )

    assert [step["phase"] for step in kill_chain] == ["entry", "pivot", "exploit", "impact"]
    assert kill_chain[0]["endpoint"] == "/api/users/{id}"
    assert kill_chain[2]["evidence_ref"] == "artifact-1"


def test_render_markdown_includes_kill_chain_and_score_explanation() -> None:
    service = ReportingService(db=None)
    report = {
        "scan_id": "scan-123",
        "generated_at": "2026-04-20T00:00:00+00:00",
        "findings": [
            {
                "title": "BOLA on GET /api/users/{id}",
                "severity": "high",
                "attack_class": "bola",
                "affected_endpoint": "/api/users/{id}",
                "description": "desc",
                "repro_steps": "steps",
                "fix_guidance": "fix",
                "attack_path": [],
                "kill_chain": [
                    {
                        "phase": "entry",
                        "description": "Recon discovered endpoint.",
                        "endpoint": "/api/users/{id}",
                        "evidence_ref": "artifact-1",
                    }
                ],
                "score_explanation": "conf=0.93 x impact=0.80 x reach=1.00 x repeat=1.00 x blast=0.60 = 0.4464",
                "proof_artifacts": [],
            }
        ],
    }

    markdown = service.render_markdown(report)

    assert "- Score Explanation: conf=0.93 x impact=0.80 x reach=1.00 x repeat=1.00 x blast=0.60 = 0.4464" in markdown
    assert "### Kill Chain" in markdown
    assert "1. [entry] Recon discovered endpoint." in markdown
