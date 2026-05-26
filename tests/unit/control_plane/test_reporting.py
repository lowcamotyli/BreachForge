from __future__ import annotations

import json
from uuid import uuid4

import pytest
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


def test_redact_identity_info_keeps_only_safe_identity_fields() -> None:
    service = ReportingService(db=None)
    identity_info = {
        "name": "current_user",
        "role_hint": "user",
        "tenant_hint": "tenant-a",
        "identity_labels": ["current_user", "alternate_user"],
        "credentials": {"username": "alice", "password": "secret"},
        "cookies": [{"name": "sid", "value": "secret"}],
        "bearer_token": "secret-token",
        "password": "secret",
        "token": "secret-token",
        "secret": "secret",
        "auth_headers": {"Authorization": "Bearer secret"},
        "extra": "ignored",
    }

    redacted = service._redact_identity_info(identity_info)

    assert redacted == {
        "name": "current_user",
        "role_hint": "user",
        "tenant_hint": "tenant-a",
        "identity_labels": ["current_user", "alternate_user"],
    }


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


def test_render_markdown_includes_leak_source_section_when_present() -> None:
    service = ReportingService(db=None)
    report = {
        "scan_id": "scan-123",
        "generated_at": "2026-04-20T00:00:00+00:00",
        "findings": [
            {
                "title": "Sensitive exposure",
                "severity": "high",
                "attack_class": "sensitive_exposure",
                "affected_endpoint": "/api/debug",
                "description": "desc",
                "repro_steps": "steps",
                "fix_guidance": "fix",
                "attack_path": [],
                "kill_chain": [],
                "score_explanation": "conf=0.90",
                "proof_artifacts": [],
                "metadata": {"leak_source": {"type": "debug_endpoint", "confidence": 1.0}},
            }
        ],
    }

    markdown = service.render_markdown(report)
    normalized = markdown.replace("**", "")

    assert "Leak Source: debug_endpoint" in normalized
    assert "Disable or restrict" in markdown


def test_render_markdown_includes_secret_properties_when_metadata_present() -> None:
    service = ReportingService(db=None)
    report = {
        "scan_id": "scan-123",
        "generated_at": "2026-04-20T00:00:00+00:00",
        "findings": [
            {
                "title": "Sensitive exposure",
                "severity": "high",
                "attack_class": "sensitive_exposure",
                "affected_endpoint": "/api/debug",
                "description": "desc",
                "repro_steps": "steps",
                "fix_guidance": "fix",
                "evidence_notes": "secret_type=JWT; secret_fingerprint=abc123def4567890; ttl_bucket=long; raw_secret=eyJhbGciOiJIUzI1NiJ9.payload.signature",
                "attack_path": [],
                "kill_chain": [],
                "score_explanation": "conf=0.90",
                "proof_artifacts": [],
            }
        ],
    }

    markdown = service.render_markdown(report)

    assert "### Secret Properties" in markdown
    assert "- Type: JWT" in markdown
    assert "- Fingerprint: `abc123def4567890` (dedup hash, not the secret value)" in markdown
    assert "- TTL Bucket: long" in markdown


def test_render_markdown_secret_properties_never_include_raw_secret_value() -> None:
    service = ReportingService(db=None)
    raw_secret = "my-super-raw-secret-value-123"
    report = {
        "scan_id": "scan-123",
        "generated_at": "2026-04-20T00:00:00+00:00",
        "findings": [
            {
                "title": "Sensitive exposure",
                "severity": "high",
                "attack_class": "sensitive_exposure",
                "affected_endpoint": "/api/debug",
                "description": "desc",
                "repro_steps": "steps",
                "fix_guidance": "fix",
                "evidence_notes": f"secret_type=API_KEY; secret_fingerprint=ff00112233445566; ttl_bucket=short; raw_secret={raw_secret}",
                "attack_path": [],
                "kill_chain": [],
                "score_explanation": "conf=0.90",
                "proof_artifacts": [],
            }
        ],
    }

    markdown = service.render_markdown(report)

    assert raw_secret not in markdown
    assert "### Secret Properties" in markdown
    assert "`ff00112233445566`" in markdown


def test_render_markdown_does_not_include_secret_properties_without_metadata() -> None:
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
                "evidence_notes": "request_chain=GET /api/users/{id}",
                "attack_path": [],
                "kill_chain": [],
                "score_explanation": "conf=0.90",
                "proof_artifacts": [],
            }
        ],
    }

    markdown = service.render_markdown(report)

    assert "### Secret Properties" not in markdown


def test_render_markdown_includes_secret_blast_radius_table_when_matrix_present() -> None:
    service = ReportingService(db=None)
    report = {
        "scan_id": "scan-123",
        "generated_at": "2026-04-20T00:00:00+00:00",
        "findings": [
            {
                "title": "Sensitive exposure",
                "severity": "high",
                "attack_class": "sensitive_exposure",
                "affected_endpoint": "/api/debug",
                "description": "desc",
                "repro_steps": "steps",
                "fix_guidance": "fix",
                "evidence_notes": "",
                "attack_path": [],
                "kill_chain": [],
                "score_explanation": "conf=0.90",
                "proof_artifacts": [],
                "metadata": {
                    "secret_blast_radius_matrix": [
                        {
                            "endpoint": "/api/private/profile",
                            "method": "GET",
                            "status": 200,
                            "content_type": "application/json",
                            "response_size": 456,
                            "auth_accepted": True,
                        }
                    ]
                },
            }
        ],
    }

    markdown = service.render_markdown(report)

    assert "### Secret Blast Radius" in markdown
    assert "| Endpoint | Method | Status | Content-Type | Response Size | Auth Accepted |" in markdown
    assert "| /api/private/profile | GET | 200 | application/json | 456 | YES |" in markdown


def test_render_markdown_omits_secret_blast_radius_when_matrix_empty() -> None:
    service = ReportingService(db=None)
    report = {
        "scan_id": "scan-123",
        "generated_at": "2026-04-20T00:00:00+00:00",
        "findings": [
            {
                "title": "Sensitive exposure",
                "severity": "high",
                "attack_class": "sensitive_exposure",
                "affected_endpoint": "/api/debug",
                "description": "desc",
                "repro_steps": "steps",
                "fix_guidance": "fix",
                "evidence_notes": "",
                "attack_path": [],
                "kill_chain": [],
                "score_explanation": "conf=0.90",
                "proof_artifacts": [],
                "metadata": {"secret_blast_radius_matrix": []},
            }
        ],
    }

    markdown = service.render_markdown(report)
    assert "### Secret Blast Radius" not in markdown


def test_render_json_adds_secret_blast_radius_payload() -> None:
    service = ReportingService(db=None)
    report = {
        "scan_id": "scan-123",
        "generated_at": "2026-04-20T00:00:00+00:00",
        "findings": [
            {
                "title": "Sensitive exposure",
                "severity": "high",
                "attack_class": "sensitive_exposure",
                "affected_endpoint": "/api/debug",
                "description": "desc",
                "repro_steps": "steps",
                "fix_guidance": "fix",
                "proof_artifacts": [],
                "metadata": {
                    "secret_blast_radius_matrix": [
                        {
                            "endpoint": "/api/private/profile",
                            "method": "GET",
                            "status": 200,
                            "content_type": "application/json",
                            "response_size": 456,
                            "auth_accepted": True,
                        },
                        {
                            "endpoint": "/api/private/admin",
                            "method": "GET",
                            "status": 403,
                            "content_type": None,
                            "response_size": None,
                            "auth_accepted": False,
                        },
                    ]
                },
            }
        ],
    }

    payload = json.loads(service.render_json(report))
    finding = payload["findings"][0]
    blast_radius = finding["secret_blast_radius"]

    assert blast_radius["endpoints_tested"] == 2
    assert blast_radius["auth_accepted_count"] == 1
    assert blast_radius["matrix"][0]["endpoint"] == "/api/private/profile"
    assert blast_radius["matrix"][1]["status"] == 403


def test_render_json_sets_secret_blast_radius_none_when_missing() -> None:
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
                "proof_artifacts": [],
            }
        ],
    }

    payload = json.loads(service.render_json(report))
    assert payload["findings"][0]["secret_blast_radius"] is None


def test_render_json_includes_leak_source_when_present() -> None:
    service = ReportingService(db=None)
    report = {
        "scan_id": "scan-123",
        "generated_at": "2026-04-20T00:00:00+00:00",
        "findings": [
            {
                "title": "Sensitive exposure",
                "severity": "high",
                "attack_class": "sensitive_exposure",
                "affected_endpoint": "/api/debug",
                "description": "desc",
                "repro_steps": "steps",
                "fix_guidance": "fix",
                "proof_artifacts": [],
                "metadata": {"leak_source": {"type": "config_json", "confidence": 0.9}},
            }
        ],
    }

    payload = json.loads(service.render_json(report))
    assert payload["findings"][0]["leak_source"] == {"type": "config_json", "confidence": 0.9}


def _make_finding(*, metadata: dict[str, object] | None = None, severity: str = "high") -> dict[str, object]:
    return {
        "title": "Sensitive exposure",
        "severity": severity,
        "attack_class": "sensitive_exposure",
        "affected_endpoint": "/api/debug",
        "description": "desc",
        "repro_steps": "steps",
        "fix_guidance": "fix",
        "proof_artifacts": [],
        "metadata": metadata or {},
    }


def test_markdown_contains_why_severity_section() -> None:
    service = ReportingService(db=None)
    finding = _make_finding(
        metadata={
            "severity_factors": [
                {
                    "source": "active_replay",
                    "confidence": 0.92,
                    "description": "Token replay succeeded against an in-scope endpoint.",
                }
            ]
        },
        severity="Critical",
    )
    report = {"scan_id": "scan-123", "generated_at": "2026-04-20T00:00:00+00:00", "findings": [finding]}

    result = service.render_markdown(report)

    assert "**Why Severity Is Critical:**" in result
    assert "- Token replay succeeded against an in-scope endpoint. (source: active_replay, confidence: 92%)" in result


def test_json_export_has_severity_factors_array() -> None:
    service = ReportingService(db=None)
    factors = [{"source": "blast_radius", "confidence": 0.8, "description": "Secret reaches multiple endpoints."}]
    finding = _make_finding(metadata={"severity_factors": factors})
    report = {"scan_id": "scan-123", "generated_at": "2026-04-20T00:00:00+00:00", "findings": [finding]}

    data = json.loads(service.render_json(report))

    assert data["findings"][0]["severity_factors"] == factors


def test_json_export_severity_factors_empty_when_absent() -> None:
    service = ReportingService(db=None)
    finding = _make_finding(metadata={})
    report = {"scan_id": "scan-123", "generated_at": "2026-04-20T00:00:00+00:00", "findings": [finding]}

    data = json.loads(service.render_json(report))

    assert data["findings"][0]["severity_factors"] == []


def test_remediation_priority_critical_active_replay() -> None:
    service = ReportingService(db=None)
    finding = _make_finding(metadata={"active_replay": True}, severity="Critical")
    report = {"scan_id": "scan-123", "generated_at": "2026-04-20T00:00:00+00:00", "findings": [finding]}

    data = json.loads(service.render_json(report))

    assert data["findings"][0]["remediation_priority"] == "Priority 1: Rotate immediately"


def test_remediation_priority_high_blast_radius() -> None:
    service = ReportingService(db=None)
    finding = _make_finding(metadata={"blast_radius_score": 0.8}, severity="High")
    report = {"scan_id": "scan-123", "generated_at": "2026-04-20T00:00:00+00:00", "findings": [finding]}

    data = json.loads(service.render_json(report))

    assert data["findings"][0]["remediation_priority"] == "Priority 2: Rotate within 24h"


def test_remediation_priority_default() -> None:
    service = ReportingService(db=None)
    finding = _make_finding(metadata={}, severity="Medium")
    report = {"scan_id": "scan-123", "generated_at": "2026-04-20T00:00:00+00:00", "findings": [finding]}

    data = json.loads(service.render_json(report))

    assert data["findings"][0]["remediation_priority"] == "Priority 3: Rotate in next maintenance window"


def test_render_markdown_includes_privilege_fingerprint_when_present() -> None:
    """Privilege Fingerprint section appears in markdown when metadata contains fingerprint."""
    service = ReportingService(db=None)
    fingerprint_data = {
        "observed_access_level": "admin",
        "inferred_level": "unknown",
        "confidence": 0.6,
        "evidence_endpoints": ["/admin/users"],
        "hint_count": 3,
    }
    finding = _make_finding(metadata={"privilege_fingerprint": fingerprint_data})
    report = {"scan_id": "scan-123", "generated_at": "2026-04-20T00:00:00+00:00", "findings": [finding]}
    result = service.render_markdown(report)
    assert "Privilege Fingerprint" in result
    assert "admin" in result
    assert "/admin/users" in result


def test_render_markdown_privilege_fingerprint_admin_has_critical_remediation() -> None:
    """Admin-level fingerprint triggers critical remediation guidance."""
    service = ReportingService(db=None)
    fingerprint_data = {
        "observed_access_level": "admin",
        "inferred_level": "admin",
        "confidence": 0.6,
        "evidence_endpoints": ["/admin/dashboard"],
        "hint_count": 2,
    }
    finding = _make_finding(metadata={"privilege_fingerprint": fingerprint_data})
    report = {"scan_id": "scan-123", "generated_at": "2026-04-20T00:00:00+00:00", "findings": [finding]}
    result = service.render_markdown(report)
    assert "Critical" in result or "critical" in result.lower()
    assert "Rotate" in result or "rotate" in result.lower()


def test_render_markdown_privilege_fingerprint_omitted_when_absent() -> None:
    """No Privilege Fingerprint section when metadata has no fingerprint."""
    service = ReportingService(db=None)
    finding = _make_finding(metadata={})
    report = {"scan_id": "scan-123", "generated_at": "2026-04-20T00:00:00+00:00", "findings": [finding]}
    result = service.render_markdown(report)
    assert "Privilege Fingerprint" not in result


def test_render_markdown_privilege_fingerprint_no_raw_secret_in_output() -> None:
    """Fingerprint section never exposes raw secret values."""
    service = ReportingService(db=None)
    fake_secret = "sk_live_SUPER_SECRET_VALUE_9999"
    fingerprint_data = {
        "observed_access_level": "user",
        "inferred_level": "unknown",
        "confidence": 0.6,
        "evidence_endpoints": ["/api/data"],
        "hint_count": 1,
    }
    finding = _make_finding(metadata={"privilege_fingerprint": fingerprint_data})
    report = {"scan_id": "scan-123", "generated_at": "2026-04-20T00:00:00+00:00", "findings": [finding]}
    result = service.render_markdown(report)
    assert fake_secret not in result


def test_render_json_includes_privilege_fingerprint_when_present() -> None:
    """render_json output contains privilege_fingerprint key when metadata has it."""
    service = ReportingService(db=None)
    fingerprint_data = {
        "observed_access_level": "elevated_user",
        "inferred_level": "admin",
        "confidence": 0.4,
        "evidence_endpoints": ["/billing/invoices"],
        "hint_count": 2,
    }
    finding = _make_finding(metadata={"privilege_fingerprint": fingerprint_data})
    report = {"scan_id": "scan-123", "generated_at": "2026-04-20T00:00:00+00:00", "findings": [finding]}
    result = service.render_json(report)
    data = json.loads(result) if isinstance(result, str) else result
    finding_data = data["findings"][0]
    assert "privilege_fingerprint" in finding_data
    fp = finding_data["privilege_fingerprint"]
    assert fp["observed_access_level"] == "elevated_user"
    assert fp["inferred_level"] == "admin"


def test_render_json_privilege_fingerprint_none_when_missing() -> None:
    """render_json has privilege_fingerprint set to None when not in metadata."""
    service = ReportingService(db=None)
    finding = _make_finding(metadata={})
    report = {"scan_id": "scan-123", "generated_at": "2026-04-20T00:00:00+00:00", "findings": [finding]}
    result = service.render_json(report)
    data = json.loads(result) if isinstance(result, str) else result
    assert data["findings"][0].get("privilege_fingerprint") is None

def test_executive_summary_returns_empty_for_non_sensitive_exposure() -> None:
    service = ReportingService(db=None)
    finding = {"attack_class": "bola", "affected_endpoint": "/api/x", "metadata": {}, "evidence_notes": ""}
    assert service._build_executive_summary(finding) == ""


def test_executive_summary_includes_secret_type_and_endpoint() -> None:
    service = ReportingService(db=None)
    finding = {
        "attack_class": "sensitive_exposure",
        "affected_endpoint": "/api/config",
        "evidence_notes": "secret_type=JWT\nttl_bucket=long\nactive_during_scan=true",
        "metadata": {},
    }
    result = service._build_executive_summary(finding)
    assert "JWT" in result
    assert "/api/config" in result


def test_executive_summary_admin_level_impact() -> None:
    service = ReportingService(db=None)
    finding = {
        "attack_class": "sensitive_exposure",
        "affected_endpoint": "/api/debug",
        "evidence_notes": "secret_type=JWT\nactive_during_scan=true",
        "metadata": {"privilege_fingerprint": {"observed_access_level": "admin"}},
    }
    result = service._build_executive_summary(finding)
    assert "admin" in result.lower()


def test_executive_summary_confirmed_active_when_true() -> None:
    service = ReportingService(db=None)
    finding = {
        "attack_class": "sensitive_exposure",
        "affected_endpoint": "/api/x",
        "evidence_notes": "secret_type=API_KEY\nactive_during_scan=true",
        "metadata": {},
    }
    result = service._build_executive_summary(finding)
    assert "confirmed active" in result


def test_executive_summary_handles_none_metadata() -> None:
    service = ReportingService(db=None)
    finding = {"attack_class": "sensitive_exposure", "affected_endpoint": "/api/x", "evidence_notes": "", "metadata": None}
    result = service._build_executive_summary(finding)
    assert isinstance(result, str)


def test_attack_narrative_returns_empty_for_non_sensitive_exposure() -> None:
    service = ReportingService(db=None)
    finding = {"attack_class": "bola", "metadata": {}, "evidence_notes": ""}
    assert service._build_attack_narrative(finding) == ""


def test_attack_narrative_includes_discovered_step() -> None:
    service = ReportingService(db=None)
    finding = {
        "attack_class": "sensitive_exposure",
        "affected_endpoint": "/api/config",
        "evidence_notes": "",
        "metadata": {"leak_source": {"type": "config_json", "confidence": 0.95}},
    }
    result = service._build_attack_narrative(finding)
    assert "Discovered" in result
    assert "config_json" in result


def test_attack_narrative_includes_classified_step() -> None:
    service = ReportingService(db=None)
    finding = {
        "attack_class": "sensitive_exposure",
        "affected_endpoint": "/api/x",
        "evidence_notes": "secret_type=JWT\nsecret_fingerprint=abc123\nttl_bucket=long\nactive_during_scan=true",
        "metadata": {},
    }
    result = service._build_attack_narrative(finding)
    assert "Classified" in result
    assert "JWT" in result
    assert "abc123" in result


def test_attack_narrative_includes_blast_radius_when_matrix_present() -> None:
    service = ReportingService(db=None)
    finding = {
        "attack_class": "sensitive_exposure",
        "affected_endpoint": "/api/x",
        "evidence_notes": "",
        "metadata": {
            "secret_blast_radius_matrix": [
                {"url_pattern": "/api/a", "method": "GET", "status": 200, "auth_accepted": True, "content_type": "application/json", "response_size": 100},
                {"url_pattern": "/api/b", "method": "GET", "status": 401, "auth_accepted": False, "content_type": "application/json", "response_size": 50},
            ]
        },
    }
    result = service._build_attack_narrative(finding)
    assert "Blast Radius" in result
    assert "2" in result


def test_remediation_plan_returns_empty_for_non_sensitive_exposure() -> None:
    service = ReportingService(db=None)
    finding = {"attack_class": "bola", "metadata": {}, "evidence_notes": ""}
    assert service._build_remediation_plan_section(finding) == ""


def test_remediation_plan_always_includes_rotate() -> None:
    service = ReportingService(db=None)
    finding = {"attack_class": "sensitive_exposure", "metadata": {}, "evidence_notes": ""}
    result = service._build_remediation_plan_section(finding)
    assert "Rotate" in result
    assert "Revoke" in result


def test_remediation_plan_includes_restrict_scope_for_admin() -> None:
    service = ReportingService(db=None)
    finding = {
        "attack_class": "sensitive_exposure",
        "metadata": {"privilege_fingerprint": {"observed_access_level": "admin"}},
        "evidence_notes": "",
    }
    result = service._build_remediation_plan_section(finding)
    assert "Restrict Scope" in result


def test_remediation_plan_includes_fix_source_for_debug_endpoint() -> None:
    service = ReportingService(db=None)
    finding = {
        "attack_class": "sensitive_exposure",
        "metadata": {"leak_source": {"type": "debug_endpoint", "confidence": 1.0}},
        "evidence_notes": "",
    }
    result = service._build_remediation_plan_section(finding)
    assert "Fix Source" in result
    assert "debug_endpoint" in result


def test_remediation_plan_includes_audit_logs_for_broad_blast_radius() -> None:
    service = ReportingService(db=None)
    matrix = [
        {"url_pattern": "/api/a", "method": "GET", "status": 200, "auth_accepted": True, "content_type": "application/json", "response_size": 100},
        {"url_pattern": "/api/b", "method": "GET", "status": 200, "auth_accepted": True, "content_type": "application/json", "response_size": 100},
        {"url_pattern": "/api/c", "method": "GET", "status": 200, "auth_accepted": True, "content_type": "application/json", "response_size": 100},
    ]
    finding = {
        "attack_class": "sensitive_exposure",
        "affected_endpoint": "/api/x",
        "evidence_notes": "",
        "metadata": {"secret_blast_radius_matrix": matrix},
    }
    result = service._build_remediation_plan_section(finding)
    assert "Audit Access Logs" in result


def test_remediation_plan_includes_cors_when_cors_permissive() -> None:
    service = ReportingService(db=None)
    finding = {
        "attack_class": "sensitive_exposure",
        "metadata": {"cors_permissive": True},
        "evidence_notes": "",
    }
    result = service._build_remediation_plan_section(finding)
    assert "CORS" in result


def test_remediation_plan_section_title_present() -> None:
    service = ReportingService(db=None)
    finding = {"attack_class": "sensitive_exposure", "metadata": {}, "evidence_notes": ""}
    result = service._build_remediation_plan_section(finding)
    assert "Remediation Plan" in result


def test_evidence_pack_returns_none_for_non_sensitive_exposure() -> None:
    service = ReportingService(db=None)
    finding = {"attack_class": "bola", "metadata": {}, "evidence_notes": ""}
    assert service._build_secret_exposure_evidence_pack(finding) is None


def test_evidence_pack_has_all_required_keys() -> None:
    service = ReportingService(db=None)
    finding = {"attack_class": "sensitive_exposure", "severity": "High", "metadata": {}, "evidence_notes": ""}
    pack = service._build_secret_exposure_evidence_pack(finding)
    assert pack is not None
    for key in ("secret_properties", "blast_radius", "privilege_fingerprint", "lifecycle", "severity_factors", "leak_source", "remediation_priority"):
        assert key in pack


def test_evidence_pack_secret_properties_from_evidence_notes() -> None:
    service = ReportingService(db=None)
    finding = {
        "attack_class": "sensitive_exposure",
        "severity": "High",
        "evidence_notes": "secret_type=JWT\nsecret_fingerprint=abc123\nttl_bucket=long\nactive_during_scan=true",
        "metadata": {},
    }
    pack = service._build_secret_exposure_evidence_pack(finding)
    assert pack is not None
    props = pack["secret_properties"]
    assert props is not None
    assert props.get("secret_type") == "JWT"
    assert props.get("secret_fingerprint") == "abc123"


def test_evidence_pack_lifecycle_when_secret_meta_present() -> None:
    service = ReportingService(db=None)
    finding = {
        "attack_class": "sensitive_exposure",
        "severity": "High",
        "evidence_notes": "secret_type=JWT\nttl_bucket=long\nactive_during_scan=true",
        "metadata": {},
    }
    pack = service._build_secret_exposure_evidence_pack(finding)
    assert pack is not None
    assert pack["lifecycle"] is not None
    assert pack["lifecycle"].get("ttl_bucket") == "long"


def test_evidence_pack_no_crash_on_none_metadata() -> None:
    service = ReportingService(db=None)
    finding = {"attack_class": "sensitive_exposure", "severity": "Medium", "metadata": None, "evidence_notes": ""}
    pack = service._build_secret_exposure_evidence_pack(finding)
    assert pack is not None
    assert pack["blast_radius"] is None
    assert pack["privilege_fingerprint"] is None


def test_render_json_includes_evidence_pack_key_for_all_findings() -> None:
    import json as _json

    service = ReportingService(db=None)
    report = {
        "scan_id": "s1",
        "findings": [
            {"id": "f1", "title": "t", "severity": "High", "attack_class": "sensitive_exposure",
             "affected_endpoint": "/api/x", "description": "", "reproduction_steps": "",
             "fix_guidance": "", "evidence_notes": "", "metadata": {}, "artifacts": []},
            {"id": "f2", "title": "t2", "severity": "Low", "attack_class": "bola",
             "affected_endpoint": "/api/y", "description": "", "reproduction_steps": "",
             "fix_guidance": "", "evidence_notes": "", "metadata": {}, "artifacts": []},
        ],
        "generated_at": "2026-04-26T00:00:00",
    }
    payload = _json.loads(service.render_json(report))
    assert "secret_exposure_evidence_pack" in payload["findings"][0]
    assert "secret_exposure_evidence_pack" in payload["findings"][1]
    assert payload["findings"][0]["secret_exposure_evidence_pack"] is not None
    assert payload["findings"][1]["secret_exposure_evidence_pack"] is None


def test_render_json_evidence_pack_contains_leak_source() -> None:
    import json as _json

    service = ReportingService(db=None)
    finding = {
        "id": "f1", "title": "t", "severity": "High", "attack_class": "sensitive_exposure",
        "affected_endpoint": "/api/x", "description": "", "reproduction_steps": "",
        "fix_guidance": "", "evidence_notes": "",
        "metadata": {"leak_source": {"type": "config_json", "confidence": 0.9}},
        "artifacts": [],
    }
    payload = _json.loads(service.render_json({"scan_id": "s1", "findings": [finding], "generated_at": "2026-04-26T00:00:00"}))
    pack = payload["findings"][0]["secret_exposure_evidence_pack"]
    assert pack is not None
    assert pack["leak_source"]["type"] == "config_json"


def test_render_markdown_includes_executive_summary_for_sensitive_exposure() -> None:
    service = ReportingService(db=None)
    finding = {
        "id": "f1", "title": "t", "severity": "High", "attack_class": "sensitive_exposure",
        "affected_endpoint": "/api/x", "description": "", "reproduction_steps": "",
        "fix_guidance": "", "evidence_notes": "secret_type=JWT\nactive_during_scan=true",
        "metadata": {}, "artifacts": [],
    }
    result = service.render_markdown({"scan_id": "s1", "findings": [finding], "generated_at": "2026-04-26T00:00:00"})
    assert "Executive Summary" in result


def test_render_markdown_no_executive_summary_for_non_sensitive() -> None:
    service = ReportingService(db=None)
    finding = {
        "id": "f1", "title": "t", "severity": "High", "attack_class": "bola",
        "affected_endpoint": "/api/x", "description": "", "reproduction_steps": "",
        "fix_guidance": "", "evidence_notes": "", "metadata": {}, "artifacts": [],
    }
    result = service.render_markdown({"scan_id": "s1", "findings": [finding], "generated_at": "2026-04-26T00:00:00"})
    assert "Executive Summary" not in result


def test_render_markdown_includes_remediation_plan_for_sensitive_exposure() -> None:
    service = ReportingService(db=None)
    finding = {
        "id": "f1", "title": "t", "severity": "High", "attack_class": "sensitive_exposure",
        "affected_endpoint": "/api/x", "description": "", "reproduction_steps": "",
        "fix_guidance": "", "evidence_notes": "", "metadata": {}, "artifacts": [],
    }
    result = service.render_markdown({"scan_id": "s1", "findings": [finding], "generated_at": "2026-04-26T00:00:00"})
    assert "Remediation Plan" in result


def test_evidence_pack_backward_compat_no_crash_on_empty_metadata() -> None:
    import json as _json

    service = ReportingService(db=None)
    old_finding = {
        "id": "old-1", "title": "old finding", "severity": "Medium",
        "attack_class": "sensitive_exposure", "affected_endpoint": "/api/x",
        "description": "", "reproduction_steps": "", "fix_guidance": "",
        "evidence_notes": "", "metadata": {}, "artifacts": [],
    }
    payload = _json.loads(service.render_json({"scan_id": "s1", "findings": [old_finding], "generated_at": "2026-04-26T00:00:00"}))
    pack = payload["findings"][0]["secret_exposure_evidence_pack"]
    assert pack is not None
    assert pack["secret_properties"] is None
    assert pack["blast_radius"] is None
    assert pack["lifecycle"] is None


def test_render_markdown_backward_compat_no_crash_on_none_metadata() -> None:
    service = ReportingService(db=None)
    old_finding = {
        "id": "old-2", "title": "old finding", "severity": "Low",
        "attack_class": "sensitive_exposure", "affected_endpoint": "/api/y",
        "description": "", "reproduction_steps": "", "fix_guidance": "",
        "evidence_notes": "", "metadata": None, "artifacts": [],
    }
    result = service.render_markdown({"scan_id": "s1", "findings": [old_finding], "generated_at": "2026-04-26T00:00:00"})
    assert "Executive Summary" in result


def test_extra_metadata_is_separate_from_orm_metadata_class() -> None:
    from storage.db.models import Finding, Severity
    import sqlalchemy as sa

    endpoint_id = uuid4()
    finding = Finding(
        id=uuid4(), scan_id=uuid4(),
        title="Sensitive exposure", description="desc",
        severity=Severity.high, attack_class="sensitive_exposure",
        affected_endpoint_id=endpoint_id,
        repro_steps="steps", fix_guidance="fix",
    )
    matrix = [{"endpoint": "/api/secret", "method": "GET", "status": 200,
               "content_type": "application/json", "response_size": 100, "auth_accepted": True}]
    finding.extra_metadata = {"secret_blast_radius_matrix": matrix}
    assert finding.extra_metadata == {"secret_blast_radius_matrix": matrix}
    assert not (isinstance(finding.metadata, dict) and "secret_blast_radius_matrix" in finding.metadata)


@pytest.mark.asyncio
async def test_assemble_report_propagates_extra_metadata_to_output() -> None:
    from unittest.mock import AsyncMock, MagicMock
    from storage.db.models import Finding, Severity, Scan, Target, Endpoint
    from control_plane.reporting import ReportingService

    scan_id = uuid4()
    target = Target(id=uuid4(), url="https://example.com", name="test", config={})
    scan = Scan(id=scan_id, target_id=target.id, status="complete")
    scan.target = target

    endpoint = Endpoint(
        id=uuid4(), asset_map_id=uuid4(), url_pattern="/api/data",
        method="GET", auth_required=True, parameters=[],
    )
    finding = Finding(
        id=uuid4(), scan_id=scan_id,
        title="Sensitive exposure", description="desc",
        severity=Severity.high, attack_class="sensitive_exposure",
        affected_endpoint_id=endpoint.id,
        repro_steps="steps", fix_guidance="fix",
    )
    matrix = [{"endpoint": "/api/secret", "method": "GET", "status": 200,
               "content_type": "application/json", "response_size": 100, "auth_accepted": True}]
    finding.extra_metadata = {"secret_blast_radius_matrix": matrix}
    finding.affected_endpoint = endpoint
    finding.proof_artifacts = []

    db = AsyncMock()
    scan_result = MagicMock()
    scan_result.scalar_one_or_none.return_value = scan
    findings_result = MagicMock()
    findings_result.scalars.return_value.all.return_value = [finding]
    db.execute = AsyncMock(side_effect=[scan_result, findings_result])

    service = ReportingService(db=db, evidence_store=None)
    service._evidence_store = None

    report = await service.assemble_report(scan_id)

    findings = report["findings"]
    assert len(findings) == 1
    metadata = findings[0].get("metadata")
    assert isinstance(metadata, dict)
    assert "secret_blast_radius_matrix" in metadata
    assert len(metadata["secret_blast_radius_matrix"]) == 1


@pytest.mark.asyncio
async def test_assemble_report_adds_identity_context_from_evidence_labels(monkeypatch: pytest.MonkeyPatch) -> None:
    from unittest.mock import AsyncMock, MagicMock
    from storage.db.models import Endpoint, Finding, ProofArtifact, Scan, Severity, Target
    from control_plane.reporting import ReportingService

    scan_id = uuid4()
    target = Target(id=uuid4(), url="https://example.com", name="test", config={})
    scan = Scan(id=scan_id, target_id=target.id, status="complete")
    scan.target = target

    endpoint = Endpoint(
        id=uuid4(), asset_map_id=uuid4(), url_pattern="/api/data",
        method="GET", auth_required=True, parameters=[],
    )
    finding = Finding(
        id=uuid4(), scan_id=scan_id,
        title="BOLA", description="desc",
        severity=Severity.high, attack_class="bola",
        affected_endpoint_id=endpoint.id,
        repro_steps="steps", fix_guidance="fix",
    )
    finding.extra_metadata = {}
    finding.affected_endpoint = endpoint
    finding.proof_artifacts = [
        ProofArtifact(
            id=uuid4(),
            attack_task_id=uuid4(),
            proof_type="differential",
            confidence_score=0.95,
            attack_probe_id=uuid4(),
            summary="summary",
            evidence_notes="notes",
        )
    ]

    db = AsyncMock()
    scan_result = MagicMock()
    scan_result.scalar_one_or_none.return_value = scan
    findings_result = MagicMock()
    findings_result.scalars.return_value.all.return_value = [finding]
    db.execute = AsyncMock(side_effect=[scan_result, findings_result])

    service = ReportingService(db=db, evidence_store=None)
    service._evidence_store = None
    monkeypatch.setattr(
        service,
        "_artifact_payload",
        lambda **_: {
            "artifact_id": "artifact-1",
            "proof_type": "differential",
            "confidence_score": 0.95,
            "identity_labels": ["current_user", "alternate_user"],
            "credentials": {"password": "secret"},
            "auth_headers": {"Authorization": "Bearer secret"},
            "request": {},
            "response": {},
        },
    )

    report = await service.assemble_report(scan_id)

    finding_report = report["findings"][0]
    assert finding_report["identity_context"] == {
        "identities_used": ["current_user", "alternate_user"],
    }
    assert "credentials" not in finding_report["identity_context"]
    assert "auth_headers" not in finding_report["identity_context"]


@pytest.mark.asyncio
async def test_assemble_report_omits_identity_context_without_identity_labels(monkeypatch: pytest.MonkeyPatch) -> None:
    from unittest.mock import AsyncMock, MagicMock
    from storage.db.models import Endpoint, Finding, ProofArtifact, Scan, Severity, Target
    from control_plane.reporting import ReportingService

    scan_id = uuid4()
    target = Target(id=uuid4(), url="https://example.com", name="test", config={})
    scan = Scan(id=scan_id, target_id=target.id, status="complete")
    scan.target = target

    endpoint = Endpoint(
        id=uuid4(), asset_map_id=uuid4(), url_pattern="/api/data",
        method="GET", auth_required=True, parameters=[],
    )
    finding = Finding(
        id=uuid4(), scan_id=scan_id,
        title="BOLA", description="desc",
        severity=Severity.high, attack_class="bola",
        affected_endpoint_id=endpoint.id,
        repro_steps="steps", fix_guidance="fix",
    )
    finding.extra_metadata = {}
    finding.affected_endpoint = endpoint
    finding.proof_artifacts = [
        ProofArtifact(
            id=uuid4(),
            attack_task_id=uuid4(),
            proof_type="differential",
            confidence_score=0.95,
            attack_probe_id=uuid4(),
            summary="summary",
            evidence_notes="notes",
        )
    ]

    db = AsyncMock()
    scan_result = MagicMock()
    scan_result.scalar_one_or_none.return_value = scan
    findings_result = MagicMock()
    findings_result.scalars.return_value.all.return_value = [finding]
    db.execute = AsyncMock(side_effect=[scan_result, findings_result])

    service = ReportingService(db=db, evidence_store=None)
    service._evidence_store = None
    monkeypatch.setattr(service, "_artifact_payload", lambda **_: {"request": {}, "response": {}})

    report = await service.assemble_report(scan_id)

    assert "identity_context" not in report["findings"][0]


@pytest.mark.asyncio
async def test_report_includes_actions_performed() -> None:
    from unittest.mock import AsyncMock, MagicMock
    from storage.db.models import Scan, Target

    scan_id = uuid4()
    target = Target(id=uuid4(), url="https://example.com", name="test", config={})
    scan = Scan(id=scan_id, target_id=target.id, status="complete")
    scan.target = target

    scan_result = MagicMock()
    scan_result.scalar_one_or_none.return_value = scan
    findings_result = MagicMock()
    findings_result.scalars.return_value.all.return_value = []
    total_requests_result = MagicMock()
    total_requests_result.scalar_one.return_value = 2
    tasks_dispatched_result = MagicMock()
    tasks_dispatched_result.scalar_one.return_value = 3
    by_class_result = MagicMock()
    by_class_result.all.return_value = [("bola", 2)]
    tasks_with_findings_result = MagicMock()
    tasks_with_findings_result.scalar_one.return_value = 1

    db = AsyncMock()
    db.execute = AsyncMock(
        side_effect=[
            scan_result,
            findings_result,
            total_requests_result,
            tasks_dispatched_result,
            by_class_result,
            tasks_with_findings_result,
        ]
    )

    service = ReportingService(db=db, evidence_store=None)
    service._evidence_store = None

    report = await service.assemble_report(scan_id)

    assert report["actions_performed"] == {
        "total_requests_sent": 2,
        "requests_by_attack_class": {"bola": 2},
        "tasks_dispatched": 3,
        "tasks_with_findings": 1,
    }


@pytest.mark.asyncio
async def test_report_includes_skipped_blocked(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeRedis:
        async def lrange(self, key: str, start: int, stop: int) -> list[str]:
            assert key == f"skipped_tasks:{scan_id}"
            assert start == 0
            assert stop == -1
            return [json.dumps({"task_id": "task-1", "reason": "blocked", "attack_class": "bola"})]

        async def aclose(self) -> None:
            return None

    scan_id = uuid4()
    monkeypatch.setenv("REDIS_URL", "redis://localhost:6379/0")
    monkeypatch.setattr("redis.asyncio.Redis.from_url", lambda *_, **__: FakeRedis())

    service = ReportingService(db=None, evidence_store=None)

    skipped_blocked = await service._skipped_blocked(scan_id)

    assert skipped_blocked == {
        "tasks_skipped": 1,
        "skipped_details": [{"task_id": "task-1", "reason": "blocked", "attack_class": "bola"}],
    }


@pytest.mark.asyncio
async def test_report_skipped_blocked_empty_on_no_redis(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("REDIS_URL", raising=False)
    service = ReportingService(db=None, evidence_store=None)

    skipped_blocked = await service._skipped_blocked(uuid4())

    assert skipped_blocked == {"tasks_skipped": 0, "skipped_details": []}
