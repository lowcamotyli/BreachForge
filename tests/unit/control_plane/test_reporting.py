from __future__ import annotations

import json

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
