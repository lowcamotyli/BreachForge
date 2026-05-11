from __future__ import annotations

import json

from control_plane.reporting import ReportingService


def _service():
    return ReportingService(db=None)


def _finding():
    return {
        "id": "finding-d3",
        "title": "Active admin credential exposed",
        "severity": "Critical",
        "attack_class": "sensitive_exposure",
        "affected_endpoint": "/api/debug/config",
        "description": "Admin JWT exposed at debug endpoint, replay confirmed.",
        "reproduction_steps": "",
        "fix_guidance": "Rotate credential and disable debug endpoint.",
        "evidence_notes": "secret_type=JWT\nsecret_fingerprint=ghi789\nttl_bucket=long\nactive_during_scan=true",
        "metadata": {
            "leak_source": {"type": "debug_endpoint", "confidence": 1.0},
            "active_replay": True,
            "blast_radius_score": 0.9,
            "secret_blast_radius_matrix": [
                {
                    "url_pattern": "/api/admin/users",
                    "method": "GET",
                    "status": 200,
                    "auth_accepted": True,
                    "content_type": "application/json",
                    "response_size": 4096,
                },
                {
                    "url_pattern": "/api/admin/settings",
                    "method": "GET",
                    "status": 200,
                    "auth_accepted": True,
                    "content_type": "application/json",
                    "response_size": 1024,
                },
                {
                    "url_pattern": "/api/admin/audit",
                    "method": "GET",
                    "status": 200,
                    "auth_accepted": True,
                    "content_type": "application/json",
                    "response_size": 2048,
                },
            ],
            "severity_factors": [
                {
                    "source": "active_replay+unauthenticated_exposure",
                    "confidence": 0.95,
                    "description": "Admin credential replay succeeded with broad blast radius.",
                }
            ],
            "privilege_fingerprint": {
                "observed_access_level": "admin",
                "inferred_level": "admin",
                "confidence": 0.95,
                "evidence_endpoints": ["/api/admin/users", "/api/admin/settings"],
            },
        },
        "artifacts": [],
    }


def _report():
    return {"scan_id": "scan-d3", "findings": [_finding()], "generated_at": "2026-04-26T00:00:00"}


def test_executive_summary_mentions_admin():
    md = _service().render_markdown(_report())
    assert "Executive Summary" in md
    assert "admin" in md.lower()


def test_remediation_plan_has_restrict_scope():
    md = _service().render_markdown(_report())
    assert "Restrict Scope" in md


def test_remediation_plan_has_audit_logs_for_broad_blast_radius():
    md = _service().render_markdown(_report())
    assert "Audit Access Logs" in md


def test_json_evidence_pack_has_severity_factors():
    payload = json.loads(_service().render_json(_report()))
    pack = payload["findings"][0]["secret_exposure_evidence_pack"]
    assert pack is not None
    assert len(pack["severity_factors"]) > 0


def test_json_evidence_pack_privilege_is_admin():
    payload = json.loads(_service().render_json(_report()))
    pack = payload["findings"][0]["secret_exposure_evidence_pack"]
    assert pack["privilege_fingerprint"]["observed_access_level"] == "admin"
