from __future__ import annotations

import json

from control_plane.reporting import ReportingService


def _service():
    return ReportingService(db=None)


def _finding():
    return {
        "id": "finding-d1",
        "title": "JWT leaked in config endpoint",
        "severity": "High",
        "attack_class": "sensitive_exposure",
        "affected_endpoint": "/api/config",
        "description": "Config endpoint returned JWT in response body.",
        "reproduction_steps": "",
        "fix_guidance": "Remove credentials from config endpoint response.",
        "evidence_notes": "secret_type=JWT\nsecret_fingerprint=abc123\nttl_bucket=long\nactive_during_scan=true",
        "metadata": {
            "leak_source": {"type": "config_json", "confidence": 0.95},
            "active_replay": True,
            "unauthenticated_exposure": True,
            "blast_radius_score": 0.8,
            "severity_factors": [
                {
                    "source": "active_replay+unauthenticated_exposure",
                    "confidence": 0.95,
                    "description": "Secret replay succeeded against an unauthenticated exposure path.",
                }
            ],
            "privilege_fingerprint": {
                "observed_access_level": "authenticated_user",
                "inferred_level": "user",
                "confidence": 0.85,
                "evidence_endpoints": ["/api/config"],
            },
        },
        "artifacts": [],
    }


def _report():
    return {"scan_id": "scan-d1", "findings": [_finding()], "generated_at": "2026-04-26T00:00:00"}


def test_markdown_has_executive_summary():
    md = _service().render_markdown(_report())
    assert "Executive Summary" in md


def test_markdown_has_attack_narrative():
    md = _service().render_markdown(_report())
    assert "Attack Narrative" in md


def test_markdown_has_remediation_plan():
    md = _service().render_markdown(_report())
    assert "Remediation Plan" in md
    assert "Rotate" in md


def test_markdown_has_config_json_source_fix():
    md = _service().render_markdown(_report())
    assert "config_json" in md


def test_json_evidence_pack_present():
    payload = json.loads(_service().render_json(_report()))
    pack = payload["findings"][0]["secret_exposure_evidence_pack"]
    assert pack is not None
    assert pack["leak_source"]["type"] == "config_json"


def test_json_evidence_pack_secret_properties_are_safe():
    # secret_properties must contain parsed metadata fields, never the raw secret value
    payload = json.loads(_service().render_json(_report()))
    pack = payload["findings"][0]["secret_exposure_evidence_pack"]
    assert pack is not None
    props = pack["secret_properties"]
    assert props is not None
    assert props.get("secret_type") == "JWT"
    assert props.get("secret_fingerprint") == "abc123"
    assert props.get("ttl_bucket") == "long"
    assert props.get("active_during_scan") == "true"
