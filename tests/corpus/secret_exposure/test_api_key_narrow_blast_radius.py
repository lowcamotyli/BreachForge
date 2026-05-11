from __future__ import annotations

import json

from control_plane.reporting import ReportingService


def _service():
    return ReportingService(db=None)


def _finding():
    return {
        "id": "finding-d2",
        "title": "API key narrow blast radius",
        "severity": "Medium",
        "attack_class": "sensitive_exposure",
        "affected_endpoint": "/api/health",
        "description": "API key exposed but accepted only on one endpoint.",
        "reproduction_steps": "",
        "fix_guidance": "Rotate the API key.",
        "evidence_notes": "secret_type=API_KEY\nsecret_fingerprint=def456\nttl_bucket=unknown\nactive_during_scan=true",
        "metadata": {
            "leak_source": {"type": "debug_endpoint", "confidence": 0.9},
            "blast_radius_score": 0.2,
            "secret_blast_radius_matrix": [
                {
                    "url_pattern": "/api/internal/metrics",
                    "method": "GET",
                    "status": 200,
                    "auth_accepted": True,
                    "content_type": "application/json",
                    "response_size": 512,
                },
                {
                    "url_pattern": "/api/public/status",
                    "method": "GET",
                    "status": 401,
                    "auth_accepted": False,
                    "content_type": "application/json",
                    "response_size": 64,
                },
            ],
            "severity_factors": [],
        },
        "artifacts": [],
    }


def _report():
    return {"scan_id": "scan-d2", "findings": [_finding()], "generated_at": "2026-04-26T00:00:00"}


def test_blast_radius_is_narrow():
    payload = json.loads(_service().render_json(_report()))
    pack = payload["findings"][0]["secret_exposure_evidence_pack"]
    assert pack is not None
    br = pack["blast_radius"]
    assert br is not None
    assert br["auth_accepted_count"] == 1
    assert br["endpoints_tested"] == 2


def test_markdown_shows_blast_radius_table():
    md = _service().render_markdown(_report())
    assert "/api/internal/metrics" in md


def test_markdown_has_executive_summary():
    md = _service().render_markdown(_report())
    assert "Executive Summary" in md


def test_json_evidence_pack_present():
    payload = json.loads(_service().render_json(_report()))
    assert payload["findings"][0]["secret_exposure_evidence_pack"] is not None
