from __future__ import annotations

import pytest
from datetime import datetime

from api.models.requests import ScanPolicyV2
from control_plane.reporting import authorization_pack_section, generate_authorization_pack


def test_authorization_pack_generated():
    policy = ScanPolicyV2()
    pack = generate_authorization_pack("scan-123", policy, "admin@example.com")
    assert pack.scan_id == "scan-123"
    assert pack.contact_email == "admin@example.com"
    assert isinstance(pack.generated_at, datetime)
    assert pack.policy_version == "2"


def test_authorization_pack_scope_summary():
    policy = ScanPolicyV2()
    policy.scope.allowed_domains = ["example.com"]
    pack = generate_authorization_pack("scan-xyz", policy)
    assert "example.com" in pack.scope_summary["allowed_domains"]


def test_authorization_pack_emergency_stop_url():
    policy = ScanPolicyV2()
    pack = generate_authorization_pack("scan-abc", policy)
    assert "scan-abc" in pack.emergency_stop_url
    assert "kill" in pack.emergency_stop_url


def test_authorization_pack_section_none_policy():
    result = authorization_pack_section("scan-123", None)
    assert result == {}


def test_authorization_pack_section_with_policy():
    result = authorization_pack_section("scan-123", ScanPolicyV2())
    assert "authorization_pack" in result
    assert result["authorization_pack"]["scan_id"] == "scan-123"
