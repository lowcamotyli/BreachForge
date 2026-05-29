from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest

from control_plane.auth_manager import IdentityContext, IdentityHealthMatrix, IdentityProfile, IdentityRole
from control_plane.reporting import ReportingService


def test_identity_profile_creation_with_valid_auth_state() -> None:
    profile = IdentityProfile(
        name="default-user",
        role="user",
        tenant="tenant-a",
        auth_state="active",
        privilege_hint="read-only",
        session_ref="session-1",
    )

    assert profile.auth_state == "active"


def test_identity_profile_rejects_invalid_auth_state() -> None:
    with pytest.raises(ValueError, match="Invalid auth_state"):
        IdentityProfile(
            name="expired-user",
            role="user",
            tenant="tenant-a",
            auth_state="invalid",  # type: ignore[arg-type]
            privilege_hint=None,
            session_ref="session-2",
        )


def test_identity_profile_has_no_credentials_field() -> None:
    profile = IdentityProfile(
        name="anon",
        role=None,
        tenant=None,
        auth_state="none",
        privilege_hint=None,
        session_ref=None,
    )

    assert not hasattr(profile, "credentials")


def test_identity_health_matrix_records_role_and_tenant_probe_stats() -> None:
    scan_id = uuid4()
    matrix = IdentityHealthMatrix()
    user_tenant_a = IdentityContext(
        scan_id=scan_id,
        role=IdentityRole.user,
        cookies=[],
        auth_headers={},
        csrf_tokens={},
        captured_at=datetime.now(UTC),
        tenant_hint="tenantA",
    )
    admin_tenant_b = IdentityContext(
        scan_id=scan_id,
        role=IdentityRole.admin,
        cookies=[],
        auth_headers={},
        csrf_tokens={},
        captured_at=datetime.now(UTC),
        tenant_hint="tenantB",
    )

    matrix.record_probe(user_tenant_a, success=True, status_code=200)
    matrix.record_probe(user_tenant_a, success=False, status_code=403)
    matrix.record_probe(admin_tenant_b, success=False, status_code=503)

    summary = matrix.summary

    assert summary["per_role"]["user"]["pass_rate"] == pytest.approx(0.5)
    assert summary["per_role"]["user"]["failed_rate"] == pytest.approx(0.5)
    assert summary["per_role"]["user"]["total_probes"] == 2
    assert summary["per_role"]["user"]["failed_probes"] == 1
    assert summary["per_role"]["admin"]["degraded_rate"] == pytest.approx(1.0)
    assert summary["per_tenant"]["tenantA"]["pass_rate"] == pytest.approx(0.5)
    assert summary["per_tenant"]["tenantB"]["failed_probes"] == 1
    assert summary["role_markers"] == ["user", "admin"]
    assert summary["tenant_markers"] == ["tenantA", "tenantB"]


def test_identity_health_matrix_summary_uses_zero_for_unprobed_markers() -> None:
    matrix = IdentityHealthMatrix()

    assert matrix.summary == {
        "per_role": {},
        "per_tenant": {},
        "role_markers": [],
        "tenant_markers": [],
    }


def test_reporting_auth_identity_matrix_section_returns_structured_stats() -> None:
    scan_id = uuid4()
    matrix = IdentityHealthMatrix()
    identity = IdentityContext(
        scan_id=scan_id,
        role=IdentityRole.anon,
        cookies=[],
        auth_headers={},
        csrf_tokens={},
        captured_at=datetime.now(UTC),
        tenant_hint="tenantA",
    )
    matrix.record_probe(identity, success=True, status_code=204)

    section = ReportingService(db=None).auth_identity_matrix_section(matrix)

    assert section["per_role"]["anon"]["pass_rate"] == 1.0
    assert section["per_tenant"]["tenantA"]["total_probes"] == 1
    assert section["role_markers"] == ["anon"]
    assert section["tenant_markers"] == ["tenantA"]
