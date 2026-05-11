from __future__ import annotations

import pytest

from control_plane.auth_manager import IdentityProfile


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
