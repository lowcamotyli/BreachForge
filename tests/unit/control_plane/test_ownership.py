from __future__ import annotations

from pathlib import Path

from control_plane.ownership import OwnershipResolver, score_ownership_confidence


async def test_manual_override_wins_over_other_sources(tmp_path: Path) -> None:
    resolver = OwnershipResolver(project_root=tmp_path)
    openapi_spec = {
        "paths": {
            "/api/users/{id}": {
                "x-owner": {"team": "platform", "service": "users"},
            }
        }
    }
    manual_overrides = {
        "https://app.example.com/api/users": {"team": "security", "service": "identity"},
    }

    owner = await resolver.resolve(
        "https://app.example.com/api/users/123",
        openapi_spec=openapi_spec,
        manual_overrides=manual_overrides,
    )

    assert owner.team == "security"
    assert owner.service == "identity"
    assert owner.confidence == 1.0
    assert owner.source == "manual"


async def test_returns_unknown_owner_info_when_no_sources_available(tmp_path: Path) -> None:
    resolver = OwnershipResolver(project_root=tmp_path)

    owner = await resolver.resolve("https://app.example.com/api/missing")

    assert owner.team == "unknown"
    assert owner.service == "unknown"
    assert owner.confidence == 0.0
    assert owner.source == "unknown"


async def test_x_owner_extracted_from_openapi_spec_paths(tmp_path: Path) -> None:
    resolver = OwnershipResolver(project_root=tmp_path)
    openapi_spec = {
        "paths": {
            "/api/orders/{order_id}": {
                "x-owner": {"team": "commerce", "service": "orders"},
            }
        }
    }

    owner = await resolver.resolve("https://app.example.com/api/orders/ord_123", openapi_spec=openapi_spec)

    assert owner.team == "commerce"
    assert owner.service == "orders"
    assert owner.confidence == 0.9
    assert owner.source == "openapi"


def test_score_ownership_confidence_returns_base_score_for_source() -> None:
    assert score_ownership_confidence("service_catalog", path_segment_count=2) == 0.5


def test_score_ownership_confidence_adds_confirming_sources_beyond_first() -> None:
    # base 0.5 + two extra confirmations * 0.05
    assert score_ownership_confidence("service_catalog", path_segment_count=3, confirming_sources=3) == 0.6


def test_score_ownership_confidence_adds_path_depth_bonus() -> None:
    # base 0.7 + depth bonus 0.02
    assert score_ownership_confidence("codeowners", path_segment_count=5, confirming_sources=1) == 0.72


def test_score_ownership_confidence_caps_at_one() -> None:
    assert score_ownership_confidence("manual", path_segment_count=8, confirming_sources=5) == 1.0
