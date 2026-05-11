from __future__ import annotations

from pathlib import Path
import sys
from unittest.mock import patch

PROJECT_ROOT = Path(__file__).resolve().parents[4]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from execution_plane.crawler.asset_map import AssetMap, Endpoint
from execution_plane.planner.secret_blast_radius import BlastRadiusSelector


def _endpoint(
    *,
    url_pattern: str,
    method: str,
    in_scope: bool = True,
    auth_required: bool = False,
) -> Endpoint:
    return Endpoint(
        url_pattern=url_pattern,
        method=method,
        in_scope=in_scope,
        auth_required=auth_required,
        parameters=[],
        observed_content_type="application/json",
        example_response_code=200,
    )


def test_only_get_head_options_included() -> None:
    asset_map = AssetMap(
        endpoints=[
            _endpoint(url_pattern="/api/read", method="GET"),
            _endpoint(url_pattern="/api/head", method="HEAD"),
            _endpoint(url_pattern="/api/options", method="OPTIONS"),
            _endpoint(url_pattern="/api/write", method="POST"),
        ]
    )

    selected = BlastRadiusSelector(asset_map).select()

    signatures = {(item["url_pattern"], item["method"]) for item in selected}
    assert signatures == {
        ("/api/head", "HEAD"),
        ("/api/options", "OPTIONS"),
        ("/api/read", "GET"),
    }


def test_out_of_scope_endpoints_are_excluded() -> None:
    asset_map = AssetMap(
        endpoints=[
            _endpoint(url_pattern="/api/me", method="GET", in_scope=False),
            _endpoint(url_pattern="/api/profile", method="GET", in_scope=True),
        ]
    )

    selected = BlastRadiusSelector(asset_map).select()

    assert len(selected) == 1
    assert selected[0]["url_pattern"] == "/api/profile"


def test_source_endpoint_ranked_first_with_priority_rank_zero() -> None:
    asset_map = AssetMap(
        endpoints=[
            _endpoint(url_pattern="/api/profile", method="GET", auth_required=True),
            _endpoint(url_pattern="/api/source", method="GET", auth_required=False),
        ]
    )

    selected = BlastRadiusSelector(asset_map, source_endpoint_pattern="/api/source").select()

    assert selected[0]["url_pattern"] == "/api/source"
    assert selected[0]["priority_rank"] == 0


def test_priority_paths_ranked_before_generic_endpoints() -> None:
    asset_map = AssetMap(
        endpoints=[
            _endpoint(url_pattern="/api/z-generic", method="GET", auth_required=False),
            _endpoint(url_pattern="/api/profile", method="GET", auth_required=False),
        ]
    )

    selected = BlastRadiusSelector(asset_map).select()

    assert selected[0]["url_pattern"] == "/api/profile"
    assert selected[0]["priority_rank"] == 1
    assert selected[1]["url_pattern"] == "/api/z-generic"
    assert selected[1]["priority_rank"] == 3


def test_auth_required_ranked_before_remaining_get_endpoints() -> None:
    asset_map = AssetMap(
        endpoints=[
            _endpoint(url_pattern="/api/public", method="GET", auth_required=False),
            _endpoint(url_pattern="/api/private", method="GET", auth_required=True),
        ]
    )

    selected = BlastRadiusSelector(asset_map).select()

    assert selected[0]["url_pattern"] == "/api/private"
    assert selected[0]["priority_rank"] == 2
    assert selected[1]["url_pattern"] == "/api/public"
    assert selected[1]["priority_rank"] == 3


def test_max_probes_cap_enforced_by_default() -> None:
    asset_map = AssetMap(
        endpoints=[_endpoint(url_pattern=f"/api/item-{index}", method="GET") for index in range(12)]
    )

    selected = BlastRadiusSelector(asset_map).select()

    assert len(selected) == 8


def test_empty_asset_map_returns_empty_list() -> None:
    selected = BlastRadiusSelector(AssetMap(endpoints=[])).select()

    assert selected == []


def test_env_override_for_max_probes_is_used() -> None:
    asset_map = AssetMap(
        endpoints=[_endpoint(url_pattern=f"/api/item-{index}", method="GET") for index in range(10)]
    )

    with patch.dict("os.environ", {"SECRET_BLAST_RADIUS_MAX_PROBES": "5"}, clear=False):
        selected = BlastRadiusSelector(asset_map).select()

    assert len(selected) == 5


def test_env_value_above_twenty_is_clamped_to_twenty() -> None:
    asset_map = AssetMap(
        endpoints=[_endpoint(url_pattern=f"/api/item-{index}", method="GET") for index in range(30)]
    )

    with patch.dict("os.environ", {"SECRET_BLAST_RADIUS_MAX_PROBES": "999"}, clear=False):
        selected = BlastRadiusSelector(asset_map).select()

    assert len(selected) == 20


def test_env_value_below_one_is_clamped_to_one() -> None:
    asset_map = AssetMap(
        endpoints=[_endpoint(url_pattern=f"/api/item-{index}", method="GET") for index in range(30)]
    )

    with patch.dict("os.environ", {"SECRET_BLAST_RADIUS_MAX_PROBES": "0"}, clear=False):
        selected = BlastRadiusSelector(asset_map).select()

    assert len(selected) == 1


def test_dedup_same_url_pattern_and_method_returns_one_entry() -> None:
    asset_map = AssetMap(
        endpoints=[
            _endpoint(url_pattern="/api/account", method="GET"),
            _endpoint(url_pattern="/api/account", method="GET"),
            _endpoint(url_pattern="/api/account", method="HEAD"),
        ]
    )

    selected = BlastRadiusSelector(asset_map).select()

    assert sum(1 for item in selected if item["url_pattern"] == "/api/account" and item["method"] == "GET") == 1
    assert sum(1 for item in selected if item["url_pattern"] == "/api/account" and item["method"] == "HEAD") == 1
