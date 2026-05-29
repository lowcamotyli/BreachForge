from __future__ import annotations

from collections.abc import Mapping

from scripts.benchmark_lab import generate_large_asset_map


def _endpoints(asset_map: Mapping[str, object]) -> list[dict[str, object]]:
    endpoints = asset_map["endpoints"]
    assert isinstance(endpoints, list)
    assert all(isinstance(endpoint, dict) for endpoint in endpoints)
    return endpoints


def _methods(asset_map: Mapping[str, object]) -> set[str]:
    return {str(endpoint["method"]) for endpoint in _endpoints(asset_map)}


def test_generate_large_asset_map_100_has_varied_methods() -> None:
    asset_map = generate_large_asset_map(100)

    endpoints = _endpoints(asset_map)

    assert len(endpoints) == 100
    assert {"GET", "POST", "PUT", "DELETE"}.issubset(_methods(asset_map))


def test_generate_large_asset_map_500_has_requested_endpoint_count() -> None:
    asset_map = generate_large_asset_map(500)

    assert len(_endpoints(asset_map)) == 500


def test_generate_large_asset_map_1000_has_all_http_methods() -> None:
    asset_map = generate_large_asset_map(1000)

    assert len(_endpoints(asset_map)) == 1000
    assert _methods(asset_map) == {"GET", "POST", "PUT", "DELETE"}
