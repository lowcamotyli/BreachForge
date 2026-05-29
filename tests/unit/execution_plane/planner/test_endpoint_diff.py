from __future__ import annotations

from execution_plane.planner.endpoint_diff import (
    DiffAwarePlanner,
    EndpointDiff,
    infer_from_openapi_diff,
    infer_from_route_list_diff,
)


def test_openapi_added() -> None:
    old_spec = {"paths": {"/health": {"get": {}}}}
    new_spec = {"paths": {"/health": {"get": {}}, "/users": {"get": {}}}}
    diff = infer_from_openapi_diff(old_spec, new_spec)
    assert "/users" in diff.added


def test_openapi_removed() -> None:
    old_spec = {"paths": {"/health": {"get": {}}, "/users": {"get": {}}}}
    new_spec = {"paths": {"/health": {"get": {}}}}
    diff = infer_from_openapi_diff(old_spec, new_spec)
    assert "/users" in diff.removed


def test_route_list_diff_basic() -> None:
    old_routes = ["/a", "/b", "/c"]
    new_routes = ["/a", "/c", "/d"]
    diff = infer_from_route_list_diff(old_routes, new_routes)
    assert diff.added == ["/d"]
    assert diff.removed == ["/b"]
    assert diff.unchanged == ["/a", "/c"]
    assert diff.modified == []


def test_diff_planner_filters() -> None:
    diff = EndpointDiff(added=["/new"], modified=["/changed"], removed=[], unchanged=["/same"])
    planner = DiffAwarePlanner(diff)
    filtered = planner.filter_endpoints(["/new", "/changed", "/same", "/other"])
    assert filtered == ["/new", "/changed"]

    no_change_planner = DiffAwarePlanner(
        EndpointDiff(added=[], modified=[], removed=[], unchanged=["/same"])
    )
    endpoints = ["/one", "/two"]
    assert no_change_planner.filter_endpoints(endpoints) == endpoints
