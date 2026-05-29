from __future__ import annotations

from collections import deque
from datetime import UTC, datetime
from dataclasses import dataclass
from types import ModuleType
from types import SimpleNamespace
import sys
from uuid import uuid4

import pytest

from execution_plane.crawler.asset_map import AssetMapBuilder, Endpoint, Parameter, normalize_graphql_operation

auth_manager_module = ModuleType("control_plane.auth_manager")


@dataclass(slots=True)
class _SessionSnapshot:
    scan_id: object
    cookies: list[dict[str, object]]
    auth_headers: dict[str, str]
    csrf_tokens: dict[str, str]
    captured_at: datetime
    expires_at: datetime | None


auth_manager_module.SessionSnapshot = _SessionSnapshot
sys.modules.setdefault("control_plane.auth_manager", auth_manager_module)

from execution_plane.crawler.engine import CrawlerReconEngine


def _build_engine(scope_domains: list[str]) -> CrawlerReconEngine:
    snapshot = SimpleNamespace(
        scan_id=uuid4(),
        cookies=[],
        auth_headers={},
        csrf_tokens={},
        captured_at=datetime.now(UTC),
        expires_at=None,
    )
    return CrawlerReconEngine(
        session_snapshot=snapshot,
        target_url="https://app.example.com",
        scope_domains=scope_domains,
    )


def test_normalize_url_pattern_replaces_numeric_segment() -> None:
    builder = AssetMapBuilder()

    normalized = builder.normalize_url_pattern("/api/users/123")

    assert normalized == "/api/users/{id}"


def test_normalize_url_pattern_rewrites_framework_parameters_and_strips_trailing_slash() -> None:
    builder = AssetMapBuilder()

    assert builder.normalize_url_pattern("/api/users/:user_id/orders/:order_id/") == (
        "/api/users/{user_id}/orders/{order_id}"
    )
    assert builder.normalize_url_pattern("/api/users/<int:user_id>/") == "/api/users/{user_id}"
    assert builder.normalize_url_pattern("/") == "/"


def test_normalize_graphql_operation_appends_operation_name() -> None:
    assert normalize_graphql_operation("/graphql", "GetUser") == "/graphql##GetUser"


def test_add_endpoint_and_build_merges_duplicates_and_auth_required() -> None:
    builder = AssetMapBuilder()

    builder.add_endpoint(
        url="/api/users/123",
        method="get",
        auth_required=False,
        parameters=[{"name": "limit", "location": "query", "type": "integer"}],
        observed_content_type=None,
        example_response_code=None,
    )
    builder.add_endpoint(
        url="/api/users/456",
        method="GET",
        auth_required=True,
        parameters=[
            {"name": "limit", "location": "query", "type": "integer"},
            {"name": "include", "location": "query", "type": "string"},
        ],
        observed_content_type="application/json",
        example_response_code=200,
    )

    asset_map = builder.build()

    assert len(asset_map.endpoints) == 1
    endpoint = asset_map.endpoints[0]
    assert endpoint.url_pattern == "/api/users/{id}"
    assert endpoint.method == "GET"
    assert endpoint.in_scope is True
    assert endpoint.auth_required is True
    assert endpoint.source == ["crawler"]
    assert endpoint.observed_content_type == "application/json"
    assert endpoint.example_response_code == 200
    assert endpoint.parameters == [
        {"name": "limit", "location": "query", "type": "integer"},
        {"name": "include", "location": "query", "type": "string"},
    ]


def test_add_endpoint_accepts_new_sources_and_aliases() -> None:
    builder = AssetMapBuilder()

    builder.add_endpoint(
        url="/internal/users",
        method="GET",
        auth_required=True,
        parameters=[],
        source="code_extractor",
    )
    builder.add_endpoint(
        url="/gateway/users",
        method="GET",
        auth_required=True,
        parameters=[],
        source="gateway",
    )
    builder.add_endpoint(
        url="/gateway/events",
        method="GET",
        auth_required=True,
        parameters=[],
        source="gateway_log",
    )

    asset_map = builder.build()
    indexed = {endpoint.url_pattern: endpoint for endpoint in asset_map.endpoints}

    assert indexed["/internal/users"].source == ["code_extractor"]
    assert indexed["/gateway/users"].source == ["gateway_log"]
    assert indexed["/gateway/events"].source == ["gateway_log"]


def test_add_endpoint_tracks_all_discovery_sources_for_same_endpoint() -> None:
    builder = AssetMapBuilder()

    builder.add_endpoint(
        url="/api/users/:user_id/",
        method="GET",
        auth_required=False,
        parameters=[],
        source="crawler",
    )
    builder.add_endpoint(
        url="/api/users/:user_id",
        method="get",
        auth_required=False,
        parameters=[],
        source="gateway_log",
    )
    builder.add_endpoint(
        url="/api/users/<int:user_id>",
        method="GET",
        auth_required=False,
        parameters=[],
        source="gateway",
    )

    asset_map = builder.build()

    assert len(asset_map.endpoints) == 1
    assert asset_map.endpoints[0].source == ["crawler", "gateway_log"]


def test_asset_map_source_summary_counts_primary_source_per_unique_endpoint() -> None:
    builder = AssetMapBuilder()

    builder.add_endpoint("/api/users", "GET", False, [], source="crawler")
    builder.add_endpoint("/api/users", "GET", False, [], source="gateway_log")
    builder.add_endpoint("/api/teams", "GET", False, [], source="gateway")
    builder.add_endpoint("/api/projects", "GET", False, [], source="code_extractor")

    asset_map = builder.build()

    assert asset_map.source_summary() == {"crawler": 1, "gateway_log": 1, "code_extractor": 1}


def test_graphql_operation_is_part_of_dedup_key() -> None:
    builder = AssetMapBuilder()

    builder.add_endpoint(
        url="/graphql",
        method="POST",
        auth_required=True,
        parameters=[],
        source="crawler",
        graphql_operation="GetUser",
    )
    builder.add_endpoint(
        url="/graphql",
        method="POST",
        auth_required=True,
        parameters=[],
        source="gateway_log",
        graphql_operation="GetUser",
    )
    builder.add_endpoint(
        url="/graphql",
        method="POST",
        auth_required=True,
        parameters=[],
        source="code_extractor",
        graphql_operation="UpdateUser",
    )

    asset_map = builder.build()

    endpoint_signatures = {
        (endpoint.url_pattern, endpoint.method, endpoint.graphql_operation)
        for endpoint in asset_map.endpoints
    }
    assert endpoint_signatures == {
        ("/graphql", "POST", "GetUser"),
        ("/graphql", "POST", "UpdateUser"),
    }
    get_user = next(
        endpoint for endpoint in asset_map.endpoints if endpoint.graphql_operation == "GetUser"
    )
    assert get_user.source == ["crawler", "gateway_log"]


@pytest.mark.asyncio
async def test_extract_discovered_links_keeps_only_in_scope_links() -> None:
    engine = _build_engine(["example.com"])

    class _FakePage:
        url = "https://app.example.com/home"

        async def eval_on_selector_all(self, selector: str, expression: str) -> list[object]:
            assert selector == "a[href]"
            assert "elements.flatMap" in expression
            return [
                "https://app.example.com/dashboard",
                "/relative/path",
                "https://api.example.com/v1/users",
                "https://evil.example.net/phish",
                "not-a-url",
                7,
            ]

    discovered_links = await engine._extract_discovered_links(_FakePage())

    assert discovered_links == [
        "https://app.example.com/dashboard",
        "https://app.example.com/relative/path",
        "https://api.example.com/v1/users",
        "https://app.example.com/not-a-url",
    ]


def test_parameter_dataclass_fields() -> None:
    parameter = Parameter(name="user_id", location="path", type="integer")

    assert parameter.name == "user_id"
    assert parameter.location == "path"
    assert parameter.type == "integer"


def test_enqueue_discovered_link_ignores_out_of_scope() -> None:
    engine = _build_engine(["example.com"])
    to_visit: deque[str] = deque(["https://app.example.com"])
    visited = {"https://app.example.com"}

    engine._enqueue_discovered_link("https://evil.example.net/phish", to_visit=to_visit, visited=visited)
    engine._enqueue_discovered_link("https://api.example.com/v1/users", to_visit=to_visit, visited=visited)

    assert list(to_visit) == ["https://app.example.com", "https://api.example.com/v1/users"]

    asset_map = engine._asset_map_builder.build()
    indexed = {(endpoint.url_pattern, endpoint.method): endpoint for endpoint in asset_map.endpoints}
    assert indexed[("https://api.example.com/v1/users", "GET")].in_scope is True


def test_extract_js_fetch_urls_captures_fetch_axios_and_xhr() -> None:
    engine = _build_engine(["example.com"])
    js_content = """
    fetch('/api/users');
    axios.get("/api/teams");
    axios('/api/projects');
    const req = new XMLHttpRequest();
    req.open('POST', '/api/forms');
    """

    discovered = engine._extract_js_fetch_urls(js_content)

    assert discovered == ["/api/users", "/api/teams", "/api/projects", "/api/forms"]


def test_extract_form_endpoints_returns_url_and_method() -> None:
    engine = _build_engine(["example.com"])
    html_content = """
    <form action="/api/users" method="post"></form>
    <form action="/api/profile"></form>
    <form method="delete" action="/api/sessions"></form>
    """

    endpoints = engine._extract_form_endpoints(html_content)

    assert endpoints == [
        {"url": "/api/users", "method": "POST"},
        {"url": "/api/profile", "method": "GET"},
        {"url": "/api/sessions", "method": "DELETE"},
    ]


def test_asset_map_deduplicate_endpoints_keeps_first_signature() -> None:
    builder = AssetMapBuilder()
    asset_map = builder.build()
    asset_map.endpoints = [
        Endpoint(
            url_pattern="/users/123/posts/456",
            method="get",
            in_scope=True,
            auth_required=False,
            parameters=[],
        ),
        Endpoint(
            url_pattern="/users/999/posts/111",
            method="GET",
            in_scope=True,
            auth_required=False,
            source=["gateway_log"],
            parameters=[],
        ),
        Endpoint(
            url_pattern="/users/123/posts/456",
            method="POST",
            in_scope=True,
            auth_required=False,
            parameters=[],
        ),
    ]

    asset_map.deduplicate_endpoints()

    assert [(endpoint.url_pattern, endpoint.method) for endpoint in asset_map.endpoints] == [
        ("/users/{id}/posts/{id}", "GET"),
        ("/users/{id}/posts/{id}", "POST"),
    ]
    assert asset_map.endpoints[0].source == ["crawler", "gateway_log"]
