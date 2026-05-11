from __future__ import annotations

from uuid import uuid4

from execution_plane.crawler.graphql_parser import (
    discover_graphql_endpoints_from_js,
    extract_schema_from_introspection,
    is_graphql_endpoint,
    mark_asset_map_graphql,
)
from storage.db.models import AssetMap, Endpoint


def _endpoint(url: str, content_type: str | None = None) -> Endpoint:
    return Endpoint(
        id=uuid4(),
        asset_map_id=uuid4(),
        url_pattern=url,
        method="POST",
        auth_required=False,
        parameters=[],
        observed_content_type=content_type,
        example_response_code=200,
    )


def test_detects_graphql_paths_and_content_type() -> None:
    assert is_graphql_endpoint("/graphql") is True
    assert is_graphql_endpoint("https://example.test/api/graphql") is True
    assert is_graphql_endpoint("/v1/query", "application/graphql") is True
    assert is_graphql_endpoint("/api/users", "application/json") is False


def test_marks_graphql_endpoints_in_asset_map_and_signals() -> None:
    graphql_endpoint = _endpoint("/graphql")
    rest_endpoint = _endpoint("/api/users")
    asset_map = AssetMap(scan_id=uuid4())
    asset_map.endpoints = [graphql_endpoint, rest_endpoint]

    mark_asset_map_graphql(asset_map)

    graphql_markers = [
        parameter
        for parameter in graphql_endpoint.parameters
        if parameter.get("name") == "graphql" and parameter.get("location") == "meta"
    ]
    assert graphql_markers
    assert getattr(asset_map, "signals")["graphql"] is True
    assert "/graphql" in getattr(asset_map, "signals")["graphql_endpoints"]


def test_extracts_schema_types_fields_and_args() -> None:
    payload = {
        "data": {
            "__schema": {
                "types": [
                    {
                        "name": "Query",
                        "fields": [
                            {
                                "name": "user",
                                "args": [
                                    {
                                        "name": "id",
                                        "type": {
                                            "kind": "NON_NULL",
                                            "name": None,
                                            "ofType": {"kind": "SCALAR", "name": "ID", "ofType": None},
                                        },
                                    }
                                ],
                            }
                        ],
                    }
                ]
            }
        }
    }

    schema = extract_schema_from_introspection(payload)

    assert schema == {"Query": {"user": {"id": "ID"}}}


def test_discovers_graphql_endpoints_in_js_bundle() -> None:
    js_bundle = """
    const apolloClient = '/graphql';
    window.graphqlEndpoint = '/api/graphql';
    const gqlUrl = '/gql';
    const fallback = '/api/v2/graphql-public';
    """

    discovered = discover_graphql_endpoints_from_js(js_bundle)

    assert discovered == ["/graphql", "/api/graphql", "/gql", "/api/v2/graphql-public"]
