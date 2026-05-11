from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import urlparse

_GRAPHQL_PATHS: tuple[str, ...] = ("/graphql", "/api/graphql", "/gql")
_GRAPHQL_CONTENT_TYPE_MARKERS: tuple[str, ...] = ("application/graphql", "application/graphql-response+json")
_JS_GRAPHQL_HINT_RE = re.compile(
    r"""(?:apolloClient|graphqlEndpoint|gqlUrl)\s*[:=]\s*(['\"])(?P<value>/[^'\"]*graphql[^'\"]*|/gql|https?://[^'\"]+)\1""",
    re.IGNORECASE,
)
_JS_ENDPOINT_LITERAL_RE = re.compile(r"""(['\"])(?P<value>/[^'\"]*(?:graphql|gql)[^'\"]*)\1""", re.IGNORECASE)


def is_graphql_endpoint(url: str, observed_content_type: str | None = None) -> bool:
    parsed_path = urlparse(url).path.lower() if "://" in url else url.lower()
    normalized_path = parsed_path.rstrip("/") or "/"
    if normalized_path in _GRAPHQL_PATHS:
        return True

    if observed_content_type:
        lowered = observed_content_type.lower()
        if any(marker in lowered for marker in _GRAPHQL_CONTENT_TYPE_MARKERS):
            return True

    return False


def discover_graphql_endpoints_from_js(js_bundle: str) -> list[str]:
    discovered: list[str] = []
    seen: set[str] = set()

    for matcher in (_JS_GRAPHQL_HINT_RE, _JS_ENDPOINT_LITERAL_RE):
        for match in matcher.finditer(js_bundle):
            value = match.groupdict().get("value")
            if not isinstance(value, str):
                continue
            endpoint = value.strip()
            if not endpoint:
                continue
            if not any(marker in endpoint.lower() for marker in ("graphql", "/gql")):
                continue
            if endpoint in seen:
                continue
            seen.add(endpoint)
            discovered.append(endpoint)

    return discovered


def extract_schema_from_introspection(payload: dict[str, Any]) -> dict[str, dict[str, dict[str, str]]]:
    schema_root = _resolve_schema_root(payload)
    if not isinstance(schema_root, dict):
        return {}

    types = schema_root.get("types")
    if not isinstance(types, list):
        return {}

    extracted: dict[str, dict[str, dict[str, str]]] = {}
    for entry in types:
        if not isinstance(entry, dict):
            continue
        type_name_raw = entry.get("name")
        if not isinstance(type_name_raw, str):
            continue
        type_name = type_name_raw.strip()
        if not type_name or type_name.startswith("__"):
            continue

        fields = entry.get("fields")
        if not isinstance(fields, list):
            extracted.setdefault(type_name, {})
            continue

        typed_fields: dict[str, dict[str, str]] = {}
        for field in fields:
            if not isinstance(field, dict):
                continue
            field_name_raw = field.get("name")
            if not isinstance(field_name_raw, str):
                continue
            field_name = field_name_raw.strip()
            if not field_name:
                continue

            args_map: dict[str, str] = {}
            args = field.get("args")
            if isinstance(args, list):
                for argument in args:
                    if not isinstance(argument, dict):
                        continue
                    arg_name_raw = argument.get("name")
                    if not isinstance(arg_name_raw, str):
                        continue
                    arg_name = arg_name_raw.strip()
                    if not arg_name:
                        continue
                    arg_type = _resolve_graphql_type_name(argument.get("type"))
                    args_map[arg_name] = arg_type or "unknown"

            typed_fields[field_name] = args_map

        extracted[type_name] = typed_fields

    return extracted


def mark_asset_map_graphql(asset_map: Any) -> None:
    endpoints = getattr(asset_map, "endpoints", None)
    if not isinstance(endpoints, list):
        return

    graphql_endpoints: list[str] = []
    for endpoint in endpoints:
        url_pattern = str(getattr(endpoint, "url_pattern", "") or "")
        content_type = getattr(endpoint, "observed_content_type", None)
        if not is_graphql_endpoint(url_pattern, content_type):
            continue

        if url_pattern not in graphql_endpoints:
            graphql_endpoints.append(url_pattern)

        raw_parameters = getattr(endpoint, "parameters", [])
        parameters = raw_parameters if isinstance(raw_parameters, list) else []
        marker_exists = any(
            isinstance(parameter, dict)
            and str(parameter.get("name", "")).lower() == "graphql"
            and str(parameter.get("location") or parameter.get("in") or "").lower() == "meta"
            for parameter in parameters
        )
        if not marker_exists:
            parameters.append(
                {
                    "name": "graphql",
                    "location": "meta",
                    "type": "boolean",
                    "value": "true",
                }
            )
        endpoint.parameters = parameters

    raw_signals = getattr(asset_map, "signals", None)
    signals = raw_signals if isinstance(raw_signals, dict) else {}
    existing = signals.get("graphql_endpoints")
    known = existing if isinstance(existing, list) else []
    merged = list(dict.fromkeys([*known, *graphql_endpoints]))
    if merged:
        signals["graphql_endpoints"] = merged
        signals["graphql"] = True
        asset_map.signals = signals


def _resolve_schema_root(payload: dict[str, Any]) -> dict[str, Any] | None:
    data = payload.get("data")
    if not isinstance(data, dict):
        return None

    schema = data.get("__schema")
    if isinstance(schema, dict):
        return schema

    type_payload = data.get("__type")
    if isinstance(type_payload, dict):
        synthetic_schema = {
            "types": [
                {
                    "name": type_payload.get("name") or "Query",
                    "fields": type_payload.get("fields") if isinstance(type_payload.get("fields"), list) else [],
                }
            ]
        }
        return synthetic_schema

    return None


def _resolve_graphql_type_name(type_node: Any) -> str | None:
    current = type_node
    while isinstance(current, dict):
        name = current.get("name")
        if isinstance(name, str) and name.strip():
            return name.strip()
        current = current.get("ofType")
    return None
