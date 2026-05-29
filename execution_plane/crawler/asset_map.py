from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Literal, cast

_NUMERIC_SEGMENT_RE = re.compile(r"/\d+(?=/|$)")
_UUID_SEGMENT_RE = re.compile(
    r"/[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}(?=/|$)"
)
_EXPRESS_PARAMETER_RE = re.compile(r"(?<=/):([A-Za-z_][A-Za-z0-9_]*)(?=/|$)")
_RAILS_PARAMETER_RE = re.compile(r"<[A-Za-z_][A-Za-z0-9_]*:([A-Za-z_][A-Za-z0-9_]*)>")
EndpointSource = Literal[
    "crawler",
    "har",
    "openapi",
    "js",
    "wordlist",
    "manual",
    "code_extractor",
    "gateway_log",
]
_ALLOWED_SOURCES: set[str] = {
    "crawler",
    "har",
    "openapi",
    "js",
    "wordlist",
    "manual",
    "code_extractor",
    "gateway_log",
}
_SOURCE_ALIASES: dict[str, EndpointSource] = {
    "crawler": "crawler",
    "code_extractor": "code_extractor",
    "gateway": "gateway_log",
    "gateway_log": "gateway_log",
    "har": "har",
    "openapi": "openapi",
    "js": "js",
    "javascript": "js",
    "sourcemap": "js",
    "wordlist": "wordlist",
    "manual": "manual",
}


def normalize_url_pattern(url: str) -> str:
    normalized = _NUMERIC_SEGMENT_RE.sub("/{id}", url)
    normalized = _UUID_SEGMENT_RE.sub("/{id}", normalized)
    normalized = _EXPRESS_PARAMETER_RE.sub(r"{\1}", normalized)
    normalized = _RAILS_PARAMETER_RE.sub(r"{\1}", normalized)
    if normalized != "/":
        normalized = normalized.rstrip("/")
    return normalized


def normalize_graphql_operation(path: str, operation_name: str) -> str:
    return f"{path}##{operation_name}"


@dataclass(slots=True, frozen=True)
class Parameter:
    name: str
    location: str
    type: str


@dataclass(slots=True)
class Endpoint:
    url_pattern: str
    method: str
    in_scope: bool
    auth_required: bool
    source: list[EndpointSource] = field(default_factory=lambda: ["crawler"])
    parameters: list[dict[str, str]] = field(default_factory=list)
    observed_content_type: str | None = None
    example_response_code: int | None = None
    graphql_operation: str | None = None

    def __post_init__(self) -> None:
        if isinstance(self.source, str):
            self.source = [self.source]


@dataclass(slots=True)
class AssetMap:
    endpoints: list[Endpoint] = field(default_factory=list)

    def deduplicate_endpoints(self) -> None:
        deduplicated: list[Endpoint] = []
        seen_signatures: dict[tuple[str, str, str | None], Endpoint] = {}
        for endpoint in self.endpoints:
            sources = endpoint.source if isinstance(endpoint.source, list) else [endpoint.source]
            signature = (
                normalize_url_pattern(endpoint.url_pattern),
                endpoint.method.upper(),
                endpoint.graphql_operation,
            )
            existing = seen_signatures.get(signature)
            if existing is not None:
                for source in sources:
                    if source not in existing.source:
                        existing.source.append(source)
                continue
            endpoint.url_pattern = signature[0]
            endpoint.method = signature[1]
            endpoint.source = list(sources)
            seen_signatures[signature] = endpoint
            deduplicated.append(endpoint)
        self.endpoints = deduplicated

    def source_summary(self) -> dict[str, int]:
        summary: dict[str, int] = {}
        for endpoint in self.endpoints:
            sources = endpoint.source if isinstance(endpoint.source, list) else [endpoint.source]
            primary_source = sources[0] if sources else "manual"
            summary[primary_source] = summary.get(primary_source, 0) + 1
        return summary


class AssetMapBuilder:
    def __init__(self) -> None:
        self._endpoints: dict[tuple[str, str] | tuple[str, str, str], Endpoint] = {}

    def normalize_url_pattern(self, url: str) -> str:
        return normalize_url_pattern(url)

    def normalize_source(self, source: str | None) -> EndpointSource:
        if source is None:
            return "crawler"
        candidate = source.strip().lower()
        resolved = _SOURCE_ALIASES.get(candidate)
        if resolved is not None:
            return resolved
        if candidate in _ALLOWED_SOURCES:
            return cast(EndpointSource, candidate)
        return "manual"

    def add_endpoint(
        self,
        url: str,
        method: str,
        auth_required: bool,
        parameters: list[dict[str, str]],
        in_scope: bool = True,
        source: str | None = None,
        observed_content_type: str | None = None,
        example_response_code: int | None = None,
        graphql_operation: str | None = None,
    ) -> None:
        normalized = self.normalize_url_pattern(url)
        normalized_source = self.normalize_source(source)
        normalized_method = method.upper()
        key: tuple[str, str] | tuple[str, str, str]
        if graphql_operation is None:
            key = (normalized, normalized_method)
        else:
            key = (normalized, normalized_method, graphql_operation)
        existing = self._endpoints.get(key)
        if existing is None:
            self._endpoints[key] = Endpoint(
                url_pattern=normalized,
                method=normalized_method,
                in_scope=in_scope,
                auth_required=auth_required,
                source=[normalized_source],
                parameters=list(parameters),
                observed_content_type=observed_content_type,
                example_response_code=example_response_code,
                graphql_operation=graphql_operation,
            )
            return

        existing.in_scope = existing.in_scope or in_scope
        existing.auth_required = existing.auth_required or auth_required
        if normalized_source not in existing.source:
            existing.source.append(normalized_source)
        existing.example_response_code = existing.example_response_code or example_response_code
        if existing.observed_content_type is None and observed_content_type is not None:
            existing.observed_content_type = observed_content_type

        seen_params = {(p.get("name"), p.get("location"), p.get("type")) for p in existing.parameters}
        for param in parameters:
            identifier = (param.get("name"), param.get("location"), param.get("type"))
            if identifier in seen_params:
                continue
            existing.parameters.append(param)
            seen_params.add(identifier)

    def build(self) -> AssetMap:
        asset_map = AssetMap(endpoints=list(self._endpoints.values()))
        asset_map.deduplicate_endpoints()
        return asset_map
