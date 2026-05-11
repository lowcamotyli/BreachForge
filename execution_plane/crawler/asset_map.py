from __future__ import annotations

import re
from dataclasses import dataclass, field

_NUMERIC_SEGMENT_RE = re.compile(r"/\d+(?=/|$)")
_UUID_SEGMENT_RE = re.compile(
    r"/[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}(?=/|$)"
)


def normalize_url_pattern(url: str) -> str:
    normalized = _NUMERIC_SEGMENT_RE.sub("/{id}", url)
    normalized = _UUID_SEGMENT_RE.sub("/{id}", normalized)
    return normalized


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
    source: str | None = None
    parameters: list[dict[str, str]] = field(default_factory=list)
    observed_content_type: str | None = None
    example_response_code: int | None = None


@dataclass(slots=True)
class AssetMap:
    endpoints: list[Endpoint] = field(default_factory=list)

    def deduplicate_endpoints(self) -> None:
        deduplicated: list[Endpoint] = []
        seen_signatures: set[tuple[str, str]] = set()
        for endpoint in self.endpoints:
            signature = (normalize_url_pattern(endpoint.url_pattern), endpoint.method.upper())
            if signature in seen_signatures:
                continue
            seen_signatures.add(signature)
            endpoint.url_pattern = signature[0]
            endpoint.method = signature[1]
            deduplicated.append(endpoint)
        self.endpoints = deduplicated


class AssetMapBuilder:
    def __init__(self) -> None:
        self._endpoints: dict[tuple[str, str], Endpoint] = {}

    def normalize_url_pattern(self, url: str) -> str:
        return normalize_url_pattern(url)

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
    ) -> None:
        normalized = self.normalize_url_pattern(url)
        key = (normalized, method.upper())
        existing = self._endpoints.get(key)
        if existing is None:
            self._endpoints[key] = Endpoint(
                url_pattern=normalized,
                method=method.upper(),
                in_scope=in_scope,
                auth_required=auth_required,
                source=source,
                parameters=list(parameters),
                observed_content_type=observed_content_type,
                example_response_code=example_response_code,
            )
            return

        existing.in_scope = existing.in_scope or in_scope
        existing.auth_required = existing.auth_required or auth_required
        if existing.source is None and source is not None:
            existing.source = source
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
