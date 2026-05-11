from __future__ import annotations

import os

from execution_plane.crawler.asset_map import AssetMap, Endpoint

_ALLOWED_METHODS: frozenset[str] = frozenset({"GET", "HEAD", "OPTIONS"})
_PRIORITY_KEYWORDS: tuple[str, ...] = (
    "/me",
    "/profile",
    "/user",
    "/account",
    "/settings",
    "/appointments",
    "/admin",
)
_DEFAULT_MAX_PROBES = 8
_MIN_MAX_PROBES = 1
_MAX_MAX_PROBES = 20


class BlastRadiusSelector:
    def __init__(self, asset_map: AssetMap, source_endpoint_pattern: str | None = None) -> None:
        self._asset_map = asset_map
        self._source_endpoint_pattern = source_endpoint_pattern

    def select(self) -> list[dict[str, object]]:
        max_probes = self._resolve_max_probes()
        candidates = self._deduplicated_candidates()

        ranked = [
            {
                "url_pattern": endpoint.url_pattern,
                "method": endpoint.method.upper(),
                "priority_rank": self._priority_rank(endpoint),
            }
            for endpoint in candidates
        ]
        ranked.sort(
            key=lambda item: (
                int(item["priority_rank"]),
                str(item["url_pattern"]),
                str(item["method"]),
            )
        )
        return ranked[:max_probes]

    def _deduplicated_candidates(self) -> list[Endpoint]:
        deduplicated: list[Endpoint] = []
        seen: set[tuple[str, str]] = set()

        for endpoint in self._asset_map.endpoints:
            method = endpoint.method.upper()
            if method not in _ALLOWED_METHODS:
                continue
            if not endpoint.in_scope:
                continue

            signature = (endpoint.url_pattern, method)
            if signature in seen:
                continue

            seen.add(signature)
            deduplicated.append(endpoint)

        return deduplicated

    def _priority_rank(self, endpoint: Endpoint) -> int:
        if self._source_endpoint_pattern is not None and endpoint.url_pattern == self._source_endpoint_pattern:
            return 0

        lowered_url_pattern = endpoint.url_pattern.lower()
        if any(keyword in lowered_url_pattern for keyword in _PRIORITY_KEYWORDS):
            return 1

        if endpoint.auth_required:
            return 2

        return 3

    def _resolve_max_probes(self) -> int:
        raw_value = os.environ.get("SECRET_BLAST_RADIUS_MAX_PROBES")
        if raw_value is None:
            return _DEFAULT_MAX_PROBES

        try:
            parsed = int(raw_value)
        except ValueError:
            return _DEFAULT_MAX_PROBES

        if parsed < _MIN_MAX_PROBES:
            return _MIN_MAX_PROBES
        if parsed > _MAX_MAX_PROBES:
            return _MAX_MAX_PROBES
        return parsed
