from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import aiofiles
import yaml


def score_ownership_confidence(owner_source: str, path_segment_count: int, confirming_sources: int = 0) -> float:
    base_scores = {
        "manual": 1.0,
        "openapi": 0.9,
        "codeowners": 0.7,
        "service_catalog": 0.5,
        "heuristic": 0.3,
        "unknown": 0.0,
    }
    total = base_scores.get(owner_source, 0.0)

    if confirming_sources > 1:
        total += 0.05 * (confirming_sources - 1)

    if path_segment_count > 4:
        total += 0.02

    return min(total, 1.0)


@dataclass(frozen=True)
class OwnerInfo:
    team: str
    service: str
    confidence: float
    source: str
    repo_hint: str | None = None


class OwnershipResolver:
    def __init__(self, project_root: Path | None = None) -> None:
        self.project_root = project_root or Path(__file__).resolve().parents[1]

    async def resolve(
        self,
        endpoint_url: str,
        openapi_spec: dict[str, Any] | None = None,
        manual_overrides: dict[str, Any] | None = None,
    ) -> OwnerInfo:
        repo_hint = self._derive_repo_hint(endpoint_url, openapi_spec)

        manual_owner = self._resolve_manual_override(endpoint_url, manual_overrides)
        if manual_owner is not None:
            return self._with_repo_hint(manual_owner, repo_hint)

        openapi_owner = self._resolve_openapi_owner(endpoint_url, openapi_spec)
        if openapi_owner is not None:
            return self._with_repo_hint(openapi_owner, repo_hint)

        codeowners_owner = await self._resolve_codeowners_owner(endpoint_url)
        if codeowners_owner is not None:
            return self._with_repo_hint(codeowners_owner, repo_hint)

        catalog_owner = await self._resolve_service_catalog_owner(endpoint_url)
        if catalog_owner is not None:
            return self._with_repo_hint(catalog_owner, repo_hint)

        return OwnerInfo(team="unknown", service="unknown", confidence=0.0, source="unknown", repo_hint=repo_hint)

    async def batch_resolve(
        self,
        endpoints: list[str],
        openapi_spec: dict[str, Any] | None = None,
        manual_overrides: dict[str, Any] | None = None,
    ) -> list[tuple[str, OwnerInfo]]:
        resolved = await asyncio.gather(
            *(self.resolve(endpoint, openapi_spec=openapi_spec, manual_overrides=manual_overrides) for endpoint in endpoints)
        )
        return list(zip(endpoints, resolved, strict=False))

    def _resolve_manual_override(self, endpoint_url: str, manual_overrides: dict[str, Any] | None) -> OwnerInfo | None:
        if not manual_overrides:
            return None

        endpoint_path = self._url_path(endpoint_url)
        matching_prefixes = [
            prefix
            for prefix in manual_overrides
            if endpoint_url.startswith(prefix) or endpoint_path.startswith(prefix)
        ]
        if not matching_prefixes:
            return None

        prefix = max(matching_prefixes, key=len)
        return self._owner_from_value(manual_overrides[prefix], confidence=1.0, source="manual")

    def _resolve_openapi_owner(self, endpoint_url: str, openapi_spec: dict[str, Any] | None) -> OwnerInfo | None:
        paths = (openapi_spec or {}).get("paths")
        if not isinstance(paths, dict):
            return None

        endpoint_path = self._url_path(endpoint_url)
        for path_pattern, path_item in paths.items():
            if not isinstance(path_pattern, str) or not isinstance(path_item, dict):
                continue
            if not self._path_matches(path_pattern, endpoint_path):
                continue
            owner_value = path_item.get("x-owner")
            if owner_value is None:
                continue
            return self._owner_from_value(owner_value, confidence=0.9, source="openapi")

        return None

    async def _resolve_codeowners_owner(self, endpoint_url: str) -> OwnerInfo | None:
        codeowners_path = self.project_root / "CODEOWNERS"
        if not await asyncio.to_thread(codeowners_path.is_file):
            return None

        try:
            async with aiofiles.open(codeowners_path, encoding="utf-8") as codeowners_file:
                contents = await codeowners_file.read()
        except OSError:
            return None

        endpoint_path = self._url_path(endpoint_url).lstrip("/")
        for raw_line in contents.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue

            parts = line.split()
            if len(parts) < 2:
                continue

            pattern = parts[0]
            owners = parts[1:]
            if not self._codeowners_pattern_matches(pattern, endpoint_path):
                continue

            owner = owners[0].lstrip("@")
            return OwnerInfo(team=owner, service=pattern, confidence=0.7, source="codeowners")

        return None

    async def _resolve_service_catalog_owner(self, endpoint_url: str) -> OwnerInfo | None:
        catalog_path = self.project_root / "service_catalog.yaml"
        if not await asyncio.to_thread(catalog_path.is_file):
            return None

        try:
            async with aiofiles.open(catalog_path, encoding="utf-8") as catalog_file:
                contents = await catalog_file.read()
        except OSError:
            return None

        try:
            catalog = yaml.safe_load(contents)
        except yaml.YAMLError:
            return None

        if not isinstance(catalog, dict):
            return None

        endpoint_path = self._url_path(endpoint_url)
        matching_keys = [
            key
            for key in catalog
            if isinstance(key, str) and (endpoint_url.startswith(key) or endpoint_path.startswith(key))
        ]
        if not matching_keys:
            return None

        key = max(matching_keys, key=len)
        return self._owner_from_value(catalog[key], confidence=0.5, source="service_catalog")

    def _owner_from_value(self, value: Any, confidence: float, source: str) -> OwnerInfo:
        if isinstance(value, OwnerInfo):
            return OwnerInfo(
                team=value.team,
                service=value.service,
                confidence=confidence,
                source=source,
                repo_hint=value.repo_hint,
            )

        if isinstance(value, dict):
            team = value.get("team") or value.get("owner") or "unknown"
            service = value.get("service") or value.get("name") or "unknown"
            return OwnerInfo(team=str(team), service=str(service), confidence=confidence, source=source)

        if isinstance(value, str):
            return OwnerInfo(team=value, service="unknown", confidence=confidence, source=source)

        return OwnerInfo(team="unknown", service="unknown", confidence=confidence, source=source)

    def _with_repo_hint(self, owner: OwnerInfo, repo_hint: str | None) -> OwnerInfo:
        return OwnerInfo(
            team=owner.team,
            service=owner.service,
            confidence=owner.confidence,
            source=owner.source,
            repo_hint=repo_hint,
        )

    def _derive_repo_hint(self, endpoint_url: str, openapi_spec: dict[str, Any] | None) -> str | None:
        openapi_repo_hint = self._extract_openapi_repo_hint(endpoint_url, openapi_spec)
        if openapi_repo_hint:
            return openapi_repo_hint

        endpoint_path = self._url_path(endpoint_url)
        match = re.search(r"/(?:api|v[0-9]+)/([^/?#]+)", endpoint_path)
        if match is None:
            return None

        candidate = match.group(1).strip()
        if not candidate:
            return None
        return candidate

    def _extract_openapi_repo_hint(self, endpoint_url: str, openapi_spec: dict[str, Any] | None) -> str | None:
        paths = (openapi_spec or {}).get("paths")
        if not isinstance(paths, dict):
            return None

        endpoint_path = self._url_path(endpoint_url)
        for path_pattern, path_item in paths.items():
            if not isinstance(path_pattern, str) or not isinstance(path_item, dict):
                continue
            if not self._path_matches(path_pattern, endpoint_path):
                continue

            owner_value = path_item.get("x-owner")
            if not isinstance(owner_value, dict):
                continue

            repo_value = owner_value.get("repo") or owner_value.get("repository")
            if isinstance(repo_value, str):
                cleaned = repo_value.strip()
                if cleaned:
                    return cleaned
        return None

    def _url_path(self, endpoint_url: str) -> str:
        parsed = urlparse(endpoint_url)
        if parsed.scheme or parsed.netloc:
            return parsed.path or "/"
        return endpoint_url or "/"

    def _path_matches(self, openapi_path: str, endpoint_path: str) -> bool:
        if openapi_path == endpoint_path:
            return True

        escaped = re.escape(openapi_path)
        templated = re.sub(r"\\\{[^/]+\\\}", r"[^/]+", escaped)
        return re.fullmatch(templated, endpoint_path) is not None

    def _codeowners_pattern_matches(self, pattern: str, endpoint_path: str) -> bool:
        normalized_pattern = pattern.lstrip("/")
        if normalized_pattern.endswith("/"):
            return endpoint_path.startswith(normalized_pattern)
        if "*" in normalized_pattern:
            regex = re.escape(normalized_pattern).replace(r"\*", ".*")
            return re.fullmatch(regex, endpoint_path) is not None
        return endpoint_path == normalized_pattern or endpoint_path.startswith(f"{normalized_pattern}/")
