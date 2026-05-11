from __future__ import annotations

import json
import math
import re
from urllib.parse import urljoin, urlparse

import httpx


class JsEndpointExtractor:
    _FETCH_AXIOS_RE = re.compile(
        r"""(?:fetch|axios\.(?:get|post|put|delete|patch|request))\s*\(\s*["`'"]\s*(/[^"`'"]{2,})["`'"]"""
    )
    _PATH_LITERAL_RE = re.compile(
        r"""["`'"](\s*/(?:api|v\d+|admin|internal|graphql|auth|users|accounts|settings|health)[/\w\-\.]*)["`'"]"""
    )
    _BASE_URL_RE = re.compile(
        r"""(?:baseURL|apiBase|API_URL|BASE_URL|apiUrl|base_url)\s*[=:]\s*["`'"](https?://[^"`'"]+|/[^"`'"]+)["`'"]"""
    )
    _EXCLUDED_EXTENSIONS = {
        ".js",
        ".css",
        ".png",
        ".html",
        ".svg",
        ".ico",
        ".woff",
        ".woff2",
        ".map",
        ".jpg",
        ".jpeg",
        ".gif",
        ".ttf",
        ".eot",
    }
    _SOURCEMAP_ROUTE_HINT_RE = re.compile(
        r"""(?:(?:^|/)(?:api|route|routes?|endpoint|endpoints?|v1|v2|v3)(?:/|$)|(?:^|/)[\w\-]+controller(?:/|$))""",
        re.IGNORECASE,
    )
    _SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
        (
            "api_key",
            re.compile(
                r"""[aA][pP][iI][_-]?[kK][eE][yY][^a-zA-Z0-9]['"=: ]+([a-zA-Z0-9_\-]{20,})"""
            ),
        ),
        (
            "token",
            re.compile(r"""[tT][oO][kK][eE][nN][^a-zA-Z0-9]['"=: ]+([a-zA-Z0-9_\-\.]{20,})"""),
        ),
        (
            "password",
            re.compile(
                r"""[pP][aA][sS][sS][wW][oO][rR][dD][^a-zA-Z0-9]['"=: ]+([a-zA-Z0-9_\-!@#]{8,})"""
            ),
        ),
        ("aws_key", re.compile(r"""(AKIA[0-9A-Z]{16})""")),
        ("bearer", re.compile(r"""([bB]earer [a-zA-Z0-9\-_\.]{20,})""")),
        ("private_key", re.compile(r"""(-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----)""")),
    )

    def extract(self, js_content: str) -> list[str]:
        results: list[str] = []
        seen: set[str] = set()

        for pattern in (self._FETCH_AXIOS_RE, self._PATH_LITERAL_RE, self._BASE_URL_RE):
            for match in pattern.findall(js_content):
                value = match.strip()
                if not value.startswith(("/", "http://", "https://")):
                    continue
                lowered = value.lower()
                if lowered.endswith(".json") and "/api/" not in lowered and "/swagger" not in lowered:
                    continue
                if any(lowered.endswith(ext) for ext in self._EXCLUDED_EXTENSIONS):
                    continue
                if value in seen:
                    continue
                seen.add(value)
                results.append(value)
                if len(results) >= 200:
                    return results

        return results

    def extract_secrets(self, js_content: str, source_url: str) -> list[dict]:
        findings: list[dict] = []
        seen: set[tuple[str, str]] = set()

        for secret_type, pattern in self._SECRET_PATTERNS:
            for match in pattern.finditer(js_content):
                value = match.group(1).strip()
                entropy = self._shannon_entropy(value)
                if entropy > 3.5:
                    confidence = 0.90
                elif entropy >= 2.5:
                    confidence = 0.85
                else:
                    continue
                if confidence < 0.85:
                    continue
                redacted_value = f"{value[:8]}..."
                dedup_key = (secret_type, redacted_value)
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)
                findings.append(
                    {
                        "secret_type": secret_type,
                        "redacted_value": redacted_value,
                        "confidence": confidence,
                        "source_url": source_url,
                        "finding_type": "js_secret",
                    }
                )

        return findings

    def _shannon_entropy(self, value: str) -> float:
        if not value:
            return 0.0
        counts: dict[str, int] = {}
        for char in value:
            counts[char] = counts.get(char, 0) + 1
        length = len(value)
        entropy = 0.0
        for count in counts.values():
            probability = count / length
            entropy -= probability * math.log2(probability)
        return entropy

    async def extract_from_sourcemap(self, sourcemap_url: str, base_url: str) -> list[str]:
        try:
            async with httpx.AsyncClient(timeout=5.0, follow_redirects=True) as client:
                response = await client.get(sourcemap_url)
        except Exception:
            return []
        if response.status_code != 200:
            return []

        try:
            payload = json.loads(response.text)
        except Exception:
            return []
        if not isinstance(payload, dict):
            return []

        sources = payload.get("sources")
        if not isinstance(sources, list):
            return []

        results: list[str] = []
        seen: set[str] = set()
        for source in sources:
            if not isinstance(source, str):
                continue
            candidate = source.strip()
            if not candidate:
                continue

            normalized = candidate.replace("\\", "/")
            lowered = normalized.lower()
            if "/" not in normalized and not any(
                token in lowered for token in ("api", "route", "endpoint", "v1", "v2", "v3", "controller")
            ):
                continue
            if self._SOURCEMAP_ROUTE_HINT_RE.search(normalized) is None and not any(
                token in lowered for token in ("api", "route", "endpoint", "v1", "v2", "v3", "controller")
            ):
                continue

            parsed = urlparse(normalized)
            path_value = parsed.path if parsed.path else normalized
            if not path_value.startswith(("/", "http://", "https://")) and "/" in path_value:
                path_value = f"/{path_value.lstrip('/')}"
            resolved = urljoin(base_url, path_value)
            extracted_hint = urlparse(resolved).path or path_value
            if not extracted_hint.startswith("/"):
                extracted_hint = f"/{extracted_hint.lstrip('/')}"
            if extracted_hint in seen:
                continue
            seen.add(extracted_hint)
            results.append(extracted_hint)

        return results
