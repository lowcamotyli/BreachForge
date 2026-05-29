from __future__ import annotations

import base64
import binascii
import json
import math
import re
from typing import Any, Literal, NotRequired, TypedDict
from urllib.parse import unquote, urljoin, urlparse

import httpx

_JS_SOURCE: Literal["JS"] = "JS"


class JsEndpoint(TypedDict):
    endpoint: str
    source: Literal["JS"]
    pattern: str
    method: NotRequired[str]
    operationName: NotRequired[str]


class JsSecretFinding(TypedDict):
    secret_type: str
    redacted_value: str
    confidence: float
    source_url: str
    finding_type: str


class JsEndpointExtractor:
    _MAX_RESULTS = 200
    _FETCH_AXIOS_RE = re.compile(
        r"""(?:fetch|axios\.(?:get|post|put|delete|patch|request))\s*\(\s*["`'"]\s*(/[^"`'"]{2,})["`'"]"""
    )
    _PATH_LITERAL_RE = re.compile(
        r"""["`'"](\s*/(?:api|v\d+|admin|internal|graphql|auth|users|accounts|settings|health)[/\w\-\.]*)["`'"]"""
    )
    _BASE_URL_RE = re.compile(
        r"""(?:baseURL|apiBase|API_URL|BASE_URL|apiUrl|base_url)\s*[=:]\s*["`'"](https?://[^"`'"]+|/[^"`'"]+)["`'"]"""
    )
    _FETCH_URL_ARGUMENT_RE = re.compile(
        r"""\bfetch\s*\(\s*(?P<quote>["'`])(?P<url>(?:https?://|/)[^"'`\s<>)]+)(?P=quote)""",
        re.IGNORECASE,
    )
    _AXIOS_URL_ARGUMENT_RE = re.compile(
        r"""\baxios(?:\.(?P<method>get|post|put|delete|patch|head|options|request))?\s*\(\s*(?P<quote>["'`])(?P<url>(?:https?://|/)[^"'`\s<>)]+)(?P=quote)""",
        re.IGNORECASE,
    )
    _AXIOS_CONFIG_URL_RE = re.compile(
        r"""\baxios(?:\.[\w$]+)?\s*\(\s*\{(?P<body>.{0,1500}?)\burl\s*:\s*(?P<quote>["'`])(?P<url>(?:https?://|/)[^"'`\s<>)]+)(?P=quote)""",
        re.IGNORECASE | re.DOTALL,
    )
    _RELATIVE_ROUTE_LITERAL_RE = re.compile(
        r"""(?P<quote>["'`])(?P<url>/(?:api|v1|v2|graphql|gql)(?:[/?#][^"'`\s<>)]*)?)(?P=quote)""",
        re.IGNORECASE,
    )
    _ROUTER_PATH_RE = re.compile(
        r"""\b(?:path|to)\s*:\s*(?P<object_quote>["'`])(?P<object_url>/[^"'`\s<>)]+)(?P=object_quote)|\broute\s*\(\s*(?P<route_quote>["'`])(?P<route_url>/[^"'`\s<>)]+)(?P=route_quote)""",
        re.IGNORECASE,
    )
    _JSX_TO_PATH_RE = re.compile(
        r"""\bto\s*=\s*\{?\s*(?P<quote>["'`])(?P<url>/[^"'`\s<>)]+)(?P=quote)\s*\}?""",
        re.IGNORECASE,
    )
    _GRAPHQL_ENDPOINT_RE = re.compile(
        r"""(?P<quote>["'`])(?P<url>(?:https?://[^"'`\s<>)]+|/[^"'`\s<>)]*?(?:graphql|gql)[^"'`\s<>)]*))(?P=quote)""",
        re.IGNORECASE,
    )
    _GRAPHQL_OPERATION_NAME_RE = re.compile(
        r"""(?:["'`]operationName["'`]|\boperationName\b)\s*[:=]\s*(?P<quote>["'`])(?P<name>[_A-Za-z][_0-9A-Za-z]*)(?P=quote)""",
        re.IGNORECASE,
    )
    _GRAPHQL_OPERATION_RE = re.compile(
        r"""\b(?:query|mutation|subscription)\s+(?P<name>[_A-Za-z][_0-9A-Za-z]*)\b""",
        re.IGNORECASE,
    )
    _GQL_TEMPLATE_RE = re.compile(r"""\bgql\s*`(?P<body>.*?)`""", re.IGNORECASE | re.DOTALL)
    _SOURCE_MAPPING_URL_RE = re.compile(
        r"""(?:\/\/[#@]\s*sourceMappingURL=|\/\*#\s*sourceMappingURL=)(?P<url>[^\s*]+)""",
        re.IGNORECASE,
    )
    _TEMPLATE_EXPRESSION_RE = re.compile(r"""\$\{\s*(?P<name>[A-Za-z_$][\w$]*).*?\}""")
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

    def extract(self, js_content: str) -> list[JsEndpoint]:
        return self._extract_js_endpoint_records(js_content=js_content, include_inline_sourcemaps=True)

    def extract_sourcemap_urls(self, js_content: str, script_url: str | None = None) -> list[str]:
        urls: list[str] = []
        seen: set[str] = set()
        for match in self._SOURCE_MAPPING_URL_RE.finditer(js_content):
            value = match.group("url").strip().strip("\"'")
            if not value or value.startswith("data:"):
                continue
            parsed_path = urlparse(value).path.lower()
            if not parsed_path.endswith(".map"):
                continue
            resolved = urljoin(script_url, value) if script_url else value
            if resolved in seen:
                continue
            seen.add(resolved)
            urls.append(resolved)
        return urls

    async def extract_from_referenced_sourcemaps(
        self,
        js_content: str,
        script_url: str,
        base_url: str,
    ) -> list[JsEndpoint]:
        results: list[JsEndpoint] = []
        seen: set[tuple[str, str]] = set()

        for payload in self._iter_inline_sourcemap_payloads(js_content):
            for endpoint in self._extract_sourcemap_payload_endpoints(payload=payload, base_url=base_url):
                self._append_existing_endpoint(results, seen, endpoint)
                if len(results) >= self._MAX_RESULTS:
                    return results

        for sourcemap_url in self.extract_sourcemap_urls(js_content=js_content, script_url=script_url):
            for endpoint in await self.extract_from_sourcemap(sourcemap_url=sourcemap_url, base_url=base_url):
                self._append_existing_endpoint(results, seen, endpoint)
                if len(results) >= self._MAX_RESULTS:
                    return results

        return results

    def extract_secrets(self, js_content: str, source_url: str) -> list[JsSecretFinding]:
        findings: list[JsSecretFinding] = []
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

    async def extract_from_sourcemap(self, sourcemap_url: str, base_url: str) -> list[JsEndpoint]:
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

        return self._extract_sourcemap_payload_endpoints(payload=payload, base_url=base_url)

    def _extract_js_endpoint_records(self, js_content: str, include_inline_sourcemaps: bool) -> list[JsEndpoint]:
        results: list[JsEndpoint] = []
        seen: set[tuple[str, str]] = set()

        for pattern_name, pattern in (
            ("legacy_fetch_axios", self._FETCH_AXIOS_RE),
            ("legacy_path_literal", self._PATH_LITERAL_RE),
            ("legacy_base_url", self._BASE_URL_RE),
        ):
            for match in pattern.findall(js_content):
                value = self._coerce_match_value(match)
                self._append_endpoint(results, seen, value, pattern_name)
                if len(results) >= self._MAX_RESULTS:
                    return results

        for match in self._FETCH_URL_ARGUMENT_RE.finditer(js_content):
            self._append_endpoint(results, seen, match.group("url"), "fetch_call", method="GET")
            if len(results) >= self._MAX_RESULTS:
                return results

        for match in self._AXIOS_URL_ARGUMENT_RE.finditer(js_content):
            method = self._axios_method_to_http_method(match.groupdict().get("method"))
            self._append_endpoint(results, seen, match.group("url"), "axios_call", method=method)
            if len(results) >= self._MAX_RESULTS:
                return results

        for match in self._AXIOS_CONFIG_URL_RE.finditer(js_content):
            self._append_endpoint(results, seen, match.group("url"), "axios_config")
            if len(results) >= self._MAX_RESULTS:
                return results

        for match in self._RELATIVE_ROUTE_LITERAL_RE.finditer(js_content):
            self._append_endpoint(results, seen, match.group("url"), "relative_route_literal")
            if len(results) >= self._MAX_RESULTS:
                return results

        for match in self._ROUTER_PATH_RE.finditer(js_content):
            url_value = match.groupdict().get("object_url") or match.groupdict().get("route_url")
            if url_value is not None:
                self._append_endpoint(results, seen, url_value, "router_path")
                if len(results) >= self._MAX_RESULTS:
                    return results

        for match in self._JSX_TO_PATH_RE.finditer(js_content):
            self._append_endpoint(results, seen, match.group("url"), "router_to_prop")
            if len(results) >= self._MAX_RESULTS:
                return results

        self._extract_graphql_endpoints(js_content, results, seen)
        if len(results) >= self._MAX_RESULTS:
            return results[: self._MAX_RESULTS]

        if include_inline_sourcemaps:
            for payload in self._iter_inline_sourcemap_payloads(js_content):
                for endpoint in self._extract_sourcemap_payload_endpoints(payload=payload, base_url=None):
                    self._append_existing_endpoint(results, seen, endpoint)
                    if len(results) >= self._MAX_RESULTS:
                        return results

        return results

    def _append_endpoint(
        self,
        results: list[JsEndpoint],
        seen: set[tuple[str, str]],
        raw_endpoint: str,
        pattern: str,
        method: str | None = None,
        operation_name: str | None = None,
    ) -> None:
        endpoint = self._normalize_endpoint(raw_endpoint)
        if endpoint is None:
            return
        dedup_key = (endpoint, operation_name or "")
        if dedup_key in seen:
            self._merge_endpoint_metadata(
                results=results,
                endpoint=endpoint,
                pattern=pattern,
                method=method,
                operation_name=operation_name,
            )
            return
        seen.add(dedup_key)
        record: JsEndpoint = {"endpoint": endpoint, "source": _JS_SOURCE, "pattern": pattern}
        if method:
            record["method"] = method
        if operation_name:
            record["operationName"] = operation_name
        results.append(record)

    def _merge_endpoint_metadata(
        self,
        results: list[JsEndpoint],
        endpoint: str,
        pattern: str,
        method: str | None,
        operation_name: str | None,
    ) -> None:
        for existing in results:
            if existing["endpoint"] != endpoint:
                continue
            if existing.get("operationName", "") != (operation_name or ""):
                continue
            if method and "method" not in existing:
                existing["method"] = method
            if self._pattern_priority(pattern) >= self._pattern_priority(existing.get("pattern", "")):
                existing["pattern"] = pattern
            return

    def _pattern_priority(self, pattern: str) -> int:
        if pattern.startswith("graphql_"):
            return 4
        if pattern in {"fetch_call", "axios_call", "axios_config"}:
            return 3
        if pattern.startswith("router_") or pattern.startswith("sourcemap_"):
            return 2
        if pattern == "relative_route_literal":
            return 1
        if pattern.startswith("legacy_"):
            return 0
        return 1

    def _append_existing_endpoint(
        self,
        results: list[JsEndpoint],
        seen: set[tuple[str, str]],
        endpoint: JsEndpoint,
    ) -> None:
        self._append_endpoint(
            results=results,
            seen=seen,
            raw_endpoint=endpoint["endpoint"],
            pattern=endpoint.get("pattern", "sourcemap"),
            method=endpoint.get("method"),
            operation_name=endpoint.get("operationName"),
        )

    def _normalize_endpoint(self, raw_endpoint: str) -> str | None:
        value = raw_endpoint.strip().strip("\"'`")
        if not value:
            return None
        value = value.replace("\\/", "/")
        value = self._TEMPLATE_EXPRESSION_RE.sub(self._replace_template_expression, value)
        if not value.startswith(("/", "http://", "https://")):
            return None
        if value.startswith("//"):
            return None
        if any(character in value for character in ("\n", "\r", "\t", " ")):
            return None
        parsed_path = urlparse(value).path if "://" in value else value.split("?", 1)[0].split("#", 1)[0]
        lowered_path = parsed_path.lower()
        lowered_value = value.lower()
        if lowered_value.endswith(".json") and "/api/" not in lowered_value and "/swagger" not in lowered_value:
            return None
        if any(lowered_path.endswith(extension) for extension in self._EXCLUDED_EXTENSIONS):
            return None
        return value

    def _replace_template_expression(self, match: re.Match[str]) -> str:
        raw_name = match.group("name").strip("$")
        name = raw_name or "value"
        return f"{{{name}}}"

    def _coerce_match_value(self, match: str | tuple[str, ...]) -> str:
        if isinstance(match, str):
            return match.strip()
        for value in match:
            candidate = value.strip()
            if candidate.startswith(("/", "http://", "https://")):
                return candidate
        return ""

    def _axios_method_to_http_method(self, method: str | None) -> str | None:
        if method is None:
            return None
        lowered = method.lower()
        if lowered == "request":
            return None
        return lowered.upper()

    def _extract_graphql_endpoints(
        self,
        js_content: str,
        results: list[JsEndpoint],
        seen: set[tuple[str, str]],
    ) -> None:
        graphql_endpoints: list[str] = []
        for match in self._GRAPHQL_ENDPOINT_RE.finditer(js_content):
            endpoint = self._normalize_endpoint(match.group("url"))
            if endpoint is None:
                continue
            if endpoint not in graphql_endpoints:
                graphql_endpoints.append(endpoint)
            self._append_endpoint(results, seen, endpoint, "graphql_endpoint", method="POST")
            if len(results) >= self._MAX_RESULTS:
                return

        operation_names = self._extract_graphql_operation_names(js_content)
        if not operation_names:
            return

        target_endpoints = graphql_endpoints or ["/graphql"]
        for endpoint in target_endpoints:
            for operation_name in operation_names:
                self._append_endpoint(
                    results,
                    seen,
                    endpoint,
                    "graphql_operation",
                    method="POST",
                    operation_name=operation_name,
                )
                if len(results) >= self._MAX_RESULTS:
                    return

    def _extract_graphql_operation_names(self, js_content: str) -> list[str]:
        names: list[str] = []
        seen: set[str] = set()

        def add_name(raw_name: str) -> None:
            name = raw_name.strip()
            if not name or name in seen:
                return
            seen.add(name)
            names.append(name)

        for match in self._GRAPHQL_OPERATION_NAME_RE.finditer(js_content):
            add_name(match.group("name"))

        for match in self._GQL_TEMPLATE_RE.finditer(js_content):
            body = match.group("body")
            operation_match = self._GRAPHQL_OPERATION_RE.search(body)
            if operation_match is not None:
                add_name(operation_match.group("name"))

        decoded_content = unquote(js_content.replace("+", " "))
        for match in self._GRAPHQL_OPERATION_RE.finditer(decoded_content):
            add_name(match.group("name"))

        return names

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

    def _iter_inline_sourcemap_payloads(self, js_content: str) -> list[dict[str, Any]]:
        payloads: list[dict[str, Any]] = []
        for match in self._SOURCE_MAPPING_URL_RE.finditer(js_content):
            value = match.group("url").strip().strip("\"'")
            if not value.startswith("data:"):
                continue
            payload = self._decode_data_sourcemap(value)
            if payload is not None:
                payloads.append(payload)
        return payloads

    def _decode_data_sourcemap(self, source_mapping_url: str) -> dict[str, Any] | None:
        header, separator, encoded_payload = source_mapping_url.partition(",")
        if not separator or not encoded_payload:
            return None
        try:
            if ";base64" in header:
                decoded = base64.b64decode(encoded_payload, validate=False).decode("utf-8", errors="replace")
            else:
                decoded = unquote(encoded_payload)
            payload = json.loads(decoded)
        except (binascii.Error, json.JSONDecodeError, ValueError):
            return None
        return payload if isinstance(payload, dict) else None

    def _extract_sourcemap_payload_endpoints(
        self,
        payload: dict[str, Any],
        base_url: str | None,
    ) -> list[JsEndpoint]:
        sources = payload.get("sources")
        sources_content = payload.get("sourcesContent")

        results: list[JsEndpoint] = []
        seen: set[tuple[str, str]] = set()

        if isinstance(sources, list):
            for source in sources:
                if not isinstance(source, str):
                    continue
                route = self._route_from_sourcemap_source(source, base_url=base_url)
                if route is None:
                    continue
                self._append_endpoint(results, seen, route, "sourcemap_source")
                if len(results) >= self._MAX_RESULTS:
                    return results

        if isinstance(sources_content, list):
            for source_content in sources_content:
                if not isinstance(source_content, str):
                    continue
                for endpoint in self._extract_js_endpoint_records(
                    js_content=source_content,
                    include_inline_sourcemaps=False,
                ):
                    self._append_endpoint(
                        results,
                        seen,
                        endpoint["endpoint"],
                        f"sourcemap_{endpoint.get('pattern', 'source_content')}",
                        method=endpoint.get("method"),
                        operation_name=endpoint.get("operationName"),
                    )
                    if len(results) >= self._MAX_RESULTS:
                        return results

        return results

    def _route_from_sourcemap_source(self, source: str, base_url: str | None) -> str | None:
        normalized = unquote(source.strip()).replace("\\", "/")
        if not normalized:
            return None
        normalized = normalized.split("?", 1)[0].split("#", 1)[0]
        normalized = re.sub(r"^(?:webpack|ng|vite|rollup):///?", "", normalized, flags=re.IGNORECASE)

        if normalized.startswith(("http://", "https://")):
            endpoint = self._normalize_endpoint(normalized)
            if endpoint is None:
                return None
            return urlparse(endpoint).path or endpoint

        parts = [part for part in normalized.split("/") if part and part not in {".", ".."}]
        if not parts:
            return None
        lowered_parts = [part.lower() for part in parts]

        for marker in ("pages", "routes", "app"):
            if marker not in lowered_parts:
                continue
            marker_index = lowered_parts.index(marker)
            route = self._route_from_path_segments(parts[marker_index + 1 :])
            if route is not None:
                return route

        for index, part in enumerate(lowered_parts):
            if part not in {"api", "graphql", "gql", "v1", "v2", "v3"}:
                continue
            route = self._route_from_path_segments(parts[index:])
            if route is not None:
                return route

        if self._SOURCEMAP_ROUTE_HINT_RE.search(normalized) is None:
            return None
        hinted_path = f"/{normalized.lstrip('/')}"
        if base_url:
            hinted_path = urlparse(urljoin(base_url, hinted_path)).path or hinted_path
        return hinted_path

    def _route_from_path_segments(self, segments: list[str]) -> str | None:
        route_segments: list[str] = []
        for index, segment in enumerate(segments):
            normalized_segment = self._normalize_route_segment(segment, is_leaf=index == len(segments) - 1)
            if normalized_segment is None:
                continue
            route_segments.append(normalized_segment)
        if not route_segments:
            return None
        route = "/" + "/".join(route_segments)
        return re.sub(r"/{2,}", "/", route)

    def _normalize_route_segment(self, segment: str, is_leaf: bool) -> str | None:
        cleaned = re.sub(r"\.(?:[cm]?jsx?|tsx?|vue|svelte)$", "", segment)
        lowered = cleaned.lower()
        if lowered in {"index", "page", "route"} and is_leaf:
            return None
        if lowered in {"layout", "template", "_app", "_document", "_error"}:
            return None
        if cleaned.startswith("(") and cleaned.endswith(")"):
            return None
        if cleaned.startswith("@"):
            return None
        if cleaned.startswith("[...") and cleaned.endswith("]"):
            return "{" + cleaned[4:-1] + "}"
        if cleaned.startswith("[") and cleaned.endswith("]"):
            return "{" + cleaned[1:-1] + "}"
        if cleaned.startswith("$") and len(cleaned) > 1:
            return "{" + cleaned[1:] + "}"
        return cleaned or None
