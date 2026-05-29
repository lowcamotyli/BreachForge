from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from http.cookies import SimpleCookie
from typing import Any
from urllib.parse import parse_qsl, urlparse
from uuid import UUID

from control_plane.auth_manager import SessionSnapshot
from execution_plane.crawler.asset_map import AssetMap, AssetMapBuilder

_SESSION_COOKIE_HINT_RE = re.compile(r"session|token|auth|jwt|sid", re.IGNORECASE)
_AUTH_HEADER_HINTS = {"authorization", "cookie", "x-csrf-token", "x-xsrf-token"}


@dataclass(slots=True)
class HarImporter:
    def parse(self, har_data: dict[str, Any]) -> tuple[AssetMap, SessionSnapshot | None]:
        entries_raw = har_data.get("log", {}).get("entries", [])
        entries = [entry for entry in entries_raw if isinstance(entry, dict)]

        asset_map_builder = AssetMapBuilder()
        for entry in entries:
            request = entry.get("request")
            response = entry.get("response")
            if not isinstance(request, dict) or not isinstance(response, dict):
                continue

            url = request.get("url")
            method = request.get("method")
            if not isinstance(url, str) or not url.strip():
                continue
            if not isinstance(method, str) or not method.strip():
                continue

            stripped_url = self._strip_query(url)
            request_headers = self._headers_to_dict(request.get("headers"))
            response_headers = self._headers_to_dict(response.get("headers"))
            status = response.get("status") if isinstance(response.get("status"), int) else None
            content_type = self._header_value(response_headers, "content-type")
            timing_ms = self._coerce_timing_ms(entry.get("time"))

            parameters = self._extract_query_parameters(url)
            for header_name in request_headers:
                parameters.append({"name": header_name, "location": "header", "type": "string"})

            body_schema = self._extract_body_schema(entry)
            if body_schema:
                parameters.append(
                    {
                        "name": "body",
                        "location": "body",
                        "type": "object",
                        "body_schema": body_schema,
                    }
                )

            if timing_ms is not None:
                parameters.append(
                    {
                        "name": "timing_ms",
                        "location": "meta",
                        "type": "number",
                        "value": str(timing_ms),
                    }
                )

            asset_map_builder.add_endpoint(
                url=stripped_url,
                method=method.upper(),
                auth_required=self._has_auth_signal(request_headers),
                parameters=parameters,
                in_scope=True,
                source="har",
                observed_content_type=content_type,
                example_response_code=status,
            )

        return asset_map_builder.build(), self._extract_session(entries)

    def _extract_session(self, entries: list[dict[str, Any]]) -> SessionSnapshot | None:
        cookies_by_name: dict[str, str] = {}
        auth_headers: dict[str, str] = {}
        session_domain: str | None = None
        has_session_cookie = False

        for entry in entries:
            request = entry.get("request")
            response = entry.get("response")
            if not isinstance(request, dict) or not isinstance(response, dict):
                continue

            request_url = request.get("url")
            if not isinstance(request_url, str) or not request_url.strip():
                continue

            request_headers = self._headers_to_dict(request.get("headers"))
            authorization_value = self._header_value(request_headers, "authorization")
            if isinstance(authorization_value, str) and authorization_value:
                auth_headers["Authorization"] = authorization_value

            for header_name, header_value in self._headers_to_list(response.get("headers")):
                if header_name.lower() != "set-cookie":
                    continue
                parsed_cookie_values = self._parse_set_cookie_values(header_value)
                for cookie_name, cookie_value in parsed_cookie_values.items():
                    cookies_by_name[cookie_name] = cookie_value
                    if _SESSION_COOKIE_HINT_RE.search(cookie_name):
                        has_session_cookie = True
                        if session_domain is None:
                            parsed_url = urlparse(request_url)
                            session_domain = parsed_url.hostname

        if not has_session_cookie:
            return None

        cookies_payload = [
            {
                "name": cookie_name,
                "value": cookie_value,
                "domain": session_domain or "",
                "path": "/",
            }
            for cookie_name, cookie_value in cookies_by_name.items()
        ]

        return SessionSnapshot(
            scan_id=UUID(int=0),
            cookies=cookies_payload,
            auth_headers=auth_headers,
            csrf_tokens={},
            captured_at=datetime.now(UTC),
            expires_at=None,
        )

    def _extract_body_schema(self, entry: dict[str, Any]) -> list[str]:
        request = entry.get("request")
        if not isinstance(request, dict):
            return []

        post_data = request.get("postData")
        if not isinstance(post_data, dict):
            return []

        mime_type = post_data.get("mimeType")
        if not isinstance(mime_type, str) or "json" not in mime_type.lower():
            return []

        body_text = post_data.get("text")
        if not isinstance(body_text, str) or not body_text.strip():
            return []

        try:
            parsed_body = json.loads(body_text)
        except (TypeError, ValueError, json.JSONDecodeError):
            return []

        if not isinstance(parsed_body, dict):
            return []

        return [field_name for field_name in parsed_body if isinstance(field_name, str)]

    def _extract_query_parameters(self, url: str) -> list[dict[str, str]]:
        query = urlparse(url).query
        if not query:
            return []

        parameters: list[dict[str, str]] = []
        for name, _value in parse_qsl(query, keep_blank_values=True):
            if not name.strip():
                continue
            parameters.append({"name": name.strip(), "location": "query", "type": "string"})
        return parameters

    def _strip_query(self, url: str) -> str:
        parsed_url = urlparse(url)
        return parsed_url._replace(query="", fragment="").geturl()

    def _coerce_timing_ms(self, timing_value: Any) -> int | None:
        if isinstance(timing_value, bool):
            return None
        if isinstance(timing_value, (int, float)):
            return int(timing_value)
        return None

    def _has_auth_signal(self, headers: dict[str, str]) -> bool:
        return any(name.lower() in _AUTH_HEADER_HINTS for name in headers)

    def _headers_to_dict(self, headers_obj: Any) -> dict[str, str]:
        result: dict[str, str] = {}
        for name, value in self._headers_to_list(headers_obj):
            if name in result:
                result[name] = f"{result[name]}, {value}"
            else:
                result[name] = value
        return result

    def _headers_to_list(self, headers_obj: Any) -> list[tuple[str, str]]:
        if not isinstance(headers_obj, list):
            return []

        headers: list[tuple[str, str]] = []
        for item in headers_obj:
            if not isinstance(item, dict):
                continue
            name = item.get("name")
            value = item.get("value")
            if not isinstance(name, str) or not isinstance(value, str):
                continue
            stripped_name = name.strip()
            if not stripped_name:
                continue
            headers.append((stripped_name, value.strip()))
        return headers

    def _header_value(self, headers: dict[str, str], expected_name: str) -> str | None:
        expected_name_lower = expected_name.lower()
        for name, value in headers.items():
            if name.lower() == expected_name_lower:
                return value
        return None

    def _parse_set_cookie_values(self, header_value: str) -> dict[str, str]:
        parsed = SimpleCookie()
        cookie_values: dict[str, str] = {}

        try:
            parsed.load(header_value)
        except Exception:
            parsed = SimpleCookie()

        for cookie_name, morsel in parsed.items():
            cookie_values[cookie_name] = morsel.value

        if cookie_values:
            return cookie_values

        for candidate in re.split(r",\s*(?=[^;,\s]+=)", header_value):
            first_part = candidate.split(";", 1)[0]
            if "=" not in first_part:
                continue
            name, value = first_part.split("=", 1)
            stripped_name = name.strip()
            if not stripped_name:
                continue
            cookie_values[stripped_name] = value.strip()

        return cookie_values
