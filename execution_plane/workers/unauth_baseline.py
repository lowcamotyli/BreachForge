from __future__ import annotations

import asyncio
import json
import time
from typing import Any

import httpx

from execution_plane.crawler.asset_map import AssetMap

_AUTH_HEADER_BLOCKLIST = {"authorization", "cookie", "x-auth-token", "x-session-token"}
_CACHE_HEADER_KEYS = ("Cache-Control", "ETag", "Vary")


class UnauthBaselineProber:
    async def probe_endpoint(self, url: str, method: str, auth_headers: dict[str, str]) -> dict[str, dict[str, Any]]:
        sanitized_headers = self._strip_auth_headers(auth_headers)
        started = time.perf_counter()
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.request(method=method.upper(), url=url, headers=sanitized_headers)
        response_time_ms = (time.perf_counter() - started) * 1000.0
        content_type = response.headers.get("Content-Type", "")
        cache_headers = {
            key: value for key in _CACHE_HEADER_KEYS if (value := response.headers.get(key)) is not None
        }
        return {
            "unauth_response": {
                "status_code": response.status_code,
                "response_size_bytes": len(response.content),
                "content_type": content_type,
                "cache_headers": cache_headers,
                "response_time_ms": response_time_ms,
                "body_text": response.text,
            }
        }

    async def probe_all(
        self,
        asset_map: AssetMap,
        auth_headers: dict[str, str],
        rate_rps: float = 0.5,
    ) -> dict[str, dict[str, Any]]:
        delay_seconds = 1.0 / rate_rps if rate_rps > 0 else 0.0
        results: dict[str, dict[str, Any]] = {}
        for index, endpoint in enumerate(asset_map.endpoints):
            endpoint_key = f"{endpoint.method.upper()} {endpoint.url_pattern}"
            results[endpoint_key] = await self.probe_endpoint(
                url=endpoint.url_pattern,
                method=endpoint.method,
                auth_headers=auth_headers,
            )
            if delay_seconds > 0 and index < len(asset_map.endpoints) - 1:
                await asyncio.sleep(delay_seconds)
        return results

    def compute_differential(self, unauth_resp: dict[str, Any], auth_resp: dict[str, Any]) -> dict[str, Any]:
        unauth_payload = self._unwrap_response(unauth_resp)
        auth_payload = self._unwrap_response(auth_resp)
        unauth_status = self._as_int(unauth_payload.get("status_code"))
        auth_status = self._as_int(auth_payload.get("status_code"))
        unauth_size = self._as_int(unauth_payload.get("response_size_bytes"))
        auth_size = self._as_int(auth_payload.get("response_size_bytes"))
        json_field_diff = self._json_field_diff(unauth_payload=unauth_payload, auth_payload=auth_payload)
        return {
            "status_diff": unauth_status != auth_status,
            "size_diff_bytes": abs(auth_size - unauth_size),
            "json_field_diff": json_field_diff,
            "is_auth_bypass_candidate": unauth_status == auth_status,
            "is_data_leakage_candidate": len(json_field_diff) > 0,
        }

    def _strip_auth_headers(self, headers: dict[str, str]) -> dict[str, str]:
        sanitized: dict[str, str] = {}
        for key, value in headers.items():
            if key.lower() in _AUTH_HEADER_BLOCKLIST:
                continue
            sanitized[key] = value
        return sanitized

    def _unwrap_response(self, response: dict[str, Any]) -> dict[str, Any]:
        wrapped = response.get("unauth_response")
        if isinstance(wrapped, dict):
            return wrapped
        return response

    def _json_field_diff(self, unauth_payload: dict[str, Any], auth_payload: dict[str, Any]) -> list[str]:
        unauth_content_type = str(unauth_payload.get("content_type", "")).lower()
        auth_content_type = str(auth_payload.get("content_type", "")).lower()
        if "json" not in unauth_content_type or "json" not in auth_content_type:
            return []
        unauth_json = self._parse_json_body(unauth_payload.get("body_text"))
        auth_json = self._parse_json_body(auth_payload.get("body_text"))
        if not isinstance(unauth_json, dict) or not isinstance(auth_json, dict):
            return []
        return sorted([field for field in auth_json if field not in unauth_json])

    def _parse_json_body(self, body: Any) -> Any:
        if not isinstance(body, str):
            return None
        try:
            return json.loads(body)
        except json.JSONDecodeError:
            return None

    def _as_int(self, value: Any) -> int:
        if isinstance(value, int):
            return value
        if isinstance(value, float):
            return int(value)
        if isinstance(value, str):
            try:
                return int(value)
            except ValueError:
                return 0
        return 0
