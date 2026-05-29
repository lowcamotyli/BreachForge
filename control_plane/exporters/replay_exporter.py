from __future__ import annotations

import shlex
from datetime import UTC, datetime
from typing import Any


class ReplayExporter:
    _REDACTED = "REDACTED"
    _SENSITIVE_HEADERS = {"authorization", "cookie"}

    @classmethod
    def to_curl(cls, bundle: dict[str, Any]) -> str:
        request = cls._attack_request(bundle)
        method = str(request.get("method") or "GET").upper()
        url = str(request.get("url") or "")
        headers = cls._redacted_headers(request.get("headers"))
        body = request.get("body")

        parts: list[str] = ["curl", "-X", shlex.quote(method)]
        for key, value in headers.items():
            parts.extend(["-H", shlex.quote(f"{key}: {value}")])
        if body not in (None, ""):
            parts.extend(["--data-raw", shlex.quote(cls._body_to_string(body))])
        if url:
            parts.append(shlex.quote(url))
        return " ".join(parts)

    @classmethod
    def to_httpie(cls, bundle: dict[str, Any]) -> str:
        request = cls._attack_request(bundle)
        method = str(request.get("method") or "GET").upper()
        url = str(request.get("url") or "")
        headers = cls._redacted_headers(request.get("headers"))
        body = request.get("body")

        parts: list[str] = ["http", shlex.quote(method), shlex.quote(url or "")]
        for key, value in headers.items():
            parts.append(shlex.quote(f"{key}:{value}"))
        if body not in (None, ""):
            parts.append(shlex.quote(f"body={cls._body_to_string(body)}"))
        return " ".join(part for part in parts if part)

    @classmethod
    def to_postman(cls, bundle: dict[str, Any]) -> dict[str, Any]:
        request = cls._attack_request(bundle)
        method = str(request.get("method") or "GET").upper()
        url = str(request.get("url") or "")
        headers = cls._redacted_headers(request.get("headers"))
        body = request.get("body")

        item: dict[str, Any] = {
            "name": str(bundle.get("name") or f"{method} {url or 'request'}"),
            "request": {
                "method": method,
                "url": url,
                "header": [{"key": key, "value": value} for key, value in headers.items()],
            },
        }
        if body not in (None, ""):
            item["request"]["body"] = {
                "mode": "raw",
                "raw": cls._body_to_string(body),
            }
        return item

    @classmethod
    def to_har_subset(cls, bundle: dict[str, Any]) -> dict[str, Any]:
        request = cls._attack_request(bundle)
        method = str(request.get("method") or "GET").upper()
        url = str(request.get("url") or "")
        headers = cls._redacted_headers(request.get("headers"))
        body = request.get("body")
        body_text = cls._body_to_string(body) if body not in (None, "") else ""

        post_data: dict[str, Any] | None = None
        if body_text:
            post_data = {
                "mimeType": headers.get("Content-Type", headers.get("content-type", "text/plain")),
                "text": body_text,
            }

        return {
            "startedDateTime": str(bundle.get("startedDateTime") or datetime.now(UTC).isoformat()),
            "request": {
                "method": method,
                "url": url,
                "headers": [{"name": key, "value": value} for key, value in headers.items()],
                "bodySize": len(body_text.encode("utf-8")) if body_text else 0,
                "postData": post_data,
            },
            "response": {
                "status": 0,
                "statusText": "",
                "httpVersion": "",
                "headers": [],
                "content": {"size": 0, "mimeType": "", "text": ""},
            },
        }

    @classmethod
    def _attack_request(cls, bundle: dict[str, Any]) -> dict[str, Any]:
        attack_request = bundle.get("attack_request")
        if isinstance(attack_request, dict):
            return attack_request
        return {}

    @classmethod
    def _redacted_headers(cls, headers: Any) -> dict[str, str]:
        if not isinstance(headers, dict):
            return {}

        redacted: dict[str, str] = {}
        for key, value in headers.items():
            key_str = str(key)
            if key_str.lower() in cls._SENSITIVE_HEADERS:
                redacted[key_str] = cls._REDACTED
            else:
                redacted[key_str] = str(value)
        return redacted

    @staticmethod
    def _body_to_string(body: Any) -> str:
        if isinstance(body, str):
            return body
        if body is None:
            return ""
        return str(body)
