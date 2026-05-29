from __future__ import annotations

import base64
import json
from dataclasses import dataclass, field
from typing import Any


@dataclass
class AuthMaterial:
    cookies: dict[str, str] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    tokens: dict[str, str] = field(default_factory=dict)
    auth_type: str = "none"
    source_format: str = "unknown"


def _loads_json(file_content: str) -> dict[str, Any]:
    data = json.loads(file_content)
    if not isinstance(data, dict):
        raise ValueError("Import file must contain a JSON object")
    return data


def _header_name(header: dict[str, Any]) -> str:
    return str(header.get("name") or header.get("key") or "").strip()


def _header_value(header: dict[str, Any]) -> str:
    return str(header.get("value") or "").strip()


def _headers_from(value: Any) -> list[tuple[str, str]]:
    if isinstance(value, list):
        return [
            (_header_name(header), _header_value(header))
            for header in value
            if isinstance(header, dict) and _header_name(header)
        ]
    if isinstance(value, dict):
        return [(str(key).strip(), str(item).strip()) for key, item in value.items() if str(key).strip()]
    return []


def _cookies_from_header(value: str) -> dict[str, str]:
    cookies: dict[str, str] = {}
    for part in value.split(";"):
        name, separator, cookie_value = part.strip().partition("=")
        if separator and name:
            cookies[name] = cookie_value
    return cookies


def _is_api_key_header(name: str) -> bool:
    lowered = name.lower()
    return lowered in {"x-api-key", "api-key", "apikey"} or "api-key" in lowered or "api_key" in lowered


def _is_csrf_header(name: str) -> bool:
    lowered = name.lower()
    return "csrf" in lowered or "xsrf" in lowered


def _decode_basic(value: str) -> str:
    try:
        decoded = base64.b64decode(value, validate=True).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return value
    return decoded


def _record_header(material: AuthMaterial, name: str, value: str) -> None:
    if not name or not value:
        return

    lowered = name.lower()
    if lowered == "cookie":
        material.cookies.update(_cookies_from_header(value))
        return

    if lowered == "authorization":
        material.headers[name] = value
        scheme, _, credentials = value.partition(" ")
        scheme = scheme.lower()
        credentials = credentials.strip()
        if scheme == "bearer" and credentials:
            material.tokens.setdefault("bearer", credentials)
        elif scheme == "basic" and credentials:
            material.tokens.setdefault("basic", _decode_basic(credentials))
        else:
            material.tokens.setdefault("authorization", value)
        return

    if _is_api_key_header(name):
        material.headers[name] = value
        material.tokens.setdefault(name, value)
        return

    if _is_csrf_header(name):
        material.headers[name] = value
        material.tokens.setdefault(name, value)


def _merge_auth_type(material: AuthMaterial) -> None:
    auth_types: list[str] = []
    if material.tokens.get("bearer"):
        auth_types.append("bearer")
    if material.tokens.get("basic"):
        auth_types.append("basic")
    if any(_is_api_key_header(key) for key in material.tokens):
        auth_types.append("api_key")
    if any(_is_csrf_header(key) for key in material.tokens):
        auth_types.append("csrf")
    if material.cookies:
        auth_types.append("cookie")

    if not auth_types:
        material.auth_type = "none"
    elif len(auth_types) == 1:
        material.auth_type = auth_types[0]
    else:
        material.auth_type = "mixed"


def _record_postman_auth(material: AuthMaterial, auth: Any) -> None:
    if not isinstance(auth, dict):
        return

    auth_type = str(auth.get("type") or "").lower()
    values = {
        str(item.get("key")): str(item.get("value"))
        for item in auth.get(auth_type, [])
        if isinstance(item, dict) and item.get("key") is not None and item.get("value") is not None
    }

    if auth_type == "bearer" and values.get("token"):
        token = values["token"]
        material.headers.setdefault("Authorization", f"Bearer {token}")
        material.tokens.setdefault("bearer", token)
    elif auth_type == "basic":
        username = values.get("username", "")
        password = values.get("password", "")
        if username or password:
            material.tokens.setdefault("basic", f"{username}:{password}")
    elif auth_type in {"apikey", "api_key"}:
        key = values.get("key") or values.get("name") or "x-api-key"
        value = values.get("value")
        if value:
            material.headers.setdefault(key, value)
            material.tokens.setdefault(key, value)


class HarImporter:
    def extract_auth(self, file_content: str) -> AuthMaterial:
        data = _loads_json(file_content)
        entries = data.get("log", {}).get("entries", [])
        if not isinstance(entries, list):
            raise ValueError("Invalid HAR file")

        material = AuthMaterial(source_format="har")
        for entry in entries:
            request = entry.get("request", {}) if isinstance(entry, dict) else {}
            if not isinstance(request, dict):
                continue

            for cookie in request.get("cookies", []):
                if isinstance(cookie, dict) and cookie.get("name") and cookie.get("value") is not None:
                    material.cookies[str(cookie["name"])] = str(cookie["value"])

            for name, value in _headers_from(request.get("headers")):
                _record_header(material, name, value)

        _merge_auth_type(material)
        return material


class PostmanImporter:
    def extract_auth(self, file_content: str) -> AuthMaterial:
        data = _loads_json(file_content)
        material = AuthMaterial(source_format="postman")

        def visit(node: Any, inherited_auth: Any = None) -> None:
            if not isinstance(node, dict):
                return
            auth = node.get("auth", inherited_auth)
            _record_postman_auth(material, auth)

            request = node.get("request")
            if isinstance(request, dict):
                _record_postman_auth(material, request.get("auth", auth))
                for name, value in _headers_from(request.get("header")):
                    _record_header(material, name, value)

            for item in node.get("item", []):
                visit(item, auth)

        visit(data)
        _merge_auth_type(material)
        return material


class OpenApiImporter:
    def extract_auth(self, file_content: str) -> AuthMaterial:
        data = _loads_json(file_content)
        material = AuthMaterial(source_format="openapi")
        schemes = data.get("components", {}).get("securitySchemes", {})
        if not schemes and isinstance(data.get("securityDefinitions"), dict):
            schemes = data["securityDefinitions"]

        if isinstance(schemes, dict):
            for name, scheme in schemes.items():
                if not isinstance(scheme, dict):
                    continue
                scheme_type = str(scheme.get("type") or "").lower()
                http_scheme = str(scheme.get("scheme") or "").lower()
                header_name = str(scheme.get("name") or name)

                if scheme_type == "http" and http_scheme == "bearer":
                    token = f"<{name}_bearer_token>"
                    material.headers.setdefault("Authorization", f"Bearer {token}")
                    material.tokens.setdefault("bearer", token)
                elif scheme_type == "http" and http_scheme == "basic":
                    material.headers.setdefault("Authorization", f"Basic <{name}_credentials>")
                    material.tokens.setdefault("basic", f"<{name}_credentials>")
                elif scheme_type == "apikey" and str(scheme.get("in") or "").lower() == "header":
                    token = f"<{header_name}>"
                    material.headers.setdefault(header_name, token)
                    material.tokens.setdefault(header_name, token)

        _merge_auth_type(material)
        return material
