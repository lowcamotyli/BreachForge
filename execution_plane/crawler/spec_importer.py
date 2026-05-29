from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

import yaml

from .asset_map import AssetMap, AssetMapBuilder

_HTTP_METHODS = {"get", "post", "put", "patch", "delete", "head", "options", "trace"}


class SpecImporter:
    def parse_openapi(self, spec: dict[str, Any]) -> AssetMap:
        builder = AssetMapBuilder()
        endpoint_meta: dict[tuple[str, str], dict[str, Any]] = {}
        auth_hints = self.extract_auth_hints(spec)
        base_url = self._extract_openapi_base_url(spec)
        paths = spec.get("paths") if isinstance(spec, Mapping) else None
        if not isinstance(paths, Mapping):
            asset_map = builder.build()
            setattr(asset_map, "auth_hints", auth_hints)
            return asset_map

        global_security = spec.get("security", [])

        for path, operations in paths.items():
            if not isinstance(path, str) or not isinstance(operations, Mapping):
                continue
            path_parameters = operations.get("parameters", [])
            for method, operation in operations.items():
                if not isinstance(method, str) or method.lower() not in _HTTP_METHODS:
                    continue
                if not isinstance(operation, Mapping):
                    continue

                url = self._join_url(base_url, path)
                parameters = self._extract_openapi_parameters(path_parameters, operation.get("parameters", []))

                security_requirements_raw = operation.get("security", global_security)
                security_requirements = self._normalize_security_requirements(security_requirements_raw)
                auth_required = len(security_requirements) > 0

                body_fields = self._extract_openapi_request_body_fields(spec, operation)

                builder.add_endpoint(
                    url=url,
                    method=method,
                    auth_required=auth_required,
                    parameters=parameters,
                    source="openapi",
                )

                normalized = builder.normalize_url_pattern(url)
                endpoint_meta[(normalized, method.upper())] = {
                    "request_body_schema": body_fields,
                    "security_requirements": security_requirements,
                }

        asset_map = builder.build()
        for endpoint in asset_map.endpoints:
            key = (endpoint.url_pattern, endpoint.method.upper())
            meta = endpoint_meta.get(key, {})
            setattr(endpoint, "request_body_schema", meta.get("request_body_schema", []))
            setattr(endpoint, "security_requirements", meta.get("security_requirements", []))

        setattr(asset_map, "auth_hints", auth_hints)
        return asset_map

    def parse_postman(self, collection: dict[str, Any]) -> AssetMap:
        builder = AssetMapBuilder()
        endpoint_meta: dict[tuple[str, str], dict[str, Any]] = {}

        items = collection.get("item")
        if isinstance(items, list):
            self._walk_postman_items(items, builder, endpoint_meta)

        asset_map = builder.build()
        for endpoint in asset_map.endpoints:
            key = (endpoint.url_pattern, endpoint.method.upper())
            meta = endpoint_meta.get(key, {})
            setattr(endpoint, "headers", meta.get("headers", []))
            setattr(endpoint, "body_schema", meta.get("body_schema", []))

        setattr(asset_map, "auth_hints", [])
        return asset_map

    def parse_insomnia(self, workspace: dict[str, Any]) -> AssetMap:
        builder = AssetMapBuilder()
        endpoint_meta: dict[tuple[str, str], dict[str, Any]] = {}

        resources = workspace.get("resources")
        if isinstance(resources, list):
            for resource in resources:
                if not isinstance(resource, Mapping):
                    continue
                if resource.get("_type") != "request":
                    continue

                method = str(resource.get("method", "GET")).upper()
                url = str(resource.get("url", ""))
                if not url:
                    continue

                headers = self._extract_insomnia_headers(resource.get("headers"))

                builder.add_endpoint(
                    url=url,
                    method=method,
                    auth_required=False,
                    parameters=[],
                    source="manual",
                )

                normalized = builder.normalize_url_pattern(url)
                endpoint_meta[(normalized, method)] = {
                    "headers": headers,
                }

        asset_map = builder.build()
        for endpoint in asset_map.endpoints:
            key = (endpoint.url_pattern, endpoint.method.upper())
            meta = endpoint_meta.get(key, {})
            setattr(endpoint, "headers", meta.get("headers", []))

        setattr(asset_map, "auth_hints", [])
        return asset_map

    def extract_auth_hints(self, spec: dict[str, Any]) -> list[dict[str, str]]:
        hints: list[dict[str, str]] = []
        seen: set[tuple[str, str, str]] = set()

        schemes: Mapping[str, Any] = {}
        components = spec.get("components") if isinstance(spec, Mapping) else None
        if isinstance(components, Mapping):
            candidate = components.get("securitySchemes")
            if isinstance(candidate, Mapping):
                schemes = candidate

        if not schemes:
            candidate = spec.get("securityDefinitions") if isinstance(spec, Mapping) else None
            if isinstance(candidate, Mapping):
                schemes = candidate

        for scheme_name, scheme in schemes.items():
            if not isinstance(scheme_name, str) or not isinstance(scheme, Mapping):
                continue

            hint_type = ""
            in_value = ""

            scheme_type = str(scheme.get("type", ""))
            if scheme_type == "apiKey":
                hint_type = "apiKey"
                in_value = str(scheme.get("in", ""))
            elif scheme_type == "oauth2":
                hint_type = "oauth2"
            elif scheme_type == "http":
                http_scheme = str(scheme.get("scheme", "")).lower()
                if http_scheme == "bearer":
                    hint_type = "bearer"
                elif http_scheme == "basic":
                    hint_type = "basic"
            elif scheme_type == "basic":
                hint_type = "basic"

            if not hint_type:
                continue

            identifier = (hint_type, scheme_name, in_value)
            if identifier in seen:
                continue
            seen.add(identifier)

            hints.append(
                {
                    "type": hint_type,
                    "name": scheme_name,
                    "in_": in_value,
                }
            )

        return hints

    def parse(self, data: dict[str, Any] | str) -> AssetMap:
        parsed: Any = data
        if isinstance(data, str):
            parsed = yaml.safe_load(data)

        if not isinstance(parsed, Mapping):
            raise ValueError("Unrecognized specification format")

        parsed_dict = dict(parsed)

        if "openapi" in parsed_dict or "swagger" in parsed_dict:
            return self.parse_openapi(parsed_dict)

        info = parsed_dict.get("info")
        if isinstance(info, Mapping):
            schema = info.get("schema")
            if isinstance(schema, str) and "v2.1" in schema:
                return self.parse_postman(parsed_dict)

        if parsed_dict.get("__export_format") == 4:
            return self.parse_insomnia(parsed_dict)

        raise ValueError("Unrecognized specification format")

    def _extract_openapi_base_url(self, spec: Mapping[str, Any]) -> str:
        if "openapi" in spec:
            servers = spec.get("servers")
            if isinstance(servers, list) and servers:
                first = servers[0]
                if isinstance(first, Mapping):
                    url = first.get("url")
                    if isinstance(url, str):
                        return url.rstrip("/")
            return ""

        if "swagger" in spec:
            host = spec.get("host")
            base_path = spec.get("basePath", "")
            if isinstance(host, str):
                scheme = "https"
                schemes = spec.get("schemes")
                if isinstance(schemes, list) and schemes and isinstance(schemes[0], str):
                    scheme = schemes[0]
                path = base_path if isinstance(base_path, str) else ""
                return f"{scheme}://{host}{path}".rstrip("/")

        return ""

    def _join_url(self, base_url: str, path: str) -> str:
        if not base_url:
            return path
        if path.startswith("/"):
            return f"{base_url}{path}"
        return f"{base_url}/{path}"

    def _extract_openapi_parameters(self, shared_params: Any, operation_params: Any) -> list[dict[str, str]]:
        merged: list[dict[str, str]] = []
        raw_params: list[Any] = []

        if isinstance(shared_params, list):
            raw_params.extend(shared_params)
        if isinstance(operation_params, list):
            raw_params.extend(operation_params)

        for param in raw_params:
            if not isinstance(param, Mapping):
                continue
            name = str(param.get("name", ""))
            location = str(param.get("in", ""))
            if not name or not location:
                continue

            required = str(bool(param.get("required", False))).lower()
            schema = param.get("schema")
            param_type = ""
            if isinstance(schema, Mapping):
                raw_type = schema.get("type")
                if isinstance(raw_type, str):
                    param_type = raw_type
            else:
                raw_type = param.get("type")
                if isinstance(raw_type, str):
                    param_type = raw_type

            merged.append(
                {
                    "name": name,
                    "location": location,
                    "required": required,
                    "type": param_type,
                }
            )

        return merged

    def _extract_openapi_request_body_fields(self, spec: Mapping[str, Any], operation: Mapping[str, Any]) -> list[str]:
        if "openapi" in spec:
            request_body = operation.get("requestBody")
            if not isinstance(request_body, Mapping):
                return []
            content = request_body.get("content")
            if not isinstance(content, Mapping):
                return []

            for media in content.values():
                if not isinstance(media, Mapping):
                    continue
                schema = media.get("schema")
                if not isinstance(schema, Mapping):
                    continue
                properties = schema.get("properties")
                if isinstance(properties, Mapping):
                    return [k for k in properties.keys() if isinstance(k, str)]
            return []

        body_params = operation.get("parameters")
        if not isinstance(body_params, list):
            return []

        for param in body_params:
            if not isinstance(param, Mapping):
                continue
            if param.get("in") != "body":
                continue
            schema = param.get("schema")
            if not isinstance(schema, Mapping):
                continue
            properties = schema.get("properties")
            if isinstance(properties, Mapping):
                return [k for k in properties.keys() if isinstance(k, str)]

        return []

    def _normalize_security_requirements(self, raw: Any) -> list[dict[str, list[str]]]:
        normalized: list[dict[str, list[str]]] = []
        if not isinstance(raw, list):
            return normalized

        for item in raw:
            if not isinstance(item, Mapping):
                continue
            normalized_item: dict[str, list[str]] = {}
            for key, value in item.items():
                if not isinstance(key, str):
                    continue
                scopes: list[str] = []
                if isinstance(value, list):
                    scopes = [v for v in value if isinstance(v, str)]
                normalized_item[key] = scopes
            if normalized_item:
                normalized.append(normalized_item)

        return normalized

    def _walk_postman_items(
        self,
        items: list[Any],
        builder: AssetMapBuilder,
        endpoint_meta: dict[tuple[str, str], dict[str, Any]],
    ) -> None:
        for item in items:
            if not isinstance(item, Mapping):
                continue

            nested = item.get("item")
            if isinstance(nested, list):
                self._walk_postman_items(nested, builder, endpoint_meta)
                continue

            request = item.get("request")
            if not isinstance(request, Mapping):
                continue

            method = str(request.get("method", "GET")).upper()
            url = self._extract_postman_url(request.get("url"))
            if not url:
                continue

            headers = self._extract_postman_headers(request.get("header"))
            body_schema = self._extract_postman_body_schema(request.get("body"))

            params = [{"name": h["key"], "location": "header", "type": "string"} for h in headers]

            builder.add_endpoint(
                url=url,
                method=method,
                auth_required=False,
                parameters=params,
                source="manual",
            )

            normalized = builder.normalize_url_pattern(url)
            endpoint_meta[(normalized, method)] = {
                "headers": headers,
                "body_schema": body_schema,
            }

    def _extract_postman_url(self, url_value: Any) -> str:
        if isinstance(url_value, str):
            return url_value
        if isinstance(url_value, Mapping):
            raw = url_value.get("raw")
            if isinstance(raw, str):
                return raw
            protocol = url_value.get("protocol")
            host = url_value.get("host")
            path = url_value.get("path")
            if isinstance(protocol, str) and isinstance(host, list):
                host_text = ".".join(str(h) for h in host)
                if isinstance(path, list):
                    path_text = "/".join(str(p) for p in path)
                    return f"{protocol}://{host_text}/{path_text}".rstrip("/")
                return f"{protocol}://{host_text}"
        return ""

    def _extract_postman_headers(self, headers_value: Any) -> list[dict[str, str]]:
        headers: list[dict[str, str]] = []
        if not isinstance(headers_value, list):
            return headers

        for header in headers_value:
            if not isinstance(header, Mapping):
                continue
            key = header.get("key")
            value = header.get("value", "")
            if isinstance(key, str):
                headers.append({"key": key, "value": str(value)})

        return headers

    def _extract_postman_body_schema(self, body_value: Any) -> list[str]:
        if not isinstance(body_value, Mapping):
            return []
        mode = body_value.get("mode")
        if mode != "raw":
            return []
        raw = body_value.get("raw")
        if not isinstance(raw, str):
            return []

        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            return []

        if isinstance(parsed, Mapping):
            return [k for k in parsed.keys() if isinstance(k, str)]
        return []

    def _extract_insomnia_headers(self, headers_value: Any) -> list[dict[str, str]]:
        headers: list[dict[str, str]] = []
        if not isinstance(headers_value, list):
            return headers

        for header in headers_value:
            if not isinstance(header, Mapping):
                continue
            name = header.get("name")
            value = header.get("value", "")
            if isinstance(name, str):
                headers.append({"key": name, "value": str(value)})

        return headers
