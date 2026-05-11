from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from urllib.parse import urlparse


class SecretLeakSource(str, Enum):
    RESPONSE_BODY = "response_body"
    RESPONSE_HEADER = "response_header"
    DEBUG_ENDPOINT = "debug_endpoint"
    CONFIG_JSON = "config_json"
    SOURCE_MAP = "source_map"
    STACK_TRACE = "stack_trace"
    PUBLIC_ASSET = "public_asset"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class LeakSourceClassification:
    source: SecretLeakSource
    confidence: float


class SecretLeakSourceClassifier:
    def classify(
        self,
        *,
        url: str = "",
        response_content_type: str = "",
        response_body: str = "",
        found_in_response_headers: bool = False,
    ) -> LeakSourceClassification:
        path = urlparse(url).path.lower()
        if "/debug" in path:
            return LeakSourceClassification(SecretLeakSource.DEBUG_ENDPOINT, 1.0)
        if path.endswith(".map") or "/sourcemap" in path:
            return LeakSourceClassification(SecretLeakSource.SOURCE_MAP, 1.0)
        if path.endswith(("/config", "/settings", "/env")):
            return LeakSourceClassification(SecretLeakSource.CONFIG_JSON, 0.95)
        if any(segment in path for segment in ("/swagger", "/openapi", "/api-docs")):
            return LeakSourceClassification(SecretLeakSource.PUBLIC_ASSET, 0.9)
        if any(segment in path for segment in ("/assets/", "/static/", "/public/")):
            return LeakSourceClassification(SecretLeakSource.PUBLIC_ASSET, 0.85)

        if found_in_response_headers:
            return LeakSourceClassification(SecretLeakSource.RESPONSE_HEADER, 0.95)

        if any(marker in response_body for marker in ("Traceback", "Stack trace", "Exception in")):
            return LeakSourceClassification(SecretLeakSource.STACK_TRACE, 0.9)

        content_type = response_content_type.lower()
        body = response_body.lower()
        if "application/json" in content_type and any(
            keyword in body for keyword in ("password", "api_key", "secret_key", "database_url", "token")
        ):
            return LeakSourceClassification(SecretLeakSource.CONFIG_JSON, 0.9)

        return LeakSourceClassification(SecretLeakSource.RESPONSE_BODY, 0.7)
