from __future__ import annotations

from execution_plane.planner.rules.base import AssetMap, AttackRule, ScanContext
from storage.db.models import AttackTask, Endpoint

_STRUCTURED_CONTENT_MARKERS: tuple[str, ...] = (
    "application/json",
    "application/problem+json",
    "application/ld+json",
    "application/vnd.api+json",
    "+json",
)
_STRUCTURED_PATH_MARKERS: tuple[str, ...] = ("/api/", "/data/", "/export/", "/report/", "/profile/")
_NOISE_CONTENT_MARKERS: tuple[str, ...] = ("text/html",)
_NOISE_PATH_MARKERS: tuple[str, ...] = ("/static/", "/assets/", "/_next/")
_NOISE_EXTENSIONS: tuple[str, ...] = (
    ".html",
    ".htm",
    ".js",
    ".css",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".ico",
    ".woff",
    ".woff2",
)

_PATTERN_GROUPS: tuple[tuple[str, str], ...] = (
    ("credential", "Expose credential-like fields in response body or headers"),
    ("token", "Expose bearer token/session token/API key in response body or headers"),
    ("pii", "Expose personally identifiable information in response without masking"),
)


class SensitiveExposure(AttackRule):
    attack_class = "sensitive_exposure"
    name = "SensitiveExposure"

    def matches(self, endpoint: Endpoint, asset_map: AssetMap) -> bool:
        del asset_map
        if not self.applies_to(endpoint):
            return False

        method = endpoint.method.upper()
        is_read_endpoint = method in {"GET", "POST"}
        has_success_like_response = endpoint.example_response_code is None or endpoint.example_response_code < 500
        return is_read_endpoint and has_success_like_response

    def generate_tasks(self, endpoint: Endpoint, context: ScanContext) -> list[AttackTask]:
        tasks: list[AttackTask] = []
        for group_name, hypothesis_suffix in _PATTERN_GROUPS:
            tasks.append(
                AttackTask(
                    scan_id=context.scan_id,
                    endpoint_id=endpoint.id,
                    attack_class=self.attack_class,
                    target_parameter=f"response.{group_name}",
                    hypothesis=f"Structured response may {hypothesis_suffix}",
                )
            )
        return tasks

    def expected_proof_signal(self) -> str:
        return "Response contains credential, token, or PII regex pattern in structured payload"

    def applies_to(self, endpoint: Endpoint) -> bool:
        if self._is_noise_endpoint(endpoint):
            return False
        return self._returns_structured_data(endpoint) or self._has_structured_path(endpoint)

    def _returns_structured_data(self, endpoint: Endpoint) -> bool:
        content_type = (endpoint.observed_content_type or "").lower()
        if any(marker in content_type for marker in _STRUCTURED_CONTENT_MARKERS):
            return True

        if endpoint.url_pattern.lower().endswith(".json"):
            return True

        for parameter in endpoint.parameters:
            schema_type = str(parameter.get("type") or "").lower()
            if schema_type in {"object", "array"}:
                return True

        return False

    def _has_structured_path(self, endpoint: Endpoint) -> bool:
        lower_path = endpoint.url_pattern.lower()
        return any(marker in lower_path for marker in _STRUCTURED_PATH_MARKERS)

    def _is_noise_endpoint(self, endpoint: Endpoint) -> bool:
        lower_path = endpoint.url_pattern.lower()
        if any(lower_path.endswith(extension) for extension in _NOISE_EXTENSIONS):
            return True
        if any(marker in lower_path for marker in _NOISE_PATH_MARKERS):
            return True

        content_type = (endpoint.observed_content_type or "").lower()
        return any(marker in content_type for marker in _NOISE_CONTENT_MARKERS)
