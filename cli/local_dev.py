from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import httpx

REDACT_KEYS = frozenset(
    {"authorization", "cookie", "password", "token", "secret", "api_key", "x-api-key"}
)


def redact_artifact(data: dict[str, Any]) -> dict[str, Any]:
    """Recursively redact sensitive keys from artifact dict."""
    result: dict[str, Any] = {}
    for key, value in data.items():
        if key.lower() in REDACT_KEYS:
            result[key] = "[REDACTED]"
        elif isinstance(value, dict):
            result[key] = redact_artifact(value)
        elif isinstance(value, list):
            result[key] = [redact_artifact(item) if isinstance(item, dict) else item for item in value]
        else:
            result[key] = value
    return result


@dataclass
class LocalDevScanner:
    api_url: str
    token: str

    def check_target_reachable(self, target_url: str) -> bool:
        """Returns True if target responds (any HTTP status)."""
        try:
            with httpx.Client(timeout=5.0) as client:
                client.get(target_url)
            return True
        except httpx.RequestError:
            return False

    def prepare_scan_payload(self, target_url: str, gate_path: str | None = None) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "target_url": target_url,
            "mode": "local_dev",
            "redact_artifacts": True,
        }
        if gate_path:
            payload["gate_config_path"] = gate_path
        return payload
