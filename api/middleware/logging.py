from __future__ import annotations

import logging
import re
from collections.abc import Mapping
from typing import Any

import structlog

REDACTED = "[REDACTED]"


class CredentialStripper:
    _SENSITIVE_KEY_PATTERN = re.compile(
        r"authorization|cookie|password|token|secret|bearer|key",
        re.IGNORECASE,
    )

    def __call__(self, _: Any, __: str, event_dict: dict[str, Any]) -> dict[str, Any]:
        return self._redact_mapping(event_dict)

    def _redact_mapping(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        redacted: dict[str, Any] = {}
        for key, value in payload.items():
            if self._SENSITIVE_KEY_PATTERN.search(key):
                redacted[key] = REDACTED
                continue

            if isinstance(value, Mapping):
                redacted[key] = self._redact_mapping(value)
            elif isinstance(value, list):
                redacted[key] = [self._redact_value(item) for item in value]
            else:
                redacted[key] = value

        return redacted

    def _redact_value(self, value: Any) -> Any:
        if isinstance(value, Mapping):
            return self._redact_mapping(value)
        if isinstance(value, list):
            return [self._redact_value(item) for item in value]
        return value


def redact_for_audit(details: dict[str, Any]) -> dict[str, Any]:
    return CredentialStripper()._redact_mapping(details)


class ScanIdProcessor:
    def __call__(self, _: Any, __: str, event_dict: dict[str, Any]) -> dict[str, Any]:
        event_dict.setdefault("scan_id", "unknown")
        return event_dict


def configure_logging(level: int = logging.INFO) -> None:
    logging.basicConfig(format="%(message)s", level=level)

    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            CredentialStripper(),
            structlog.processors.TimeStamper(fmt="iso", key="timestamp"),
            structlog.stdlib.add_log_level,
            ScanIdProcessor(),
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.stdlib.BoundLogger,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )
