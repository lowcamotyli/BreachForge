from __future__ import annotations

from typing import Any

from execution_plane.providers.base import ToolResult


class ToolOutputNormalizer:
    MAX_RESPONSE_BODY = 1_000_000
    MAX_STDERR = 65_536

    @staticmethod
    def to_raw_probe(result: ToolResult, scan_id: str, target_url: str) -> dict[str, Any]:
        return {
            "scan_id": scan_id,
            "url": target_url,
            "method": "PROVIDER",
            "request_headers": {},
            "response_status": result.exit_code,
            "response_headers": {},
            "response_body": result.stdout[: ToolOutputNormalizer.MAX_RESPONSE_BODY],
            "provider_id": result.provider_id,
            "raw_stderr": result.stderr[: ToolOutputNormalizer.MAX_STDERR],
        }

    @staticmethod
    def to_discovery_signals(result: ToolResult) -> list[dict[str, Any]]:
        if result.json_output is None:
            return []

        payload = result.json_output
        items: list[Any] | None = None

        if isinstance(payload, list):
            items = payload
        elif isinstance(payload, dict):
            for key in ("findings", "results", "issues", "vulnerabilities"):
                value = payload.get(key)
                if isinstance(value, list):
                    items = value
                    break

        if items is None:
            return [
                {
                    "signal_type": "provider_discovery",
                    "provider_id": result.provider_id,
                    "raw": payload,
                }
            ]

        return [
            {
                "signal_type": "provider_discovery",
                "provider_id": result.provider_id,
                "raw": item,
            }
            for item in items
        ]

    @staticmethod
    def validate_output(result: ToolResult) -> bool:
        # Pre-validation normalization check only; canonical validation happens upstream.
        return result.exit_code == 0 and (bool(result.stdout) or result.json_output is not None)


class FindingNormalizer:
    TYPE_ALIASES: dict[str, str] = {
        "idor": "BOLA",
        "broken object level authorization": "BOLA",
        "bola": "BOLA",
        "bfla": "BFLA",
        "broken function level authorization": "BFLA",
        "auth bypass": "AUTH_BYPASS",
        "authentication bypass": "AUTH_BYPASS",
        "broken auth": "AUTH_BYPASS",
        "tenant isolation": "TENANT_ISOLATION",
        "cross-tenant": "TENANT_ISOLATION",
        "privilege escalation": "PRIVILEGE_ESCALATION",
        "privesc": "PRIVILEGE_ESCALATION",
        "race condition": "RACE_CONDITION",
        "toctou": "RACE_CONDITION",
        "business logic": "BUSINESS_LOGIC",
        "logic flaw": "BUSINESS_LOGIC",
        "mass assignment": "MASS_ASSIGNMENT",
        "object property": "MASS_ASSIGNMENT",
        "hidden endpoint": "HIDDEN_ENDPOINT",
        "shadow api": "HIDDEN_ENDPOINT",
        "graphql": "GRAPHQL",
        "oauth": "OAUTH",
        "sensitive data": "SENSITIVE_DATA",
        "information disclosure": "SENSITIVE_DATA",
        "injection": "INJECTION",
        "sqli": "INJECTION",
        "sql injection": "INJECTION",
        "command injection": "INJECTION",
        "xss": "INJECTION",
    }

    @staticmethod
    def normalize_type(raw_type: str) -> tuple[str, bool]:
        normalized = raw_type.lower()
        for alias, canonical in FindingNormalizer.TYPE_ALIASES.items():
            if normalized == alias or alias in normalized:
                return canonical, False
        return "unknown", True

    @staticmethod
    def normalize_endpoint(endpoint: str) -> str:
        re = __import__("re")
        normalized = endpoint.split("?", 1)[0]
        uuid_pattern = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
        digit_pattern = r"^\d+$"

        segments = normalized.split("/")
        normalized_segments: list[str] = []
        for segment in segments:
            if re.fullmatch(uuid_pattern, segment):
                normalized_segments.append("{id}")
            elif re.fullmatch(digit_pattern, segment):
                normalized_segments.append("{id}")
            else:
                normalized_segments.append(segment)

        normalized = "/".join(normalized_segments).lower()
        if normalized != "/" and normalized.endswith("/"):
            normalized = normalized[:-1]
        return normalized

    @staticmethod
    def normalize_method(method: str | None) -> str:
        if method and method.strip():
            return method.strip().upper()
        return "GET"

    @staticmethod
    def normalize_confidence(raw: float | str | None, source_engine: str = "") -> float:
        _ = source_engine
        if isinstance(raw, float):
            return max(0.0, min(1.0, raw))
        if isinstance(raw, int):
            return max(0.0, min(1.0, float(raw)))
        if isinstance(raw, str):
            mapping = {
                "critical": 0.95,
                "high": 0.9,
                "medium": 0.7,
                "low": 0.4,
                "info": 0.2,
                "informational": 0.2,
            }
            return mapping.get(raw.lower(), 0.5)
        return 0.5

    @classmethod
    def normalize_finding(
        cls,
        raw_type: str,
        endpoint: str,
        method: str | None,
        confidence: float | str | None,
        source_engine: str = "",
    ) -> dict[str, object]:
        canonical, manual_review_flag = cls.normalize_type(raw_type)
        return {
            "canonical_type": canonical,
            "normalized_endpoint": cls.normalize_endpoint(endpoint),
            "normalized_method": cls.normalize_method(method),
            "normalized_confidence": cls.normalize_confidence(confidence, source_engine),
            "manual_review_flag": manual_review_flag,
        }
