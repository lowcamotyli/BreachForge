from __future__ import annotations

from dataclasses import dataclass
from typing import Any


class BaseImporter:
    def normalize(self, raw: list[dict[str, Any]]) -> list[dict[str, Any]]:
        raise NotImplementedError


ATTACK_CLASSES: list[str] = [
    "BOLA",
    "BFLA",
    "AUTH_BYPASS",
    "TENANT_ISOLATION",
    "PRIVILEGE_ESCALATION",
    "RACE_CONDITION",
    "BUSINESS_LOGIC",
    "MASS_ASSIGNMENT",
    "HIDDEN_ENDPOINT",
    "GRAPHQL",
    "OAUTH",
    "SENSITIVE_DATA",
    "INJECTION",
]

ALIASES: dict[str, str] = {
    "idor": "BOLA",
    "object level authorization": "BOLA",
    "broken object level authorization": "BOLA",
    "function level authorization": "BFLA",
    "broken function level authorization": "BFLA",
    "broken auth": "AUTH_BYPASS",
    "authentication bypass": "AUTH_BYPASS",
    "auth bypass": "AUTH_BYPASS",
    "tenant isolation": "TENANT_ISOLATION",
    "privilege escalation": "PRIVILEGE_ESCALATION",
    "race condition": "RACE_CONDITION",
    "business logic": "BUSINESS_LOGIC",
    "mass assignment": "MASS_ASSIGNMENT",
    "hidden endpoint": "HIDDEN_ENDPOINT",
    "graphql": "GRAPHQL",
    "oauth": "OAUTH",
    "sensitive data": "SENSITIVE_DATA",
    "sensitive exposure": "SENSITIVE_DATA",
    "data leak": "SENSITIVE_DATA",
    "sql injection": "INJECTION",
    "sqli": "INJECTION",
    "xss": "INJECTION",
    "command injection": "INJECTION",
    "injection": "INJECTION",
}


@dataclass
class ImportedFinding:
    id: str
    source_engine: str
    finding_type: str
    endpoint: str
    method: str
    evidence: dict[str, Any]
    confidence: float
    manual_review_flag: bool = False
    category: str = ""

    def __post_init__(self) -> None:
        self.confidence = max(0.0, min(1.0, self.confidence))


def map_to_attack_class(type_str: str) -> str | None:
    normalized = type_str.casefold().replace("-", " ").replace("_", " ").strip()
    if not normalized:
        return None

    for attack_class in ATTACK_CLASSES:
        if attack_class.casefold().replace("_", " ") in normalized:
            return attack_class

    for alias, attack_class in ALIASES.items():
        if alias in normalized:
            return attack_class

    return None


def category_for(type_str: str) -> tuple[str, bool]:
    attack_class = map_to_attack_class(type_str)
    if attack_class is None:
        return "unknown", True
    return attack_class, False
