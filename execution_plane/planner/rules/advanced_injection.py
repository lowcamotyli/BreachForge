from __future__ import annotations

from typing import ClassVar

from execution_plane.planner.rules.base import AssetMap, AttackRule, ScanContext
from storage.db.models import AttackTask, Endpoint

_STRING_TYPES: set[str] = {"string", "str", "text"}
_STRING_LOCATIONS: set[str] = {"query", "form", "body", "json"}


class LdapInjectionRule(AttackRule):
    requires_auth = False
    attack_class: ClassVar[str] = "ldap_injection"
    name: ClassVar[str] = "LdapInjectionRule"

    def matches(self, endpoint: Endpoint, asset_map: AssetMap) -> bool:
        del asset_map
        if endpoint.auth_required is not True:
            return False
        return len(self._string_parameters(endpoint)) > 0

    def generate_tasks(self, endpoint: Endpoint, context: ScanContext) -> list[AttackTask]:
        tasks: list[AttackTask] = []
        for parameter_name in self._string_parameters(endpoint):
            hypothesis = (
                "LDAP injection probe; "
                f"parameter={parameter_name}; "
                "payloads: *)(uid=*))(|(uid=*, admin)(|(password=*; "
                "proof: auth bypass or error disclosure"
            )
            tasks.append(
                AttackTask(
                    scan_id=context.scan_id,
                    endpoint_id=endpoint.id,
                    attack_class=self.attack_class,
                    target_parameter=parameter_name,
                    hypothesis=hypothesis,
                )
            )
        return tasks

    def expected_proof_signal(self) -> str:
        return "Auth bypass or LDAP error disclosure after operator injection"

    def _string_parameters(self, endpoint: Endpoint) -> list[str]:
        selected: list[str] = []
        seen: set[str] = set()

        for parameter in endpoint.parameters:
            raw_name = parameter.get("name")
            if not isinstance(raw_name, str) or not raw_name.strip():
                continue
            name = raw_name.strip()

            raw_type = str(parameter.get("type") or parameter.get("schema") or "").lower()
            location = str(parameter.get("in") or parameter.get("location") or "").lower()
            if location not in _STRING_LOCATIONS:
                continue

            type_is_string = any(token in raw_type for token in _STRING_TYPES)
            if not type_is_string and location in {"query", "form"}:
                type_is_string = True
            if not type_is_string:
                continue

            lowered = name.lower()
            if lowered in seen:
                continue

            seen.add(lowered)
            selected.append(name)

        return selected


class XpathInjectionRule(AttackRule):
    requires_auth = False
    attack_class: ClassVar[str] = "xpath_injection"
    name: ClassVar[str] = "XpathInjectionRule"

    def matches(self, endpoint: Endpoint, asset_map: AssetMap) -> bool:
        del asset_map
        if endpoint.auth_required is not True:
            return False
        return len(self._string_parameters(endpoint)) > 0

    def generate_tasks(self, endpoint: Endpoint, context: ScanContext) -> list[AttackTask]:
        tasks: list[AttackTask] = []
        for parameter_name in self._string_parameters(endpoint):
            hypothesis = (
                "XPath injection probe; "
                f"parameter={parameter_name}; "
                "payloads: quote or 1=1, quote or empty=empty; "
                "proof: unexpected data return or error"
            )
            tasks.append(
                AttackTask(
                    scan_id=context.scan_id,
                    endpoint_id=endpoint.id,
                    attack_class=self.attack_class,
                    target_parameter=parameter_name,
                    hypothesis=hypothesis,
                )
            )
        return tasks

    def expected_proof_signal(self) -> str:
        return "Unexpected data return or XPath error disclosure after injection"

    def _string_parameters(self, endpoint: Endpoint) -> list[str]:
        selected: list[str] = []
        seen: set[str] = set()

        for parameter in endpoint.parameters:
            raw_name = parameter.get("name")
            if not isinstance(raw_name, str) or not raw_name.strip():
                continue
            name = raw_name.strip()

            raw_type = str(parameter.get("type") or parameter.get("schema") or "").lower()
            location = str(parameter.get("in") or parameter.get("location") or "").lower()
            if location not in _STRING_LOCATIONS:
                continue

            type_is_string = any(token in raw_type for token in _STRING_TYPES)
            if not type_is_string and location in {"query", "form"}:
                type_is_string = True
            if not type_is_string:
                continue

            lowered = name.lower()
            if lowered in seen:
                continue

            seen.add(lowered)
            selected.append(name)

        return selected


class HeaderInjectionRule(AttackRule):
    requires_auth = False
    attack_class: ClassVar[str] = "header_injection"
    name: ClassVar[str] = "HeaderInjectionRule"

    _STATE_CHANGING_METHODS: ClassVar[frozenset[str]] = frozenset({"POST", "PUT", "PATCH", "DELETE"})

    def matches(self, endpoint: Endpoint, asset_map: AssetMap) -> bool:
        del asset_map
        # Host/XFF injection is meaningful when the server enforces IP-based access control
        # (auth_required) or processes request context in state-changing operations.
        return endpoint.auth_required or endpoint.method.upper() in self._STATE_CHANGING_METHODS

    def generate_tasks(self, endpoint: Endpoint, context: ScanContext) -> list[AttackTask]:
        return [
            AttackTask(
                scan_id=context.scan_id,
                endpoint_id=endpoint.id,
                attack_class=self.attack_class,
                target_parameter="Host",
                hypothesis=(
                    "Host header injection probe; injected value: evil.com; "
                    "proof: host reflected in response or redirect"
                ),
            ),
            AttackTask(
                scan_id=context.scan_id,
                endpoint_id=endpoint.id,
                attack_class=self.attack_class,
                target_parameter="X-Forwarded-For",
                hypothesis=(
                    "XFF spoofing probe; injected value: 127.0.0.1; "
                    "proof: access control change after IP spoofing [unauth_injectable=true]"
                ),
            ),
        ]

    def expected_proof_signal(self) -> str:
        return "Response changes or access control bypass after Host/X-Forwarded-For header manipulation"
