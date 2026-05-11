from __future__ import annotations

from typing import ClassVar

from execution_plane.planner.rules.base import AssetMap, AttackRule, ScanContext
from storage.db.models import AttackTask, Endpoint

_STRING_TYPES: set[str] = {"string", "str", "text"}
_STRING_LOCATIONS: set[str] = {"body", "json", "query", "form"}
_PUBLIC_STRING_LOCATIONS: set[str] = {"query", "form", "path"}
_PUBLIC_GET_PATH_KEYWORDS: tuple[str, ...] = (
    "login",
    "search",
    "contact",
    "newsletter",
    "subscribe",
    "register",
    "forgot",
    "reset",
    "verify",
)


class SstiRule(AttackRule):
    attack_class: ClassVar[str] = "ssti"
    name: ClassVar[str] = "SstiRule"
    requires_auth: ClassVar[bool] = False

    _STATE_CHANGING_METHODS: ClassVar[frozenset[str]] = frozenset({"POST", "PUT", "PATCH"})

    def matches(self, endpoint: Endpoint, asset_map: AssetMap) -> bool:
        del asset_map
        # Template rendering with user input is realistic on protected or state-mutating endpoints.
        interesting = endpoint.auth_required or endpoint.method.upper() in self._STATE_CHANGING_METHODS
        return interesting and bool(self._string_parameters(endpoint))

    def generate_tasks(self, endpoint: Endpoint, context: ScanContext) -> list[AttackTask]:
        unauth_injectable = self._is_public_endpoint(endpoint) and self._has_public_string_parameters(endpoint)
        tasks: list[AttackTask] = []
        for parameter_name in self._string_parameters(endpoint):
            hypothesis = (
                f"SSTI probe via template expression; parameter={parameter_name}; payloads: "
                "{{7*7}},${{}7*7{}}, <=% 7*7 %=>, #{{7*7}}, *{{7*7}}; "
                "proof: response contains math eval result 49"
            )
            if unauth_injectable:
                hypothesis += " [unauth_injectable=true]"

            task = AttackTask(
                scan_id=context.scan_id,
                endpoint_id=endpoint.id,
                attack_class=self.attack_class,
                target_parameter=parameter_name,
                hypothesis=hypothesis,
            )
            setattr(task, "unauth_injectable", unauth_injectable)
            tasks.append(task)
        return tasks

    def expected_proof_signal(self) -> str:
        return "Response body contains math eval result 49 from template expression injection"

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

    def _is_public_endpoint(self, endpoint: Endpoint) -> bool:
        auth_required = getattr(endpoint, "auth_required", False)
        if auth_required is False:
            return True

        method = str(getattr(endpoint, "method", "") or "").upper()
        if method != "GET":
            return False

        path = str(getattr(endpoint, "url_pattern", "") or "").lower()
        return any(keyword in path for keyword in _PUBLIC_GET_PATH_KEYWORDS)

    def _has_public_string_parameters(self, endpoint: Endpoint) -> bool:
        parameters = getattr(endpoint, "parameters", []) or []
        for parameter in parameters:
            if not isinstance(parameter, dict):
                continue
            location = str(parameter.get("in") or parameter.get("location") or "").lower()
            if location not in _PUBLIC_STRING_LOCATIONS:
                continue
            raw_type = str(parameter.get("type") or parameter.get("schema") or "").lower()
            type_is_string = any(token in raw_type for token in _STRING_TYPES)
            if not type_is_string and location in _PUBLIC_STRING_LOCATIONS:
                type_is_string = True
            if type_is_string:
                return True
        return False
