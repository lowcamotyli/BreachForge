from __future__ import annotations

import json
from typing import Any

from execution_plane.planner.rules.base import AssetMap, AttackRule, ScanContext
from storage.db.models import AttackTask, Endpoint

_WRITE_METHODS: set[str] = {"POST", "PUT", "PATCH"}
_READ_METHODS: set[str] = {"GET"}
_HIDDEN_PRIVILEGE_FIELDS: tuple[str, ...] = (
    "role",
    "admin",
    "is_admin",
    "verified",
    "balance",
    "credits",
    "permission",
    "status",
    "plan",
    "subscription_tier",
)


class MassAssignmentRule(AttackRule):
    requires_auth = True
    attack_class = "mass_assignment"
    name = "MassAssignmentRule"

    def matches(self, endpoint: Endpoint, asset_map: AssetMap) -> bool:
        del asset_map
        return endpoint.method.upper() in _WRITE_METHODS and self._accepts_body(endpoint)

    def generate_tasks(self, endpoint: Endpoint, context: ScanContext) -> list[AttackTask]:
        hypothesis = {
            "probe_type": "mass_assignment_hidden_fields",
            "method": endpoint.method.upper(),
            "hidden_fields": list(_HIDDEN_PRIVILEGE_FIELDS),
            "extra_field_payload": self._safe_extra_field_payload(),
            "requires_safe_fixture_or_allow_mutation": True,
            "verification": "compare_get_before_after_write",
            "rollback": "restore_original_values_when_safe_fixture",
        }
        return [
            AttackTask(
                scan_id=context.scan_id,
                endpoint_id=endpoint.id,
                attack_class=self.attack_class,
                target_parameter="body",
                hypothesis=json.dumps(hypothesis, sort_keys=True),
                priority_score=0.82 if endpoint.auth_required else 0.72,
            )
        ]

    def expected_proof_signal(self) -> str:
        return "Hidden privilege field accepted by write request and visible in post-write GET response"

    def _accepts_body(self, endpoint: Endpoint) -> bool:
        content_type = (endpoint.observed_content_type or "").lower()
        if "json" in content_type:
            return True
        return any(self._parameter_is_body_object(parameter) for parameter in endpoint.parameters)

    def _parameter_is_body_object(self, parameter: dict[str, Any]) -> bool:
        location = str(parameter.get("in") or parameter.get("location") or "").lower()
        parameter_type = str(parameter.get("type") or "").lower()
        return location in {"body", "json", "form"} or parameter_type in {"object", "array"}

    def _safe_extra_field_payload(self) -> dict[str, object]:
        return {
            "role": "admin",
            "admin": True,
            "is_admin": True,
            "verified": True,
            "balance": 1,
            "credits": 1,
            "permission": "admin",
            "status": "active",
            "plan": "enterprise",
            "subscription_tier": "enterprise",
        }


class ExcessiveDataExposureRule(AttackRule):
    requires_auth = True
    attack_class = "excessive_exposure"
    name = "ExcessiveDataExposureRule"

    def matches(self, endpoint: Endpoint, asset_map: AssetMap) -> bool:
        del asset_map
        if endpoint.method.upper() not in _READ_METHODS:
            return False
        request_fields = self._request_fields(endpoint)
        response_fields = self._response_fields(endpoint)
        if not request_fields or not response_fields:
            return False
        extra_fields = response_fields - request_fields
        return len(extra_fields) / max(len(request_fields), 1) > 0.30

    def generate_tasks(self, endpoint: Endpoint, context: ScanContext) -> list[AttackTask]:
        request_fields = self._request_fields(endpoint)
        response_fields = self._response_fields(endpoint)
        extra_fields = sorted(response_fields - request_fields)
        hypothesis = {
            "probe_type": "excessive_data_exposure_schema_delta",
            "method": endpoint.method.upper(),
            "request_schema_fields": sorted(request_fields),
            "response_schema_fields": sorted(response_fields),
            "extra_response_fields": extra_fields,
            "extra_field_ratio": round(len(extra_fields) / max(len(request_fields), 1), 3),
            "read_only": True,
        }
        return [
            AttackTask(
                scan_id=context.scan_id,
                endpoint_id=endpoint.id,
                attack_class=self.attack_class,
                target_parameter="response",
                hypothesis=json.dumps(hypothesis, sort_keys=True),
                priority_score=0.70 if endpoint.auth_required else 0.62,
            )
        ]

    def expected_proof_signal(self) -> str:
        return "Response contains sensitive or undocumented fields compared with request schema"

    def _request_fields(self, endpoint: Endpoint) -> set[str]:
        return self._schema_fields(
            endpoint,
            keys=("request_schema", "body_schema", "schema", "request_fields"),
            include_body_parameter_names=True,
        )

    def _response_fields(self, endpoint: Endpoint) -> set[str]:
        return self._schema_fields(
            endpoint,
            keys=("response_schema", "response_fields", "example_response_schema"),
            include_body_parameter_names=False,
        )

    def _schema_fields(
        self,
        endpoint: Endpoint,
        *,
        keys: tuple[str, ...],
        include_body_parameter_names: bool,
    ) -> set[str]:
        fields: set[str] = set()
        for parameter in endpoint.parameters:
            for key in keys:
                fields.update(self._fields_from_value(parameter.get(key)))
            if include_body_parameter_names and str(parameter.get("in") or parameter.get("location") or "").lower() in {
                "body",
                "json",
                "form",
            }:
                name = parameter.get("name")
                if isinstance(name, str) and name.strip():
                    fields.add(name.strip())
        return fields

    def _fields_from_value(self, value: Any) -> set[str]:
        if isinstance(value, list):
            return {str(item).strip() for item in value if isinstance(item, str) and item.strip()}
        if not isinstance(value, dict):
            return set()

        properties = value.get("properties")
        if isinstance(properties, dict):
            return {str(field).strip() for field in properties if str(field).strip()}

        fields = value.get("fields")
        if isinstance(fields, list):
            return {str(item).strip() for item in fields if isinstance(item, str) and item.strip()}

        return {str(field).strip() for field in value if str(field).strip()}
