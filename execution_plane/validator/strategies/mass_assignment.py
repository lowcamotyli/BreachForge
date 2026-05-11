from __future__ import annotations

import json
from typing import Any

from execution_plane.validator.strategies.base import ValidationStrategy
from storage.db.models import ProofArtifact, RawProbe

_HIDDEN_PRIVILEGE_FIELDS: set[str] = {
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
}
_SENSITIVE_RESPONSE_FIELDS: set[str] = {
    "password_hash",
    "salt",
    "internal_id",
    "secret_key",
    "ssn",
    "credit_card",
}


class MassAssignmentStrategy(ValidationStrategy):
    def validate(self, attack_probe: RawProbe, control_probe: RawProbe | None) -> ProofArtifact | None:
        if control_probe is None:
            return None

        attempted_values = self._attempted_hidden_values(attack_probe.request)
        if not attempted_values:
            return None

        before_state = self._extract_body(control_probe.response)
        after_state = self._extract_body(attack_probe.response)
        if not isinstance(before_state, dict) or not isinstance(after_state, dict):
            return None

        changed_fields: list[str] = []
        for field, attempted_value in attempted_values.items():
            before_value = before_state.get(field)
            after_value = after_state.get(field)
            if after_value == before_value:
                continue
            if after_value != attempted_value:
                continue
            changed_fields.append(field)

        if not changed_fields:
            return None

        evidence_notes = (
            "proof_signal=hidden_field_persisted; "
            f"changed_fields={','.join(sorted(changed_fields))}; "
            "comparison=pre_get_vs_post_write_get; values_logged=false"
        )
        rollback_note = self._rollback_note(attack_probe.request, changed_fields)
        if rollback_note:
            evidence_notes = f"{evidence_notes}; {rollback_note}"

        return ProofArtifact(
            attack_task_id=attack_probe.attack_task_id,
            proof_type=self.expected_proof_type(),
            confidence_score=0.92,
            attack_probe_id=attack_probe.id,
            control_probe_id=control_probe.id,
            summary="Mass assignment proof: hidden privilege field persisted after write probe",
            evidence_notes=evidence_notes,
        )

    def expected_proof_type(self) -> str:
        return "differential"

    def expected_attack_class(self) -> str:
        return "mass_assignment"

    def _attempted_hidden_values(self, request: dict[str, Any]) -> dict[str, Any]:
        candidates: dict[str, Any] = {}
        for key in ("extra_fields", "extra_field_payload", "attempted_fields", "hidden_field_payload"):
            value = request.get(key)
            if isinstance(value, dict):
                candidates.update(value)

        hypothesis = self._parse_json_mapping(request.get("hypothesis"))
        for key in ("extra_fields", "extra_field_payload", "attempted_fields", "hidden_field_payload"):
            value = hypothesis.get(key)
            if isinstance(value, dict):
                candidates.update(value)

        body = request.get("body")
        if isinstance(body, dict):
            candidates.update(body)
        elif isinstance(body, str):
            parsed_body = self._parse_json_mapping(body)
            candidates.update(parsed_body)

        return {field: candidates[field] for field in _HIDDEN_PRIVILEGE_FIELDS if field in candidates}

    def _extract_body(self, response: dict[str, Any]) -> Any:
        for key in ("json", "body", "data"):
            if key not in response:
                continue
            value = response[key]
            if isinstance(value, str):
                parsed = self._parse_json_value(value)
                return parsed if parsed is not None else value
            return value
        return response

    def _parse_json_mapping(self, value: Any) -> dict[str, Any]:
        parsed = self._parse_json_value(value)
        return parsed if isinstance(parsed, dict) else {}

    def _parse_json_value(self, value: Any) -> Any:
        if not isinstance(value, str) or not value.strip():
            return None
        try:
            return json.loads(value)
        except (TypeError, ValueError):
            return None

    def _rollback_note(self, request: dict[str, Any], changed_fields: list[str]) -> str:
        safe_fixture = request.get("safe_fixture") is True or request.get("safe_fixture_enabled") is True
        allow_mutation = request.get("allow_mutation") is True
        if not safe_fixture and not allow_mutation:
            return "rollback_guard=not_executed_without_safe_fixture_or_allow_mutation"

        rollback = request.get("rollback")
        rollback_performed = request.get("rollback_performed") is True or isinstance(rollback, dict)
        status = "performed" if rollback_performed else "required"
        return f"rollback_guard={status}; rollback_fields={','.join(sorted(changed_fields))}"


class ExcessiveExposureStrategy(ValidationStrategy):
    def validate(self, attack_probe: RawProbe, control_probe: RawProbe | None) -> ProofArtifact | None:
        del control_probe

        response_body = self._extract_body(attack_probe.response)
        response_fields = self._field_names(response_body)
        sensitive_hits = sorted(field for field in response_fields if field in _SENSITIVE_RESPONSE_FIELDS)
        if not sensitive_hits:
            return None

        return ProofArtifact(
            attack_task_id=attack_probe.attack_task_id,
            proof_type=self.expected_proof_type(),
            confidence_score=0.87,
            attack_probe_id=attack_probe.id,
            control_probe_id=None,
            summary="Excessive exposure proof: response contains sensitive object property names",
            evidence_notes=(
                "proof_signal=sensitive_field_name; "
                f"sensitive_fields={','.join(sensitive_hits)}; values_logged=false; read_only=true"
            ),
        )

    def expected_proof_type(self) -> str:
        return "absolute"

    def expected_attack_class(self) -> str:
        return "excessive_exposure"

    def _extract_body(self, response: dict[str, Any]) -> Any:
        for key in ("json", "body", "data"):
            if key not in response:
                continue
            value = response[key]
            if isinstance(value, str):
                try:
                    return json.loads(value)
                except (TypeError, ValueError):
                    return value
            return value
        return response

    def _field_names(self, value: Any) -> set[str]:
        fields: set[str] = set()
        if isinstance(value, dict):
            for key, nested in value.items():
                fields.add(str(key))
                fields.update(self._field_names(nested))
        elif isinstance(value, list):
            for item in value:
                fields.update(self._field_names(item))
        return fields
