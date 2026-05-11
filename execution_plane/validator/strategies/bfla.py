from __future__ import annotations

import json
from typing import Any

from execution_plane.validator.strategies.base import ValidationStrategy
from storage.db.models import ProofArtifact, RawProbe

_LOW_PRIV_ROLES: set[str] = {"user", "viewer", "guest", "anonymous", "anon", "unauthenticated"}
_ELEVATED_ROLES: set[str] = {"admin", "manager", "owner", "superuser", "ops", "system"}
_MUTATING_VERBS: set[str] = {"DELETE", "PUT", "PATCH"}


class BflaStrategy(ValidationStrategy):
    def validate(self, attack_probe: RawProbe, control_probe: RawProbe | None) -> ProofArtifact | None:
        attack_status = self._extract_status_code(attack_probe.response)
        control_status = self._extract_status_code(control_probe.response) if control_probe is not None else None
        method = self._extract_method(attack_probe.request)

        if attack_status is None:
            return None

        if self._is_false_positive(
            attack_status=attack_status,
            control_status=control_status,
            method=method,
            attack_probe=attack_probe,
            control_probe=control_probe,
        ):
            return None

        body_evidence = self._body_evidence(attack_probe.response)
        attack_role = self._extract_role(attack_probe.request)
        expected_status = self._expected_statuses(attack_probe.request, method)

        if self._is_mutating_verb_proof(
            method=method,
            attack_status=attack_status,
            attack_probe=attack_probe,
            attack_role=attack_role,
        ):
            confidence = 0.95 if method == "DELETE" and attack_status == 200 and self._request_without_admin_auth(attack_probe.request) else 0.93
            return ProofArtifact(
                attack_task_id=attack_probe.attack_task_id,
                proof_type="absolute",
                confidence_score=confidence,
                attack_probe_id=attack_probe.id,
                control_probe_id=control_probe.id if control_probe is not None else None,
                summary="BFLA proof: restricted mutating HTTP verb succeeded without elevated authorization",
                evidence_notes=self._format_evidence(
                    invoked_role=attack_role,
                    expected_status=expected_status,
                    received_status=attack_status,
                    method=method,
                    body_evidence=body_evidence,
                    control_status=control_status,
                ),
                identity_role=attack_role,
            )

        if self._is_differential_admin_path_proof(
            attack_status=attack_status,
            control_status=control_status,
            body_evidence=body_evidence,
            expected_status=expected_status,
            attack_role=attack_role,
        ):
            return ProofArtifact(
                attack_task_id=attack_probe.attack_task_id,
                proof_type="differential",
                confidence_score=0.92,
                attack_probe_id=attack_probe.id,
                control_probe_id=control_probe.id if control_probe is not None else None,
                summary="BFLA differential proof: low-privilege identity accessed admin-only endpoint",
                evidence_notes=self._format_evidence(
                    invoked_role=attack_role,
                    expected_status=expected_status,
                    received_status=attack_status,
                    method=method,
                    body_evidence=body_evidence,
                    control_status=control_status,
                ),
                identity_role=attack_role,
            )

        return None

    def expected_proof_type(self) -> str:
        return "differential"

    def expected_attack_class(self) -> str:
        return "bfla"

    def _is_false_positive(
        self,
        *,
        attack_status: int,
        control_status: int | None,
        method: str,
        attack_probe: RawProbe,
        control_probe: RawProbe | None,
    ) -> bool:
        del control_probe
        if attack_status == 405:
            return True

        redirect_location = self._redirect_location(attack_probe.response)
        if attack_status == 401 and redirect_location is not None:
            return True

        if control_status is not None and attack_status == 404 and control_status == 404:
            return True

        if control_status is not None and control_status in {403, 404}:
            return True

        if method in _MUTATING_VERBS and attack_status in {401, 403, 404}:
            return True

        return False

    def _is_mutating_verb_proof(
        self,
        *,
        method: str,
        attack_status: int,
        attack_probe: RawProbe,
        attack_role: str,
    ) -> bool:
        if method not in _MUTATING_VERBS:
            return False
        if attack_status not in {200, 204}:
            return False
        if not self._request_without_admin_auth(attack_probe.request):
            return False
        return self._is_low_priv(attack_role)

    def _is_differential_admin_path_proof(
        self,
        *,
        attack_status: int,
        control_status: int | None,
        body_evidence: str,
        expected_status: str,
        attack_role: str,
    ) -> bool:
        if not self._is_low_priv(attack_role):
            return False
        expected_tokens = {token.strip() for token in expected_status.split("|") if token.strip()}
        if "403" not in expected_tokens and "404" not in expected_tokens:
            return False
        if attack_status != 200:
            return False
        if not body_evidence:
            return False
        return control_status is None or control_status in {200, 201, 204}

    def _extract_status_code(self, response: dict[str, Any]) -> int | None:
        for key in ("status", "status_code", "code"):
            raw = response.get(key)
            if isinstance(raw, int):
                return raw
            if isinstance(raw, str) and raw.isdigit():
                return int(raw)
        return None

    def _extract_method(self, request: dict[str, Any]) -> str:
        raw_method = request.get("method")
        return str(raw_method or "GET").strip().upper()

    def _extract_role(self, request: dict[str, Any]) -> str:
        for key in ("identity_role", "role", "invoked_role", "actor_role"):
            value = request.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip().lower()
        return "unknown"

    def _is_low_priv(self, role: str) -> bool:
        return role.strip().lower() in _LOW_PRIV_ROLES

    def _is_elevated(self, role: str) -> bool:
        return role.strip().lower() in _ELEVATED_ROLES

    def _expected_statuses(self, request: dict[str, Any], method: str) -> str:
        hypothesis = self._parse_json(request.get("hypothesis"))

        expected = request.get("expected_status")
        if isinstance(expected, int):
            return str(expected)

        expected_values = request.get("expected_statuses")
        if isinstance(expected_values, list):
            parsed = [str(value) for value in expected_values if isinstance(value, (int, str))]
            if parsed:
                return "|".join(parsed)

        if isinstance(hypothesis, dict):
            direct = hypothesis.get("expected_low_priv_status")
            if isinstance(direct, list):
                parsed = [str(value) for value in direct if isinstance(value, (int, str))]
                if parsed:
                    return "|".join(parsed)
            candidates = hypothesis.get("candidates")
            if isinstance(candidates, list):
                for candidate in candidates:
                    if not isinstance(candidate, dict):
                        continue
                    if str(candidate.get("method") or "").strip().upper() != method:
                        continue
                    candidate_expected = candidate.get("expected_low_priv_status")
                    if isinstance(candidate_expected, list):
                        parsed = [str(value) for value in candidate_expected if isinstance(value, (int, str))]
                        if parsed:
                            return "|".join(parsed)

        return "403|404|405"

    def _request_without_admin_auth(self, request: dict[str, Any]) -> bool:
        role = self._extract_role(request)
        if self._is_elevated(role):
            return False

        for key in ("is_admin", "admin", "as_admin", "admin_mode", "elevated"):
            value = request.get(key)
            if value is True:
                return False

        headers = request.get("headers")
        if isinstance(headers, dict):
            auth_value = self._header_value(headers, "authorization")
            if isinstance(auth_value, str) and any(marker in auth_value.lower() for marker in ("admin", "manager", "superuser", "root")):
                return False
            role_header = self._header_value(headers, "x-role")
            if isinstance(role_header, str) and self._is_elevated(role_header):
                return False
        return True

    def _header_value(self, headers: dict[str, Any], header_name: str) -> Any:
        for key, value in headers.items():
            if str(key).strip().lower() == header_name:
                return value
        return None

    def _redirect_location(self, response: dict[str, Any]) -> str | None:
        headers = response.get("headers")
        if not isinstance(headers, dict):
            return None
        for key, value in headers.items():
            if str(key).strip().lower() != "location":
                continue
            if isinstance(value, str) and value.strip():
                return value.strip()
        return None

    def _body_evidence(self, response: dict[str, Any]) -> str:
        body = self._extract_body(response)
        if body is None:
            return ""

        if isinstance(body, dict):
            keys = sorted(str(key) for key in body.keys())
            if keys:
                return f"json_keys={','.join(keys[:8])}"
            return ""

        if isinstance(body, list):
            return f"list_items={len(body)}" if body else ""

        body_text = str(body).strip()
        if not body_text:
            return ""
        compact = " ".join(body_text.split())
        return f"text_prefix={compact[:120]}"

    def _extract_body(self, response: dict[str, Any]) -> Any:
        for key in ("json", "body", "data", "content", "text"):
            value = response.get(key)
            if value is None:
                continue
            if isinstance(value, str):
                parsed = self._parse_json(value)
                if parsed is not None:
                    return parsed
            return value
        return None

    def _parse_json(self, value: Any) -> Any:
        if not isinstance(value, str) or not value.strip():
            return None
        try:
            return json.loads(value)
        except (TypeError, ValueError):
            return None

    def _format_evidence(
        self,
        *,
        invoked_role: str,
        expected_status: str,
        received_status: int,
        method: str,
        body_evidence: str,
        control_status: int | None,
    ) -> str:
        fragments = [
            f"invoked_role={invoked_role}",
            f"expected_status={expected_status}",
            f"received_status={received_status}",
            f"method={method}",
        ]
        if control_status is not None:
            fragments.append(f"control_status={control_status}")
        if body_evidence:
            fragments.append(f"body_evidence={body_evidence}")
        return "; ".join(fragments)
