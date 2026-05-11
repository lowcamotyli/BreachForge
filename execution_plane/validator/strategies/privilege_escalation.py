from __future__ import annotations

import json
from typing import Any

from execution_plane.validator.differential import DifferentialProbeResult
from execution_plane.validator.strategies.base import ValidationStrategy
from storage.db.models import ProofArtifact, RawProbe

_ROLE_RANKING: dict[str, int] = {
    "guest": 0,
    "anonymous": 0,
    "viewer": 1,
    "read_only": 1,
    "user": 2,
    "member": 2,
    "editor": 3,
    "manager": 4,
    "admin": 5,
    "super_admin": 6,
    "owner": 7,
    "root": 8,
}
_ACCESS_KEYS: tuple[str, ...] = (
    "role",
    "roles",
    "permission",
    "permissions",
    "scope",
    "scopes",
    "is_admin",
    "access_level",
    "privilege",
)


class PrivilegeEscalationStrategy(ValidationStrategy):
    _MIN_PROOF_CONFIDENCE_THRESHOLD = 0.85
    _ABSOLUTE_CONFIDENCE = 0.95

    def validate(
        self,
        attack_probe: RawProbe,
        control_probe: RawProbe | None,
        differential_result: DifferentialProbeResult | None = None,
    ) -> ProofArtifact | None:
        if control_probe is None:
            return None

        attack_status = self._extract_status(attack_probe.response)
        control_status = self._extract_status(control_probe.response)
        if not self._is_success_status(attack_status) or not self._is_success_status(control_status):
            return None

        attack_body = self._extract_semantic_body(attack_probe.response)
        control_body = self._extract_semantic_body(control_probe.response)

        attack_snapshot = self._extract_access_snapshot(attack_body)
        control_snapshot = self._extract_access_snapshot(control_body)
        if not attack_snapshot:
            return None

        attack_score = self._score_snapshot(attack_snapshot)
        control_score = self._score_snapshot(control_snapshot)

        if attack_score <= control_score:
            return None

        confidence = self._ABSOLUTE_CONFIDENCE
        evidence_suffix = ""
        if differential_result is not None:
            observed_access = differential_result.challenger_status in (200, 201, 204)
            elevated_blocked = differential_result.baseline_status in (200, 201, 204)
            boundary_collapse = observed_access and elevated_blocked and (not differential_result.status_differs)
            evidence_suffix = (
                ", differential_observed_access="
                f"{observed_access}, differential_elevated_blocked={elevated_blocked}, "
                f"differential_status_differs={differential_result.status_differs}"
            )
            if boundary_collapse:
                confidence = min(1.0, confidence + 0.2)
                evidence_suffix = f"{evidence_suffix}, privilege boundary collapse"
        if confidence < self._MIN_PROOF_CONFIDENCE_THRESHOLD:
            return None

        return ProofArtifact(
            attack_task_id=attack_probe.attack_task_id,
            proof_type=self.expected_proof_type(),
            confidence_score=confidence,
            attack_probe_id=attack_probe.id,
            control_probe_id=control_probe.id,
            summary="Privilege escalation absolute proof: attack response indicates a higher access level than baseline.",
            evidence_notes=(
                f"attack_access_score={attack_score}, control_access_score={control_score}, "
                f"attack_status={attack_status}, control_status={control_status}, "
                f"attack_snapshot={json.dumps(attack_snapshot, sort_keys=True)}{evidence_suffix}"
            ),
        )

    def expected_proof_type(self) -> str:
        return "absolute"

    def expected_attack_class(self) -> str:
        return "privilege_escalation"

    def _extract_status(self, response: dict[str, Any]) -> int | str | None:
        for key in ("status", "status_code", "code"):
            if key in response:
                return response[key]
        return None

    def _is_success_status(self, status: int | str | None) -> bool:
        if isinstance(status, int):
            return 200 <= status < 300
        if isinstance(status, str) and status.isdigit():
            parsed = int(status)
            return 200 <= parsed < 300
        return False

    def _extract_semantic_body(self, response: dict[str, Any]) -> Any:
        for key in ("body", "json", "data", "content", "text"):
            if key in response:
                return self._normalize_value(response[key])
        return None

    def _normalize_value(self, value: Any) -> Any:
        if isinstance(value, str):
            stripped = value.strip()
            if not stripped:
                return ""
            try:
                parsed = json.loads(stripped)
            except (TypeError, ValueError):
                return stripped
            return self._normalize_value(parsed)
        if isinstance(value, dict):
            return {str(key): self._normalize_value(value[key]) for key in sorted(value)}
        if isinstance(value, list):
            return [self._normalize_value(item) for item in value]
        return value

    def _extract_access_snapshot(self, body: Any) -> dict[str, Any]:
        snapshot: dict[str, Any] = {}
        self._collect_access_signals(body, snapshot)
        return snapshot

    def _collect_access_signals(self, value: Any, snapshot: dict[str, Any]) -> None:
        if isinstance(value, dict):
            for raw_key, raw_value in value.items():
                key = str(raw_key).lower()
                if key in _ACCESS_KEYS and key not in snapshot:
                    snapshot[key] = raw_value
                self._collect_access_signals(raw_value, snapshot)
            return
        if isinstance(value, list):
            for item in value:
                self._collect_access_signals(item, snapshot)

    def _score_snapshot(self, snapshot: dict[str, Any]) -> int:
        score = 0
        for key, value in snapshot.items():
            normalized_key = key.lower()
            if normalized_key == "is_admin" and self._as_bool(value):
                score = max(score, _ROLE_RANKING["admin"])
                continue
            if normalized_key == "access_level":
                parsed = self._as_int(value)
                if parsed is not None:
                    score = max(score, parsed)
                continue
            if normalized_key in {"role", "roles", "permission", "permissions", "scope", "scopes", "privilege"}:
                score = max(score, self._score_role_value(value))
        return score

    def _score_role_value(self, value: Any) -> int:
        if isinstance(value, list):
            return max((self._score_role_value(item) for item in value), default=0)
        if isinstance(value, dict):
            return max((self._score_role_value(item) for item in value.values()), default=0)
        if isinstance(value, str):
            normalized = value.strip().lower().replace("-", "_").replace(" ", "_")
            return _ROLE_RANKING.get(normalized, 0)
        if isinstance(value, bool):
            return _ROLE_RANKING["admin"] if value else 0
        if isinstance(value, int):
            return value
        return 0

    def _as_bool(self, value: Any) -> bool:
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            return value.strip().lower() in {"1", "true", "yes", "y"}
        if isinstance(value, int):
            return value != 0
        return False

    def _as_int(self, value: Any) -> int | None:
        if isinstance(value, bool):
            return int(value)
        if isinstance(value, int):
            return value
        if isinstance(value, str) and value.strip().isdigit():
            return int(value.strip())
        return None
