from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

_SECRET_LIKE_KEY_RE = re.compile(
    r"(authorization|cookie|password|token|secret|api[_-]?key|client[_-]?secret)",
    re.IGNORECASE,
)
_SECRET_LIKE_VALUE_RE = re.compile(
    r"("
    r"\bbearer\s+token\b|"
    r"\bauthorization\s*[:=]|"
    r"\bcookie\s*[:=]|"
    r"\bpassword\s*[:=]|"
    r"\btoken\s*[:=]|"
    r"\bsecret\s*[:=]|"
    r"\bapi[_-]?key\s*[:=]|"
    r"\bclient[_-]?secret\s*[:=]"
    r")",
    re.IGNORECASE,
)
_MUTATING_ACTION_RE = re.compile(
    r"(write|create|update|delete|finalize|replay|approve|pay|submit|activate)",
    re.IGNORECASE,
)
_ALLOWED_SCOPE: set[str] = {"target_only", "current_endpoint"}
_MAX_REASONABLE_REQUESTS = 50


class PlaybookValidationError(ValueError):
    """Raised when a playbook fails closed during validation."""


@dataclass(frozen=True, slots=True)
class PlaybookStep:
    action: str
    identity_selector: str
    probe_template: dict[str, Any]
    expected_signal: str
    max_attempts: int
    id: str | None = None
    validator: str | None = None
    observe_only: bool = False
    safe_fixture_required: bool = False

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> PlaybookStep:
        required = {"action", "identity_selector", "probe_template", "expected_signal", "max_attempts"}
        missing = required - set(raw)
        if missing:
            raise PlaybookValidationError(f"playbook step missing required fields: {sorted(missing)}")

        action = _require_non_empty_string(raw, "action")
        identity_selector = _require_non_empty_string(raw, "identity_selector")
        probe_template = _require_mapping(raw, "probe_template")
        expected_signal = _require_non_empty_string(raw, "expected_signal")
        max_attempts = raw["max_attempts"]
        if not isinstance(max_attempts, int) or isinstance(max_attempts, bool) or max_attempts <= 0:
            raise PlaybookValidationError("playbook step max_attempts must be an explicit positive integer")

        raw_step_id = raw.get("id")
        step_id: str | None = None
        if raw_step_id is not None:
            if not isinstance(raw_step_id, str) or not raw_step_id.strip():
                raise PlaybookValidationError("playbook step id must be a non-empty string when present")
            step_id = raw_step_id.strip()

        validator = raw.get("validator")
        if validator is not None and not isinstance(validator, str):
            raise PlaybookValidationError("playbook step validator must be a string when present")
        if isinstance(validator, str):
            validator = validator.strip() or None

        observe_only = raw.get("observe_only", False)
        if not isinstance(observe_only, bool):
            raise PlaybookValidationError("playbook step observe_only must be a boolean")
        if validator is None and not observe_only:
            raise PlaybookValidationError("playbook step requires validator or observe_only=true")

        safe_fixture_required = raw.get("safe_fixture_required", False)
        if not isinstance(safe_fixture_required, bool):
            raise PlaybookValidationError("playbook step safe_fixture_required must be a boolean when present")

        assert_no_secret_like_data(probe_template, path="probe_template")
        return cls(
            id=step_id,
            action=action,
            identity_selector=identity_selector,
            probe_template=dict(probe_template),
            expected_signal=expected_signal,
            max_attempts=max_attempts,
            validator=validator,
            observe_only=observe_only,
            safe_fixture_required=safe_fixture_required,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "expected_signal": self.expected_signal,
            "id": self.id,
            "identity_selector": self.identity_selector,
            "max_attempts": self.max_attempts,
            "observe_only": self.observe_only,
            "probe_template": _stable_value(self.probe_template),
            "safe_fixture_required": self.safe_fixture_required,
            "validator": self.validator,
        }


@dataclass(frozen=True, slots=True)
class AttackPlaybook:
    id: str
    attack_class: str
    preconditions: dict[str, Any]
    steps: list[PlaybookStep]
    validators: dict[str, Any]
    safety_budget: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> AttackPlaybook:
        required = {"id", "attack_class", "preconditions", "steps", "validators", "safety_budget"}
        missing = required - set(raw)
        if missing:
            raise PlaybookValidationError(f"playbook missing required fields: {sorted(missing)}")

        playbook_id = _require_non_empty_string(raw, "id")
        attack_class = _require_non_empty_string(raw, "attack_class")
        preconditions = _require_mapping(raw, "preconditions")
        validators = _require_mapping(raw, "validators")
        safety_budget = _require_mapping(raw, "safety_budget")
        raw_steps = raw["steps"]
        if not isinstance(raw_steps, list) or not raw_steps:
            raise PlaybookValidationError("playbook steps must be a non-empty list")

        steps = [PlaybookStep.from_dict(step) for step in raw_steps if isinstance(step, dict)]
        if len(steps) != len(raw_steps):
            raise PlaybookValidationError("playbook steps must be objects")

        playbook = cls(
            id=playbook_id,
            attack_class=attack_class,
            preconditions=dict(preconditions),
            steps=steps,
            validators=dict(validators),
            safety_budget=dict(safety_budget),
        )
        playbook.validate()
        return playbook

    def validate(self) -> None:
        max_requests = self.safety_budget.get("max_requests")
        if not isinstance(max_requests, int) or isinstance(max_requests, bool) or max_requests <= 0:
            raise PlaybookValidationError("safety_budget.max_requests must be a positive integer")
        if max_requests > _MAX_REASONABLE_REQUESTS:
            raise PlaybookValidationError("safety_budget.max_requests exceeds safe upper bound")

        scope = self.safety_budget.get("scope")
        if not isinstance(scope, str) or scope not in _ALLOWED_SCOPE:
            raise PlaybookValidationError("safety_budget.scope must be target_only or current_endpoint")

        if "rate_limit_rps" in self.safety_budget:
            rate_limit_rps = self.safety_budget["rate_limit_rps"]
            if not isinstance(rate_limit_rps, (int, float)) or isinstance(rate_limit_rps, bool) or rate_limit_rps <= 0:
                raise PlaybookValidationError("safety_budget.rate_limit_rps must be a positive number")
            if float(rate_limit_rps) > 1.0:
                raise PlaybookValidationError("safety_budget.rate_limit_rps cannot exceed 1.0")

        if "proof_gate" in self.safety_budget and self.safety_budget["proof_gate"] not in {"default", "unchanged"}:
            raise PlaybookValidationError("safety_budget.proof_gate cannot be overridden by playbook")
        for forbidden_key in ("proof_confidence_threshold", "proof_gate_override", "scope_override", "rate_override"):
            if forbidden_key in self.safety_budget:
                raise PlaybookValidationError(f"safety_budget.{forbidden_key} is not allowed")

        step_attempts = sum(step.max_attempts for step in self.steps)
        if step_attempts > max_requests:
            raise PlaybookValidationError("playbook steps exceed safety_budget.max_requests")

        explicit_safe_fixture = self.safety_budget.get("safe_fixture_required") is True or self.safety_budget.get(
            "requires_explicit_safe_fixture"
        ) is True
        max_attempts_per_step = self.safety_budget.get("max_attempts_per_step")
        if max_attempts_per_step is not None:
            if (
                not isinstance(max_attempts_per_step, int)
                or isinstance(max_attempts_per_step, bool)
                or max_attempts_per_step <= 0
            ):
                raise PlaybookValidationError("safety_budget.max_attempts_per_step must be a positive integer")

        for step in self.steps:
            if step.max_attempts > max_requests:
                raise PlaybookValidationError("playbook step max_attempts cannot exceed safety_budget.max_requests")
            if isinstance(max_attempts_per_step, int) and step.max_attempts > max_attempts_per_step:
                raise PlaybookValidationError(
                    "playbook step max_attempts cannot exceed safety_budget.max_attempts_per_step"
                )
            if _is_mutating_action(step.action) and not (
                step.observe_only or step.safe_fixture_required or explicit_safe_fixture
            ):
                raise PlaybookValidationError(
                    "mutating playbook steps require observe_only=true or explicit safe fixture"
                )

        assert_no_secret_like_data(self.preconditions, path="preconditions")
        assert_no_secret_like_data(self.validators, path="validators")
        assert_no_secret_like_data(self.safety_budget, path="safety_budget")

    def to_dict(self) -> dict[str, Any]:
        return {
            "attack_class": self.attack_class,
            "id": self.id,
            "preconditions": _stable_value(self.preconditions),
            "safety_budget": _stable_value(self.safety_budget),
            "steps": [step.to_dict() for step in self.steps],
            "validators": _stable_value(self.validators),
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))


def _require_non_empty_string(raw: dict[str, Any], key: str) -> str:
    value = raw.get(key)
    if not isinstance(value, str) or not value.strip():
        raise PlaybookValidationError(f"playbook field {key} must be a non-empty string")
    return value.strip()


def _require_mapping(raw: dict[str, Any], key: str) -> dict[str, Any]:
    value = raw.get(key)
    if not isinstance(value, dict):
        raise PlaybookValidationError(f"playbook field {key} must be an object")
    return value


def assert_no_secret_like_data(value: Any, *, path: str) -> None:
    if isinstance(value, dict):
        for key, nested in value.items():
            if not isinstance(key, str):
                raise PlaybookValidationError(f"{path} contains a non-string field name")
            nested_path = f"{path}.{key}"
            if _SECRET_LIKE_KEY_RE.search(key):
                raise PlaybookValidationError(f"{nested_path} looks like a secret-bearing field")
            assert_no_secret_like_data(nested, path=nested_path)
        return

    if isinstance(value, list):
        for index, nested in enumerate(value):
            assert_no_secret_like_data(nested, path=f"{path}[{index}]")
        return

    if isinstance(value, str) and _SECRET_LIKE_VALUE_RE.search(value):
        raise PlaybookValidationError(f"{path} looks like a secret-bearing value")


def _stable_value(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _stable_value(value[key]) for key in sorted(value)}
    if isinstance(value, list):
        return [_stable_value(item) for item in value]
    return value


def _is_mutating_action(action: str) -> bool:
    return bool(_MUTATING_ACTION_RE.search(action))
