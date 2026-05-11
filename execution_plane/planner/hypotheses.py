from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Iterable

_HIGH_RISK_PARAMETER_ORDER: tuple[str, ...] = (
    "id",
    "user_id",
    "org_id",
    "tenant_id",
    "role",
    "status",
    "price",
    "redirect",
    "callback",
)
_HIGH_RISK_PARAMETER_SET: frozenset[str] = frozenset(_HIGH_RISK_PARAMETER_ORDER)
_FLOW_HINT_ORDER: tuple[str, ...] = ("create", "update", "delete", "approve", "status", "export", "admin")
_PATH_PARAMETER_RE = re.compile(r"\{([a-zA-Z_][a-zA-Z0-9_]*)\}")


@dataclass(frozen=True, slots=True)
class AttackSignal:
    kind: str
    key: str
    value: str
    endpoint: str | None = None
    method: str | None = None
    location: str | None = None
    strength: float = 1.0
    tags: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        normalized_kind = self.kind.strip().lower()
        if normalized_kind not in {"endpoint", "param", "identity", "response_delta", "state_delta"}:
            raise ValueError("unsupported signal kind")

        normalized_key = self.key.strip().lower()
        normalized_value = self.value.strip().lower()
        if not normalized_key:
            raise ValueError("signal key must be non-empty")
        if not normalized_value:
            raise ValueError("signal value must be non-empty")

        normalized_endpoint = _normalize_optional_string(self.endpoint, lowercase=True)
        normalized_method = _normalize_optional_string(self.method, uppercase=True)
        normalized_location = _normalize_optional_string(self.location, lowercase=True)
        if normalized_location in {"json", "form"}:
            normalized_location = "body"

        rounded_strength = round(float(self.strength), 6)
        if rounded_strength <= 0.0:
            raise ValueError("signal strength must be positive")

        normalized_tags = tuple(sorted({tag.strip().lower() for tag in self.tags if tag.strip()}))

        object.__setattr__(self, "kind", normalized_kind)
        object.__setattr__(self, "key", normalized_key)
        object.__setattr__(self, "value", normalized_value)
        object.__setattr__(self, "endpoint", normalized_endpoint)
        object.__setattr__(self, "method", normalized_method)
        object.__setattr__(self, "location", normalized_location)
        object.__setattr__(self, "strength", rounded_strength)
        object.__setattr__(self, "tags", normalized_tags)

    def to_dict(self) -> dict[str, Any]:
        return {
            "endpoint": self.endpoint,
            "key": self.key,
            "kind": self.kind,
            "location": self.location,
            "method": self.method,
            "strength": self.strength,
            "tags": list(self.tags),
            "value": self.value,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), separators=(",", ":"), sort_keys=True)


@dataclass(frozen=True, slots=True)
class AttackHypothesis:
    type: str
    target: str
    rationale: str
    required_identities: tuple[str, ...] = field(default_factory=tuple)
    candidate_playbooks: tuple[str, ...] = field(default_factory=tuple)
    confidence: float = 0.5
    signals: tuple[AttackSignal, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        normalized_type = self.type.strip().lower()
        normalized_target = self.target.strip().lower()
        normalized_rationale = " ".join(self.rationale.strip().split())
        if not normalized_type:
            raise ValueError("hypothesis type must be non-empty")
        if not normalized_target:
            raise ValueError("hypothesis target must be non-empty")
        if not normalized_rationale:
            raise ValueError("hypothesis rationale must be non-empty")

        identities = tuple(sorted({identity.strip().lower() for identity in self.required_identities if identity.strip()}))
        playbooks = tuple(sorted({playbook.strip().lower() for playbook in self.candidate_playbooks if playbook.strip()}))
        normalized_confidence = min(max(round(float(self.confidence), 6), 0.0), 1.0)
        normalized_signals = tuple(sorted(self.signals, key=lambda signal: signal.to_json()))

        object.__setattr__(self, "type", normalized_type)
        object.__setattr__(self, "target", normalized_target)
        object.__setattr__(self, "rationale", normalized_rationale)
        object.__setattr__(self, "required_identities", identities)
        object.__setattr__(self, "candidate_playbooks", playbooks)
        object.__setattr__(self, "confidence", normalized_confidence)
        object.__setattr__(self, "signals", normalized_signals)

    def key(self) -> str:
        return f"{self.type}|{self.target}|{','.join(self.candidate_playbooks)}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "candidate_playbooks": list(self.candidate_playbooks),
            "confidence": self.confidence,
            "rationale": self.rationale,
            "required_identities": list(self.required_identities),
            "signals": [signal.to_dict() for signal in self.signals],
            "target": self.target,
            "type": self.type,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), separators=(",", ":"), sort_keys=True)


def extract_high_risk_parameters(endpoint: Any) -> tuple[str, ...]:
    seen: set[str] = set()
    ordered: list[str] = []
    for raw_name in _iter_endpoint_parameter_names(endpoint):
        lowered = raw_name.strip().lower()
        if lowered not in _HIGH_RISK_PARAMETER_SET:
            continue
        if lowered in seen:
            continue
        seen.add(lowered)
        ordered.append(lowered)

    ordered.sort(key=lambda value: (_HIGH_RISK_PARAMETER_ORDER.index(value), value))
    return tuple(ordered)


def extract_flow_hints_from_endpoint(endpoint: Any) -> tuple[str, ...]:
    candidates = [str(getattr(endpoint, "url_pattern", "")), str(getattr(endpoint, "method", ""))]
    parameters = getattr(endpoint, "parameters", [])
    if isinstance(parameters, list):
        for parameter in parameters:
            if not isinstance(parameter, dict):
                continue
            candidates.append(str(parameter.get("name") or ""))

    lowered_blob = " ".join(part.lower() for part in candidates)
    matched = [hint for hint in _FLOW_HINT_ORDER if hint in lowered_blob]
    return tuple(matched)


def extract_flow_hints_from_asset_map(asset_map: Any) -> dict[str, tuple[str, ...]]:
    raw_endpoints = getattr(asset_map, "endpoints", [])
    if not isinstance(raw_endpoints, list):
        return {}

    collected: dict[str, tuple[str, ...]] = {}
    for endpoint in raw_endpoints:
        url_pattern = str(getattr(endpoint, "url_pattern", "")).strip().lower()
        method = str(getattr(endpoint, "method", "GET")).strip().upper() or "GET"
        endpoint_key = f"{method} {url_pattern}"
        hints = extract_flow_hints_from_endpoint(endpoint)
        if hints:
            collected[endpoint_key] = hints
    return dict(sorted(collected.items(), key=lambda item: item[0]))


def build_endpoint_signals(endpoint: Any) -> tuple[AttackSignal, ...]:
    url_pattern = str(getattr(endpoint, "url_pattern", "")).strip().lower()
    method = str(getattr(endpoint, "method", "GET")).strip().upper() or "GET"
    signals: list[AttackSignal] = [
        AttackSignal(
            kind="endpoint",
            key="endpoint",
            value=f"{method} {url_pattern}",
            endpoint=url_pattern,
            method=method,
            tags=("endpoint",),
        )
    ]

    for parameter in extract_high_risk_parameters(endpoint):
        signals.append(
            AttackSignal(
                kind="param",
                key="high_risk_param",
                value=parameter,
                endpoint=url_pattern,
                method=method,
                tags=("high_risk", "param"),
            )
        )

    for hint in extract_flow_hints_from_endpoint(endpoint):
        signals.append(
            AttackSignal(
                kind="state_delta",
                key="flow_hint",
                value=hint,
                endpoint=url_pattern,
                method=method,
                tags=("flow",),
            )
        )

    return tuple(sorted(signals, key=lambda signal: signal.to_json()))


def _iter_endpoint_parameter_names(endpoint: Any) -> Iterable[str]:
    parameters = getattr(endpoint, "parameters", [])
    if isinstance(parameters, list):
        for parameter in parameters:
            if not isinstance(parameter, dict):
                continue
            name = parameter.get("name")
            if isinstance(name, str) and name.strip():
                yield name

    url_pattern = str(getattr(endpoint, "url_pattern", ""))
    for path_name in _PATH_PARAMETER_RE.findall(url_pattern):
        if path_name.strip():
            yield path_name


def _normalize_optional_string(
    value: str | None,
    *,
    lowercase: bool = False,
    uppercase: bool = False,
) -> str | None:
    if value is None:
        return None
    normalized = value.strip()
    if not normalized:
        return None
    if lowercase:
        return normalized.lower()
    if uppercase:
        return normalized.upper()
    return normalized
