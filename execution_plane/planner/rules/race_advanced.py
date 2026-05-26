from __future__ import annotations

import json
from typing import Any
from uuid import uuid4

from execution_plane.planner.rules.base import AssetMap, AttackRule, ScanContext
from storage.db.models import AttackTask, Endpoint

_LIMIT_TOKENS: frozenset[str] = frozenset({"limit", "max_per_user", "one_per_account", "quota", "balance"})
_DOUBLE_SPEND_TOKENS: frozenset[str] = frozenset({"transfer", "withdraw", "debit", "purchase", "checkout", "redeem"})
_INVENTORY_TOKENS: frozenset[str] = frozenset({"reserve", "hold", "stock", "inventory", "allocation", "slot"})
_IDEMPOTENCY_HEADER: str = "idempotency-key"
_IDEMPOTENCY_PARAM: str = "idempotency_key"


class RaceAdvancedRule(AttackRule):
    requires_auth = False
    attack_class: str = "race_condition"
    name: str = "RaceAdvancedRule"

    def matches(self, endpoint: Endpoint, asset_map: AssetMap) -> bool:
        del asset_map
        if self._has_existing_race_finding(endpoint=endpoint):
            return False
        return bool(
            self.detect_limit_override_candidates(endpoint)
            or self.detect_double_spend_candidates(endpoint)
            or self.detect_inventory_reservation_candidates(endpoint)
            or self.detect_idempotency_bypass_candidates(endpoint)
        )

    def generate_tasks(self, endpoint: Endpoint, context: ScanContext) -> list[AttackTask]:
        if self._has_existing_race_finding(endpoint=endpoint, context=context):
            return []

        candidates: list[dict[str, Any]] = []
        candidates.extend(self.detect_limit_override_candidates(endpoint))
        candidates.extend(self.detect_double_spend_candidates(endpoint))
        candidates.extend(self.detect_inventory_reservation_candidates(endpoint))
        candidates.extend(self.detect_idempotency_bypass_candidates(endpoint))

        tasks: list[AttackTask] = []
        seen: set[tuple[str, str]] = set()
        for candidate in candidates:
            target_parameter = str(candidate.get("target_parameter") or "race_window")
            attack_class = str(candidate["attack_class"])
            dedup_key = (attack_class, target_parameter)
            if dedup_key in seen:
                continue
            seen.add(dedup_key)
            hypothesis_payload: dict[str, Any] = {
                "probe_type": "race_advanced_candidate",
                "endpoint": endpoint.url_pattern,
                "attack_class": attack_class,
                "priority": float(candidate["priority"]),
                "rationale": str(candidate["rationale"]),
                "method": endpoint.method.upper(),
                "_race_group_id": str(uuid4()),
            }
            tasks.append(
                AttackTask(
                    scan_id=context.scan_id,
                    endpoint_id=endpoint.id,
                    attack_class=attack_class,
                    target_parameter=target_parameter,
                    priority_score=float(candidate["priority"]),
                    hypothesis=json.dumps(hypothesis_payload, sort_keys=True),
                )
            )
        return tasks

    def expected_proof_signal(self) -> str:
        return "Concurrent requests bypass business invariants: limits, spend integrity, or idempotency guarantees"

    def detect_limit_override_candidates(self, endpoint: Endpoint) -> list[dict[str, Any]]:
        matched = self._matching_parameter_tokens(endpoint=endpoint, tokens=_LIMIT_TOKENS)
        if not matched:
            return []
        token = matched[0]
        return [
            {
                "endpoint": endpoint.url_pattern,
                "attack_class": "limit_override_race",
                "priority": 0.96,
                "rationale": f"Detected limit-control token '{token}' in request shape; race may overrun server-side quota checks.",
                "target_parameter": token,
            }
        ]

    def detect_double_spend_candidates(self, endpoint: Endpoint) -> list[dict[str, Any]]:
        path_matches = [token for token in _DOUBLE_SPEND_TOKENS if token in endpoint.url_pattern.lower()]
        param_matches = self._matching_parameter_tokens(endpoint=endpoint, tokens=_DOUBLE_SPEND_TOKENS)
        if not path_matches and not param_matches:
            return []
        token = (path_matches + param_matches)[0]
        return [
            {
                "endpoint": endpoint.url_pattern,
                "attack_class": "double_spend",
                "priority": 0.97,
                "rationale": f"Detected monetary transfer token '{token}' in path/parameters; concurrent execution may permit duplicate spending.",
                "target_parameter": token,
            }
        ]

    def detect_idempotency_bypass_candidates(self, endpoint: Endpoint) -> list[dict[str, Any]]:
        parameter_names = self._parameter_names(endpoint)
        lowered_names = {name.lower() for name in parameter_names}
        if _IDEMPOTENCY_PARAM not in lowered_names and _IDEMPOTENCY_HEADER not in lowered_names:
            return []

        target = _IDEMPOTENCY_PARAM if _IDEMPOTENCY_PARAM in lowered_names else _IDEMPOTENCY_HEADER
        return [
            {
                "endpoint": endpoint.url_pattern,
                "attack_class": "idempotency_bypass",
                "priority": 0.95,
                "rationale": "Detected idempotency key marker in request metadata; races can expose weak key-lock semantics.",
                "target_parameter": target,
            }
        ]

    def detect_inventory_reservation_candidates(self, endpoint: Endpoint) -> list[dict[str, Any]]:
        path_matches = [token for token in _INVENTORY_TOKENS if token in endpoint.url_pattern.lower()]
        param_matches = self._matching_parameter_tokens(endpoint=endpoint, tokens=_INVENTORY_TOKENS)
        if not path_matches and not param_matches:
            return []
        token = (path_matches + param_matches)[0]
        return [
            {
                "endpoint": endpoint.url_pattern,
                "attack_class": "inventory_reservation_abuse",
                "priority": 0.96,
                "rationale": f"Detected reservation token '{token}' in path/parameters; race on hold/stock allocation may over-reserve inventory.",
                "target_parameter": token,
            }
        ]

    def _parameter_names(self, endpoint: Endpoint) -> list[str]:
        names: list[str] = []
        for parameter in endpoint.parameters:
            if not isinstance(parameter, dict):
                continue
            for key in ("name", "key", "param", "parameter", "header"):
                raw = parameter.get(key)
                if isinstance(raw, str) and raw.strip():
                    names.append(raw.strip())
            raw_location = parameter.get("location")
            raw_name = parameter.get("name")
            if (
                isinstance(raw_location, str)
                and raw_location.lower() == "header"
                and isinstance(raw_name, str)
                and raw_name.strip()
            ):
                names.append(raw_name.strip())
        return names

    def _matching_parameter_tokens(self, endpoint: Endpoint, tokens: frozenset[str]) -> list[str]:
        names = self._parameter_names(endpoint)
        matches: list[str] = []
        for name in names:
            lowered = name.lower()
            for token in tokens:
                if token in lowered:
                    matches.append(token)
        return list(dict.fromkeys(matches))

    def _has_existing_race_finding(self, endpoint: Endpoint, context: ScanContext | None = None) -> bool:
        if context is not None:
            for finding in context.prior_findings:
                if finding.affected_endpoint_id == endpoint.id and finding.attack_class == "race_condition":
                    return True
        for finding in endpoint.findings:
            if finding.attack_class == "race_condition":
                return True
        return False
