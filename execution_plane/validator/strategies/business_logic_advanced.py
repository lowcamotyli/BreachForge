from __future__ import annotations

import json
import math
import statistics
from typing import Any

from execution_plane.validator.strategies.base import ValidationStrategy
from storage.db.models import ProofArtifact, RawProbe


class NegativeValueStrategy(ValidationStrategy):
    _THRESHOLD = 0.90

    def expected_attack_class(self) -> str:
        return "negative_value"

    def expected_proof_type(self) -> str:
        return "differential"

    def validate(self, attack_probe: RawProbe, control_probe: RawProbe | None) -> ProofArtifact | None:
        del control_probe
        response = attack_probe.response
        if not (200 <= _response_status(response) < 300):
            return None

        body = _extract_response_body(response)
        accepted_state = _extract_negative_state(body)
        if accepted_state is None:
            return None

        confidence = 0.90
        if confidence < self._THRESHOLD:
            return None

        request = attack_probe.request
        endpoint = str(request.get("url") or "")
        param = str(request.get("target_parameter") or "")

        return ProofArtifact(
            attack_task_id=attack_probe.attack_task_id,
            proof_type=self.expected_proof_type(),
            confidence_score=confidence,
            attack_probe_id=attack_probe.id,
            control_probe_id=None,
            summary="Negative value accepted: server processed a negative numeric parameter without rejection",
            evidence_notes=f"endpoint={endpoint}, param={param}, probe_value=-1, accepted_state={accepted_state}",
        )


class IntegerOverflowStrategy(ValidationStrategy):
    _THRESHOLD = 0.85
    _TOKENS = (
        "overflow",
        "out of range",
        "int32",
        "int64",
        "integer",
        "too large",
        "exceeds maximum",
    )

    def expected_attack_class(self) -> str:
        return "integer_overflow"

    def expected_proof_type(self) -> str:
        return "differential"

    def validate(self, attack_probe: RawProbe, control_probe: RawProbe | None) -> ProofArtifact | None:
        del control_probe
        request_body = _parse_body(attack_probe)
        probe_value = _extract_probe_value(request_body)

        response_body = _extract_response_body(attack_probe.response)
        response_text = _response_text(attack_probe.response).lower()
        matched = next((token for token in self._TOKENS if token in response_text), None)

        wrapped = False
        if matched is None and isinstance(probe_value, (int, float)) and probe_value > 1_000_000:
            observed = _extract_any_numeric(response_body)
            if observed is not None and (observed < 0 or abs(observed) < abs(probe_value) * 0.001):
                wrapped = True

        if matched is None and not wrapped:
            return None

        confidence = 0.85
        if confidence < self._THRESHOLD:
            return None

        signal = matched or "wrapped"
        return ProofArtifact(
            attack_task_id=attack_probe.attack_task_id,
            proof_type=self.expected_proof_type(),
            confidence_score=confidence,
            attack_probe_id=attack_probe.id,
            control_probe_id=None,
            summary="Integer overflow behavior detected: server revealed type or wrapped numeric boundary",
            evidence_notes=f"probe_value={probe_value}, overflow_signal={signal}",
        )


class PriceManipulationStrategy(ValidationStrategy):
    _THRESHOLD = 0.88

    def expected_attack_class(self) -> str:
        return "price_manipulation"

    def expected_proof_type(self) -> str:
        return "differential"

    def validate(self, attack_probe: RawProbe, control_probe: RawProbe | None) -> ProofArtifact | None:
        del control_probe
        response = attack_probe.response
        if not (200 <= _response_status(response) < 300):
            return None

        request_body = _parse_body(attack_probe)
        manipulation_type = str(_get_value(request_body, "manipulation_type") or "")
        original_price = _get_value(request_body, "original_price")
        manipulated_price = _get_value(request_body, "manipulated_price")

        body = _extract_response_body(response)
        accepted_flag = _is_true(_get_value(body, "currency_accepted")) or _is_true(_get_value(body, "price_accepted"))
        low_price_accepted = False
        if manipulation_type in {"unit_confusion", "currency_swap"}:
            accepted_value = _get_value(body, "price")
            if accepted_value is None:
                accepted_value = _get_value(body, "amount")
            if isinstance(accepted_value, (int, float)) and float(accepted_value) <= 0.10:
                low_price_accepted = True

        if not (accepted_flag or low_price_accepted):
            return None

        confidence = 0.88
        if confidence < self._THRESHOLD:
            return None

        return ProofArtifact(
            attack_task_id=attack_probe.attack_task_id,
            proof_type=self.expected_proof_type(),
            confidence_score=confidence,
            attack_probe_id=attack_probe.id,
            control_probe_id=None,
            summary="Price manipulation accepted: server processed mismatched price unit or currency without validation",
            evidence_notes=(
                f"original_price={original_price}, manipulated_price={manipulated_price}, "
                f"manipulation_type={manipulation_type}"
            ),
        )


class AccountEnumerationTimingStrategy(ValidationStrategy):
    _THRESHOLD = 0.80

    def expected_attack_class(self) -> str:
        return "account_enumeration_timing"

    def expected_proof_type(self) -> str:
        return "timing"

    def validate(self, attack_probe: RawProbe, control_probe: RawProbe | None) -> ProofArtifact | None:
        del control_probe
        body = _parse_body(attack_probe)
        pairs_raw = _get_value(body, "timing_pairs")
        if not isinstance(pairs_raw, list) or len(pairs_raw) < 10:
            return None

        deltas: list[float] = []
        for pair in pairs_raw:
            if not isinstance(pair, dict):
                continue
            existing_ms = pair.get("existing_ms")
            nonexistent_ms = pair.get("nonexistent_ms")
            if not isinstance(existing_ms, (int, float)) or not isinstance(nonexistent_ms, (int, float)):
                continue
            deltas.append(float(nonexistent_ms) - float(existing_ms))

        if len(deltas) < 10:
            return None

        mean_delta = statistics.mean(deltas)
        std_dev = statistics.stdev(deltas) if len(deltas) > 1 else 0.0
        sigma_ratio = math.inf if std_dev == 0 else mean_delta / std_dev

        if not (mean_delta > 20 and mean_delta > (2 * std_dev)):
            return None

        confidence = 0.80
        if confidence < self._THRESHOLD:
            return None

        return ProofArtifact(
            attack_task_id=attack_probe.attack_task_id,
            proof_type=self.expected_proof_type(),
            confidence_score=confidence,
            attack_probe_id=attack_probe.id,
            control_probe_id=None,
            summary="Timing oracle detected: statistically significant response time differential for existing vs non-existing identifiers",
            evidence_notes=(
                f"sample_count={len(deltas)}, mean_delta_ms={mean_delta:.1f}, "
                f"std_dev_ms={std_dev:.1f}, sigma_ratio={sigma_ratio:.1f}"
            ),
        )


class InventoryReservationStrategy(ValidationStrategy):
    _THRESHOLD = 0.87

    def expected_attack_class(self) -> str:
        return "inventory_reservation"

    def expected_proof_type(self) -> str:
        return "reproduction"

    def validate(self, attack_probe: RawProbe, control_probe: RawProbe | None) -> ProofArtifact | None:
        del control_probe
        body = _parse_body(attack_probe)
        cycles = _get_value(body, "reservation_cycles")
        decremented = _get_value(body, "inventory_decremented")
        if not isinstance(cycles, int) or not isinstance(decremented, bool):
            return None

        if not (cycles >= 2 and decremented is False):
            return None

        confidence = 0.87
        if confidence < self._THRESHOLD:
            return None

        endpoint = str(attack_probe.request.get("url") or "")
        return ProofArtifact(
            attack_task_id=attack_probe.attack_task_id,
            proof_type=self.expected_proof_type(),
            confidence_score=confidence,
            attack_probe_id=attack_probe.id,
            control_probe_id=None,
            summary="Inventory reservation exploit: item reserved multiple cycles without inventory decrement",
            evidence_notes=f"cycle_count={cycles}, inventory_decremented=False, endpoint={endpoint}",
        )


def _response_text(response: dict[str, Any]) -> str:
    for key in ("body", "json", "data", "text"):
        if key not in response:
            continue
        value = response[key]
        if isinstance(value, str):
            return value
        if isinstance(value, (dict, list)):
            return json.dumps(value, separators=(",", ":"))
        return str(value)
    return ""


def _response_status(response: dict[str, Any]) -> int:
    status = response.get("status")
    if isinstance(status, int):
        return status
    status_code = response.get("status_code")
    if isinstance(status_code, int):
        return status_code
    return 0


def _parse_body(probe: RawProbe) -> Any:
    request = probe.request
    body = request.get("body", "")
    if isinstance(body, str):
        try:
            return json.loads(body)
        except (TypeError, ValueError):
            return body
    return body


def _extract_response_body(response: dict[str, Any]) -> Any:
    for key in ("body", "json", "data", "text"):
        if key not in response:
            continue
        value = response[key]
        if isinstance(value, str):
            try:
                return json.loads(value)
            except (TypeError, ValueError):
                return value
        return value
    return None


def _extract_negative_state(value: Any) -> str | None:
    if isinstance(value, (int, float)) and value < 0:
        return str(value)
    if isinstance(value, dict):
        for key, item in value.items():
            nested = _extract_negative_state(item)
            if nested is not None:
                return nested
            if str(key).lower() in {"balance", "total", "amount", "credits"} and isinstance(item, (int, float)) and item < 0:
                return f"{key}={item}"
    if isinstance(value, list):
        for item in value:
            nested = _extract_negative_state(item)
            if nested is not None:
                return nested
    return None


def _extract_probe_value(body: Any) -> Any:
    for key in ("probe_value", "value", "amount", "target_value", "balance", "credits", "price", "quantity", "total", "fee", "cost", "sum"):
        value = _get_value(body, key)
        if value is not None:
            return value
    if isinstance(body, dict):
        for v in body.values():
            if isinstance(v, (int, float)):
                return v
    return None


def _extract_any_numeric(value: Any) -> float | None:
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, dict):
        for item in value.values():
            found = _extract_any_numeric(item)
            if found is not None:
                return found
    if isinstance(value, list):
        for item in value:
            found = _extract_any_numeric(item)
            if found is not None:
                return found
    return None


def _get_value(data: Any, key: str) -> Any:
    if not isinstance(data, dict):
        return None
    return data.get(key)


def _is_true(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() == "true"
    return False
