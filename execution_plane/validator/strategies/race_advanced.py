from __future__ import annotations

import json
from typing import Any

from execution_plane.validator.strategies.base import ValidationStrategy
from storage.db.models import ProofArtifact, RawProbe


class LimitOverrideRaceStrategy(ValidationStrategy):
    _MIN_PROOF_CONFIDENCE_THRESHOLD = 0.85
    _BASE_CONFIDENCE = 0.92
    _SINGLE_BURST_CONFIDENCE_CAP = 0.70
    _MAX_BURST_CONCURRENCY = 5

    def expected_attack_class(self) -> str:
        return "limit_override_race"

    def expected_proof_type(self) -> str:
        return "reproduction"

    def validate(self, attack_probe: RawProbe, control_probe: RawProbe | None) -> ProofArtifact | None:
        del control_probe
        request = attack_probe.request
        response = attack_probe.response

        requests_sent = _to_int(_get_value(request, "requests_sent"), default=0)
        accepted_count = _to_int(_get_value(response, "accepted_count"), default=0)
        allowed_limit = _to_int(
            _first_non_none(
                _get_value(request, "allowed_limit"),
                _get_value(response, "allowed_limit"),
                1,
            ),
            default=1,
        )

        if requests_sent <= 0:
            requests_sent = self._MAX_BURST_CONCURRENCY
        if requests_sent > self._MAX_BURST_CONCURRENCY:
            requests_sent = self._MAX_BURST_CONCURRENCY

        if not (accepted_count > allowed_limit):
            return None

        confidence = _reproducibility_confidence(
            request=request,
            full_confidence=self._BASE_CONFIDENCE,
            single_burst_cap=self._SINGLE_BURST_CONFIDENCE_CAP,
        )
        if confidence < self._MIN_PROOF_CONFIDENCE_THRESHOLD:
            return None
        if not _requires_final_state_proof(attack_probe):
            return None

        return ProofArtifact(
            attack_task_id=attack_probe.attack_task_id,
            proof_type=self.expected_proof_type(),
            confidence_score=confidence,
            attack_probe_id=attack_probe.id,
            control_probe_id=None,
            summary="Limit override race: concurrent requests bypassed configured operation cap",
            evidence_notes=(
                "probe_type=race_concurrent, "
                f"requests_sent={requests_sent}, accepted_count={accepted_count}, allowed_limit={allowed_limit}"
            ),
        )


class DoubleSpendStrategy(ValidationStrategy):
    _MIN_PROOF_CONFIDENCE_THRESHOLD = 0.85
    _BASE_CONFIDENCE = 0.94
    _SINGLE_BURST_CONFIDENCE_CAP = 0.70
    _BURST_CONCURRENCY = 2

    def expected_attack_class(self) -> str:
        return "double_spend"

    def expected_proof_type(self) -> str:
        return "reproduction"

    def validate(self, attack_probe: RawProbe, control_probe: RawProbe | None) -> ProofArtifact | None:
        del control_probe
        request = attack_probe.request
        response = attack_probe.response

        if not _is_safe_fixture(request):
            return None

        first_response = _get_value(response, "first_response")
        second_response = _get_value(response, "second_response")
        first_success = _is_success(first_response)
        second_success = _is_success(second_response)

        original_balance = _to_float(_get_value(response, "original_balance"), default=0.0)
        transfer_sum = _to_float(_get_value(response, "transfer_sum"), default=float("nan"))
        if transfer_sum != transfer_sum:
            first_amount = _to_float(_extract_amount(first_response), default=0.0)
            second_amount = _to_float(_extract_amount(second_response), default=0.0)
            transfer_sum = first_amount + second_amount

        if not (first_success and second_success and transfer_sum > original_balance):
            return None

        confidence = _reproducibility_confidence(
            request=request,
            full_confidence=self._BASE_CONFIDENCE,
            single_burst_cap=self._SINGLE_BURST_CONFIDENCE_CAP,
        )
        if confidence < self._MIN_PROOF_CONFIDENCE_THRESHOLD:
            return None
        if not _requires_final_state_proof(attack_probe):
            return None

        first_compact = _compact(first_response)
        second_compact = _compact(second_response)
        return ProofArtifact(
            attack_task_id=attack_probe.attack_task_id,
            proof_type=self.expected_proof_type(),
            confidence_score=confidence,
            attack_probe_id=attack_probe.id,
            control_probe_id=None,
            summary="Double-spend race: two concurrent identical transfer requests were both accepted",
            evidence_notes=(
                "probe_type=race_concurrent, "
                f"burst_concurrency={self._BURST_CONCURRENCY}, "
                f"first_response={first_compact}, second_response={second_compact}, "
                f"transfer_sum={transfer_sum}, original_balance={original_balance}"
            ),
        )


class IdempotencyBypassStrategy(ValidationStrategy):
    _MIN_PROOF_CONFIDENCE_THRESHOLD = 0.85
    _BASE_CONFIDENCE = 0.88
    _SINGLE_BURST_CONFIDENCE_CAP = 0.70

    def expected_attack_class(self) -> str:
        return "idempotency_bypass"

    def expected_proof_type(self) -> str:
        return "reproduction"

    def validate(self, attack_probe: RawProbe, control_probe: RawProbe | None) -> ProofArtifact | None:
        del control_probe
        request = attack_probe.request
        response = attack_probe.response

        idempotency_key = _first_non_none(
            _get_value(request, "idempotency_key"),
            _get_value(request, "Idempotency-Key"),
            _get_value(_get_value(request, "headers"), "Idempotency-Key"),
            "",
        )
        if not isinstance(idempotency_key, str) or idempotency_key == "":
            return None

        first_params = _get_value(request, "first_params")
        second_params = _get_value(request, "second_params")
        if not _responses_differ(first_params, second_params):
            return None

        first_response = _get_value(response, "first_response")
        second_response = _get_value(response, "second_response")
        if not _responses_differ(first_response, second_response):
            return None

        confidence = _reproducibility_confidence(
            request=request,
            full_confidence=self._BASE_CONFIDENCE,
            single_burst_cap=self._SINGLE_BURST_CONFIDENCE_CAP,
        )
        if confidence < self._MIN_PROOF_CONFIDENCE_THRESHOLD:
            return None
        if not _requires_final_state_proof(attack_probe):
            return None

        return ProofArtifact(
            attack_task_id=attack_probe.attack_task_id,
            proof_type=self.expected_proof_type(),
            confidence_score=confidence,
            attack_probe_id=attack_probe.id,
            control_probe_id=None,
            summary="Idempotency bypass: second request executed with same Idempotency-Key and different parameters",
            evidence_notes=(
                "probe_type=race_concurrent, "
                f"idempotency_key={idempotency_key}, "
                f"first_response={_compact(first_response)}, second_response={_compact(second_response)}"
            ),
        )


class DistributedLockEvasionStrategy(ValidationStrategy):
    _MIN_PROOF_CONFIDENCE_THRESHOLD = 0.85
    _BASE_CONFIDENCE = 0.87
    _SINGLE_BURST_CONFIDENCE_CAP = 0.70
    _MAX_CYCLES = 3

    def expected_attack_class(self) -> str:
        return "distributed_lock_evasion"

    def expected_proof_type(self) -> str:
        return "reproduction"

    def validate(self, attack_probe: RawProbe, control_probe: RawProbe | None) -> ProofArtifact | None:
        del control_probe
        request = attack_probe.request
        response = attack_probe.response

        if not _is_safe_fixture(request):
            return None

        cycles = _to_int(_get_value(response, "cycles"), default=0)
        if cycles <= 0:
            cycles = _to_int(_get_value(request, "cycles"), default=0)
        if cycles <= 0:
            cycles = self._MAX_CYCLES
        if cycles > self._MAX_CYCLES:
            cycles = self._MAX_CYCLES

        reserved_count = _to_int(_get_value(response, "reserved_count"), default=0)
        inventory_limit = _to_int(_get_value(response, "inventory_limit"), default=0)

        if not (reserved_count > inventory_limit):
            return None

        confidence = _reproducibility_confidence(
            request=request,
            full_confidence=self._BASE_CONFIDENCE,
            single_burst_cap=self._SINGLE_BURST_CONFIDENCE_CAP,
        )
        if confidence < self._MIN_PROOF_CONFIDENCE_THRESHOLD:
            return None
        if not _requires_final_state_proof(attack_probe):
            return None

        return ProofArtifact(
            attack_task_id=attack_probe.attack_task_id,
            proof_type=self.expected_proof_type(),
            confidence_score=confidence,
            attack_probe_id=attack_probe.id,
            control_probe_id=None,
            summary="Distributed lock evasion: rapid cancel/re-acquire loop exceeded inventory constraints",
            evidence_notes=(
                "probe_type=race_concurrent, "
                f"cycles={cycles}, reserved_count={reserved_count}, inventory_limit={inventory_limit}"
            ),
        )


class InventoryReservationStrategy(ValidationStrategy):
    _MIN_PROOF_CONFIDENCE_THRESHOLD = 0.85
    _BASELINE_CONFIDENCE = 0.87
    _OVERALLOCATION_CONFIDENCE = 0.90

    def expected_attack_class(self) -> str:
        return "inventory_reservation_abuse"

    def expected_proof_type(self) -> str:
        return "reproduction"

    def validate(self, attack_probe: RawProbe, control_probe: RawProbe | None) -> ProofArtifact | None:
        del control_probe
        response = attack_probe.response

        accepted_count = _to_int(_get_value(response, "accepted_count"), default=0)
        available_stock = _to_int(_get_value(response, "available_stock"), default=0)
        over_allocated = accepted_count > available_stock

        responses = _get_value(response, "responses")
        multi_success = False
        if isinstance(responses, list):
            success_count = 0
            for resp in responses:
                if _is_success(resp):
                    success_count += 1
            multi_success = success_count > 1

        if not over_allocated and not multi_success:
            return None

        confidence = self._OVERALLOCATION_CONFIDENCE if over_allocated else self._BASELINE_CONFIDENCE
        if confidence < self._MIN_PROOF_CONFIDENCE_THRESHOLD:
            return None
        if not _requires_final_state_proof(attack_probe):
            return None

        return ProofArtifact(
            attack_task_id=attack_probe.attack_task_id,
            proof_type=self.expected_proof_type(),
            confidence_score=confidence,
            attack_probe_id=attack_probe.id,
            control_probe_id=None,
            summary="Inventory reservation abuse race: concurrent reservations exceeded available stock guarantees",
            evidence_notes=(
                "probe_type=race_concurrent, "
                f"accepted_count={accepted_count}, available_stock={available_stock}, "
                f"multi_success={multi_success}"
            ),
        )


def _reproducibility_confidence(request: dict[str, Any], full_confidence: float, single_burst_cap: float) -> float:
    reproduced = _get_value(request, "reproduced") is True
    reproduction_count = _to_int(_get_value(request, "reproduction_count"), default=0)
    if reproduced or reproduction_count >= 2:
        return full_confidence
    return min(full_confidence, single_burst_cap)


def _is_safe_fixture(request: dict[str, Any]) -> bool:
    if _get_value(request, "safe_fixture") is True:
        return True
    metadata = _get_value(request, "metadata")
    return isinstance(metadata, dict) and metadata.get("safe_fixture") is True


def _is_success(response: Any) -> bool:
    if isinstance(response, dict):
        success = response.get("success")
        if isinstance(success, bool):
            return success
        status = response.get("status")
        if isinstance(status, int):
            return 200 <= status < 300
        status_code = response.get("status_code")
        if isinstance(status_code, int):
            return 200 <= status_code < 300
    return False


def _extract_amount(response: Any) -> Any:
    if not isinstance(response, dict):
        return None
    if "amount" in response:
        return response.get("amount")
    if "transfer_amount" in response:
        return response.get("transfer_amount")
    if "body" in response and isinstance(response.get("body"), dict):
        body = response.get("body")
        if isinstance(body, dict):
            if "amount" in body:
                return body.get("amount")
            if "transfer_amount" in body:
                return body.get("transfer_amount")
    return None


def _responses_differ(first: Any, second: Any) -> bool:
    return _normalized(first) != _normalized(second)


def _normalized(value: Any) -> str:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    except (TypeError, ValueError):
        return str(value)


def _compact(value: Any) -> str:
    normalized = _normalized(value)
    if len(normalized) <= 240:
        return normalized
    return f"{normalized[:237]}..."


def _get_value(container: Any, key: str) -> Any:
    if isinstance(container, dict):
        return container.get(key)
    return None


def _first_non_none(*values: Any) -> Any:
    for value in values:
        if value is not None:
            return value
    return None


def _to_int(value: Any, default: int) -> int:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str):
        try:
            return int(value.strip())
        except ValueError:
            return default
    return default


def _to_float(value: Any, default: float) -> float:
    if isinstance(value, bool):
        return float(value)
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value.strip())
        except ValueError:
            return default
    return default


def _requires_final_state_proof(probe: RawProbe) -> bool:
    response = getattr(probe, "response", None)
    if not isinstance(response, dict):
        return True
    if response.get("status_code") is None:
        return True
    state_diff = getattr(probe, "state_diff_data", {}) or {}
    if not isinstance(state_diff, dict):
        state_diff = {}
    final_state = state_diff.get("final_state") or response.get("final_state")
    return final_state is not None
