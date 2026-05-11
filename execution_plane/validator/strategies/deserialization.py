from __future__ import annotations

import json
from typing import Any

from execution_plane.validator.strategies.base import ValidationStrategy
from storage.db.models import ProofArtifact, RawProbe

_DESERIALIZATION_MARKERS: tuple[str, ...] = (
    "java.io.ioexception",
    "java.io.streamcorruptedexception",
    "objectinputstream",
    "serializationexception",
    "pickle.unpicklingerror",
    "_pickle.unpicklingerror",
    "invalid load key",
    "unserialize()",
    "__php_incomplete_class",
    "deserialization error",
    "serialized object",
)
_YAML_ERROR_MARKERS: tuple[str, ...] = (
    "yaml",
    "!!python",
    "unsafe_load",
    "yaml.constructor",
)
_YAML_TIMING_DELTA_SECONDS = 3.0


class DeserializationProbeStrategy(ValidationStrategy):
    """Payload is truncated/malformed only; no ysoserial gadget execution."""

    def validate(self, attack_probe: RawProbe, control_probe: RawProbe | None) -> ProofArtifact | None:
        body = self._flatten_response(attack_probe.response).lower()
        if any(marker in body for marker in _DESERIALIZATION_MARKERS):
            return self._artifact(
                attack_probe=attack_probe,
                control_probe=control_probe,
                confidence=0.85,
                summary="Deserialization parsing error marker observed in response",
                evidence_notes="proof_signal=framework_error_marker; payload_mode=truncated_or_malformed",
            )
        return None

    def expected_attack_class(self) -> str:
        return "deserialization_probe"

    def expected_proof_type(self) -> str:
        return "absolute"

    def _artifact(
        self,
        *,
        attack_probe: RawProbe,
        control_probe: RawProbe | None,
        confidence: float,
        summary: str,
        evidence_notes: str,
    ) -> ProofArtifact:
        return ProofArtifact(
            attack_task_id=attack_probe.attack_task_id,
            proof_type=self.expected_proof_type(),
            confidence_score=confidence,
            attack_probe_id=attack_probe.id,
            control_probe_id=control_probe.id if control_probe is not None else None,
            summary=summary,
            evidence_notes=evidence_notes,
        )

    def _flatten_response(self, response: dict[str, Any]) -> str:
        chunks: list[str] = []
        for key in ("body", "json", "data", "text", "headers"):
            if key in response:
                chunks.append(self._to_text(response[key]))
        return "\n".join(chunk for chunk in chunks if chunk)

    def _to_text(self, value: Any) -> str:
        if isinstance(value, str):
            return value
        if isinstance(value, (dict, list)):
            return json.dumps(value, sort_keys=True, separators=(",", ":"))
        return str(value)


class YamlDeserializationStrategy(ValidationStrategy):
    """Probe uses os.getpid and no side-effect primitives."""

    def validate(self, attack_probe: RawProbe, control_probe: RawProbe | None) -> ProofArtifact | None:
        body = self._flatten_response(attack_probe.response).lower()
        if any(marker in body for marker in _YAML_ERROR_MARKERS):
            return self._artifact(
                attack_probe=attack_probe,
                control_probe=control_probe,
                confidence=0.85,
                summary="YAML deserialization error marker observed in response",
                evidence_notes="proof_signal=yaml_error_marker; probe=os.getpid_only",
            )

        latency_delta = self._latency_delta_seconds(attack_probe=attack_probe, control_probe=control_probe)
        if latency_delta is not None and latency_delta > _YAML_TIMING_DELTA_SECONDS:
            return self._artifact(
                attack_probe=attack_probe,
                control_probe=control_probe,
                confidence=0.72,
                summary="Potential YAML deserialization timeout behavior relative to baseline",
                evidence_notes=(
                    f"proof_signal=timing_delta; latency_delta_seconds={latency_delta:.3f}; "
                    "probe=os.getpid_only; timeout_guard=true"
                ),
            )

        return None

    def expected_attack_class(self) -> str:
        return "yaml_deserialization"

    def expected_proof_type(self) -> str:
        return "absolute"

    def _artifact(
        self,
        *,
        attack_probe: RawProbe,
        control_probe: RawProbe | None,
        confidence: float,
        summary: str,
        evidence_notes: str,
    ) -> ProofArtifact:
        return ProofArtifact(
            attack_task_id=attack_probe.attack_task_id,
            proof_type=self.expected_proof_type(),
            confidence_score=confidence,
            attack_probe_id=attack_probe.id,
            control_probe_id=control_probe.id if control_probe is not None else None,
            summary=summary,
            evidence_notes=evidence_notes,
        )

    def _flatten_response(self, response: dict[str, Any]) -> str:
        chunks: list[str] = []
        for key in ("body", "json", "data", "text", "headers"):
            if key in response:
                chunks.append(self._to_text(response[key]))
        return "\n".join(chunk for chunk in chunks if chunk)

    def _to_text(self, value: Any) -> str:
        if isinstance(value, str):
            return value
        if isinstance(value, (dict, list)):
            return json.dumps(value, sort_keys=True, separators=(",", ":"))
        return str(value)

    def _latency_delta_seconds(self, *, attack_probe: RawProbe, control_probe: RawProbe | None) -> float | None:
        if control_probe is None:
            baseline = attack_probe.request.get("baseline_latency_ms")
            baseline_ms = self._number_or_none(baseline)
        else:
            baseline_ms = self._number_or_none(control_probe.response.get("latency_ms"))
        attack_ms = self._number_or_none(attack_probe.response.get("latency_ms"))
        if baseline_ms is None or attack_ms is None:
            return None
        return max(0.0, (attack_ms - baseline_ms) / 1000.0)

    def _number_or_none(self, value: Any) -> float | None:
        if isinstance(value, bool):
            return None
        if isinstance(value, (int, float)):
            return float(value)
        if isinstance(value, str):
            try:
                return float(value)
            except ValueError:
                return None
        return None
