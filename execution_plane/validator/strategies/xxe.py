from __future__ import annotations

import json
import re
from typing import Any

from execution_plane.oob.oob_manager import OOBManager
from execution_plane.validator.strategies.base import ValidationStrategy
from storage.db.models import ProofArtifact, RawProbe

_UNIX_PASSWD_MARKERS: tuple[str, ...] = ("root:", "daemon:", "nobody:")
_UNIX_PASSWD_ENTRY_RE = re.compile(r"\\w+:x:\\d+:\\d+")
_XXE_ERROR_PATH_MARKERS: tuple[str, ...] = ("/etc/", "/usr/", "/var/", "/home/")
_XXE_PARSER_MARKERS: tuple[str, ...] = (
    "SAXParser",
    "XMLReader",
    "XML parser",
    "javax.xml",
    "org.xml",
)
_XXE_CLASSIC_ALLOWED_PROBES: tuple[str, ...] = ("/etc/passwd", "/etc/hostname")
_TIMING_DELTA_SECONDS = 2.0
_BLIND_XXE_CONFIDENCE = 0.65
_OOB_CONFIDENCE = 0.92


class XxeClassicStrategy(ValidationStrategy):
    def expected_attack_class(self) -> str:
        return "xxe_classic"

    def expected_proof_type(self) -> str:
        return "absolute"

    def validate(self, attack_probe: RawProbe, control_probe: RawProbe | None) -> ProofArtifact | None:
        if not self._probe_is_guardrail_allowed(attack_probe.request):
            return None

        body = self._flatten_response(attack_probe.response)
        lowered = body.lower()
        if any(marker in lowered for marker in _UNIX_PASSWD_MARKERS) or _UNIX_PASSWD_ENTRY_RE.search(body):
            return self._artifact(
                attack_probe=attack_probe,
                control_probe=control_probe,
                confidence=0.95,
                summary="XXE classic proof: local file content pattern observed",
                evidence_notes="proof_signal=passwd_pattern; guardrail=etc_passwd_or_hostname_only",
            )
        return None

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

    def _probe_is_guardrail_allowed(self, request: dict[str, Any]) -> bool:
        flattened = self._to_text(request).lower()
        return any(marker in flattened for marker in _XXE_CLASSIC_ALLOWED_PROBES)


class XxeErrorStrategy(ValidationStrategy):
    def expected_attack_class(self) -> str:
        return "xxe_error"

    def expected_proof_type(self) -> str:
        return "absolute"

    def validate(self, attack_probe: RawProbe, control_probe: RawProbe | None) -> ProofArtifact | None:
        body = self._flatten_response(attack_probe.response)
        lowered = body.lower()

        has_path_disclosure = any(marker in lowered for marker in _XXE_ERROR_PATH_MARKERS)
        has_parser_marker = any(marker.lower() in lowered for marker in _XXE_PARSER_MARKERS)

        if has_path_disclosure or has_parser_marker:
            return self._artifact(
                attack_probe=attack_probe,
                control_probe=control_probe,
                confidence=0.80,
                summary="XXE error proof: parser internals or filesystem path disclosure detected",
                evidence_notes=(
                    f"proof_signal=xml_error_context; has_path_disclosure={has_path_disclosure}; "
                    f"has_parser_marker={has_parser_marker}"
                ),
            )
        return None

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


class XxeBlindStrategy(ValidationStrategy):
    def expected_attack_class(self) -> str:
        return "xxe_blind"

    def expected_proof_type(self) -> str:
        return "timing"

    async def validate(
        self,
        attack_probe: RawProbe,
        control_probe: RawProbe | None,
        context: Any | None = None,
        oob_manager: OOBManager | None = None,
    ) -> ProofArtifact | None:
        if control_probe is None:
            return None

        oob_probe_token: str | None = None
        oob_payload: str | None = None
        if oob_manager is not None and oob_manager.config.oob_enabled:
            scan_id = self._extract_scan_id(context=context, request=attack_probe.request)
            oob_url, oob_probe_token = oob_manager.generate_callback_url(scan_id=scan_id)
            oob_payload = f'<!DOCTYPE foo [<!ENTITY xxe SYSTEM "{oob_url}">]>&xxe;'

        attack_ms = self._number_or_none(attack_probe.response.get("latency_ms"))
        control_ms = self._number_or_none(control_probe.response.get("latency_ms"))
        if attack_ms is None or control_ms is None:
            return None

        delta_seconds = max(0.0, (attack_ms - control_ms) / 1000.0)
        if delta_seconds > _TIMING_DELTA_SECONDS:
            confidence = _BLIND_XXE_CONFIDENCE
            oob_hit = None
            if oob_manager is not None and oob_probe_token is not None and oob_manager.config.oob_enabled:
                oob_hit = await oob_manager.wait_for_hit(oob_probe_token, timeout=30.0)
                if oob_hit is not None:
                    confidence = _OOB_CONFIDENCE
            return self._artifact(
                attack_probe=attack_probe,
                control_probe=control_probe,
                confidence=confidence,
                summary="Potential blind XXE: probe latency exceeded control baseline",
                evidence_notes=(
                    f"proof_signal=timing_delta; latency_delta_seconds={delta_seconds:.3f}; "
                    f"confidence_capped={str(confidence < _OOB_CONFIDENCE).lower()}; "
                    f"needs_oob_for_high_confidence={str(confidence < _OOB_CONFIDENCE).lower()}; "
                    f"oob_hit={str(oob_hit is not None).lower()}; "
                    f"oob_payload_injected={str(oob_payload is not None).lower()}"
                ),
            )
        return None

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

    def _extract_scan_id(self, *, context: Any | None, request: dict[str, Any]) -> str:
        context_scan_id = getattr(context, "scan_id", None) if context is not None else None
        if context_scan_id is not None:
            return str(context_scan_id)
        request_scan_id = request.get("scan_id")
        if isinstance(request_scan_id, str) and request_scan_id.strip():
            return request_scan_id.strip()
        return "unknown"
