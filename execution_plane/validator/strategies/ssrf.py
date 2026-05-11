from __future__ import annotations

import ipaddress
import json
from typing import Any
from urllib.parse import urlparse

from execution_plane.oob.oob_manager import OOBManager
from execution_plane.validator.strategies.base import ValidationStrategy
from storage.db.models import ProofArtifact, RawProbe

_METADATA_MARKERS: tuple[str, ...] = (
    "ami-id",
    "iam/security-credentials",
    "hostname",
    "instance-id",
)
_CLOUD_METADATA_HOSTS: set[str] = {
    "169.254.169.254",
    "100.100.100.200",
    "metadata.google.internal",
}
_RESTRICTED_PROTOCOLS: set[str] = {"file", "dict", "gopher"}
_TIMING_DELTA_SECONDS = 2.0
_METADATA_CONFIDENCE = 0.95
_BLIND_SSRF_CONFIDENCE = 0.65
_OOB_CONFIDENCE = 0.92
_INTERNAL_IP_RANGES: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
)


class SsrfStrategy(ValidationStrategy):
    async def validate(
        self,
        attack_probe: RawProbe,
        control_probe: RawProbe | None,
        context: Any | None = None,
        oob_manager: OOBManager | None = None,
    ) -> ProofArtifact | None:
        target_url = self._extract_ssrf_target(attack_probe.request)
        oob_probe_token: str | None = None
        if oob_manager is not None and oob_manager.config.oob_enabled:
            scan_id = self._extract_scan_id(context=context, request=attack_probe.request)
            oob_url, oob_probe_token = oob_manager.generate_callback_url(scan_id=scan_id)
            target_url = oob_url

        if target_url is not None and not self._is_target_allowed(target_url, attack_probe.request):
            return None

        if target_url is not None and self._uses_restricted_protocol(target_url):
            if not self._explicit_protocol_ssrf_allowed(attack_probe.request):
                return None

        body = self._flatten_response(attack_probe.response)
        metadata_markers = self._metadata_markers(body)
        if metadata_markers:
            return self._artifact(
                attack_probe=attack_probe,
                control_probe=control_probe,
                confidence=_METADATA_CONFIDENCE,
                summary="SSRF proof: server-side request reached cloud metadata service",
                evidence_notes=(
                    f"proof_signal=metadata_marker; markers={','.join(metadata_markers)}; "
                    f"target_allowed=true; request_has_auth={self._request_has_auth(attack_probe.request)}"
                ),
            )

        latency_delta = self._latency_delta_seconds(attack_probe=attack_probe, control_probe=control_probe)
        if latency_delta is not None and latency_delta > _TIMING_DELTA_SECONDS:
            confidence = _BLIND_SSRF_CONFIDENCE
            oob_hit = None
            if oob_manager is not None and oob_probe_token is not None and oob_manager.config.oob_enabled:
                oob_hit = await oob_manager.wait_for_hit(oob_probe_token, timeout=30.0)
                if oob_hit is not None:
                    confidence = _OOB_CONFIDENCE
            return self._artifact(
                attack_probe=attack_probe,
                control_probe=control_probe,
                confidence=confidence,
                summary="Potential blind SSRF: internal target latency exceeded baseline",
                evidence_notes=(
                    f"proof_signal=timing_delta; latency_delta_seconds={latency_delta:.3f}; "
                    f"confidence_capped={str(confidence < _OOB_CONFIDENCE).lower()}; "
                    f"needs_oob_for_high_confidence={str(confidence < _OOB_CONFIDENCE).lower()}; "
                    f"oob_hit={str(oob_hit is not None).lower()}"
                ),
            )

        return None

    def expected_proof_type(self) -> str:
        return "absolute"

    def expected_attack_class(self) -> str:
        return "ssrf"

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

    def _extract_ssrf_target(self, request: dict[str, Any]) -> str | None:
        for key in ("ssrf_target_url", "payload_url", "target_url", "probe_url"):
            value = request.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()

        hypothesis = request.get("hypothesis")
        if isinstance(hypothesis, str):
            try:
                parsed = json.loads(hypothesis)
            except (TypeError, ValueError):
                parsed = {}
            if isinstance(parsed, dict):
                for key in ("ssrf_target_url", "payload_url", "target_url", "probe_url"):
                    value = parsed.get(key)
                    if isinstance(value, str) and value.strip():
                        return value.strip()

        body = request.get("body")
        if isinstance(body, str):
            try:
                parsed_body = json.loads(body)
            except (TypeError, ValueError):
                parsed_body = {}
            if isinstance(parsed_body, dict):
                for value in parsed_body.values():
                    if isinstance(value, str) and "://" in value:
                        return value.strip()
        return None

    def _is_target_allowed(self, target_url: str, request: dict[str, Any]) -> bool:
        parsed = urlparse(target_url)
        host = (parsed.hostname or "").lower().rstrip(".")
        if not host:
            return False
        if host in _CLOUD_METADATA_HOSTS:
            return True
        if self._host_is_internal(host):
            return True

        allowlist = request.get("ssrf_allowlist")
        if isinstance(allowlist, list):
            normalized = {str(item).lower().rstrip(".") for item in allowlist if isinstance(item, str)}
            return host in normalized
        return False

    def _host_is_internal(self, host: str) -> bool:
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            return host in {"localhost"}
        return any(ip in network for network in _INTERNAL_IP_RANGES)

    def _uses_restricted_protocol(self, target_url: str) -> bool:
        return urlparse(target_url).scheme.lower() in _RESTRICTED_PROTOCOLS

    def _explicit_protocol_ssrf_allowed(self, request: dict[str, Any]) -> bool:
        return request.get("allow_protocol_ssrf") is True

    def _metadata_markers(self, body: str) -> list[str]:
        lowered = body.lower()
        return [marker for marker in _METADATA_MARKERS if marker in lowered]

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

    def _request_has_auth(self, request: dict[str, Any]) -> bool:
        headers = request.get("headers")
        if not isinstance(headers, dict):
            return False
        return any(str(key).lower() in {"authorization", "cookie", "x-api-key"} for key in headers)

    def _extract_scan_id(self, *, context: Any | None, request: dict[str, Any]) -> str:
        context_scan_id = getattr(context, "scan_id", None) if context is not None else None
        if context_scan_id is not None:
            return str(context_scan_id)
        request_scan_id = request.get("scan_id")
        if isinstance(request_scan_id, str) and request_scan_id.strip():
            return request_scan_id.strip()
        return "unknown"
