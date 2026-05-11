from __future__ import annotations
import json
from uuid import NAMESPACE_URL, uuid5
from execution_plane.validator.strategies.base import ValidationStrategy
from storage.db.models import ProofArtifact, RawProbe

def _extract_from_request(request: dict, key: str) -> object:
    val = request.get(key)
    if val is not None:
        return val
    try:
        return json.loads(request.get("body", "{}")).get(key)
    except Exception:
        return None

class HttpSmugglingStrategy(ValidationStrategy):
    _CONFIDENCE = 0.88
    _TIMEOUT_MULTIPLIER = 3.0
    def expected_proof_type(self) -> str: return "differential"
    def expected_attack_class(self) -> str: return "http_smuggling"
    def validate(self, attack_probe: RawProbe, control_probe: RawProbe | None) -> ProofArtifact | None:
        probe_type = _extract_from_request(attack_probe.request, "probe_type")
        if probe_type not in ("cl_te_probe", "te_cl_probe"): return None
        if not _extract_from_request(attack_probe.request, "allow_smuggling_probes_required"): return None
        a_resp = attack_probe.response or {}
        c_resp = (control_probe.response or {}) if control_probe else {}
        a_lat = a_resp.get("latency_ms")
        c_lat = c_resp.get("latency_ms")
        timeout_diff = bool(a_lat and c_lat and a_lat > c_lat * self._TIMEOUT_MULTIPLIER)
        poisoned = "SMUGGLED" in str(a_resp.get("body", "")) or "X-Smuggled" in str(a_resp.get("body", ""))
        if not (timeout_diff or poisoned): return None
        sd = {"probe_type": probe_type, "timeout_differential": timeout_diff, "attack_latency_ms": a_lat}
        return ProofArtifact(attack_task_id=attack_probe.attack_task_id, finding_id=uuid5(NAMESPACE_URL, f"http_smuggling:{attack_probe.request.get('url', '')}:{probe_type}"), proof_type=self.expected_proof_type(), confidence_score=self._CONFIDENCE, attack_probe_id=attack_probe.id, control_probe_id=control_probe.id if control_probe else None, state_diff=sd, summary=f"HTTP request smuggling probe: {probe_type}", evidence_notes=f"probe_type={probe_type} timeout_differential={timeout_diff}")

class HttpMethodOverrideStrategy(ValidationStrategy):
    _CONFIDENCE = 0.90
    def expected_proof_type(self) -> str: return "absolute"
    def expected_attack_class(self) -> str: return "http_method_override"
    def validate(self, attack_probe: RawProbe, control_probe: RawProbe | None) -> ProofArtifact | None:
        if _extract_from_request(attack_probe.request, "probe_type") != "method_override": return None
        override_verb = str(_extract_from_request(attack_probe.request, "override_value") or "DELETE")
        resp = attack_probe.response or {}
        status = resp.get("status") or resp.get("status_code")
        if status not in (200, 201, 204): return None
        sd = {"original_verb": "POST", "override_verb": override_verb, "response_status": status, "execution_confirmed": True}
        return ProofArtifact(attack_task_id=attack_probe.attack_task_id, finding_id=uuid5(NAMESPACE_URL, f"http_method_override:{attack_probe.request.get('url', '')}:{override_verb}"), proof_type=self.expected_proof_type(), confidence_score=self._CONFIDENCE, attack_probe_id=attack_probe.id, control_probe_id=None, state_diff=sd, summary=f"HTTP method override accepted: POST overridden to {override_verb}", evidence_notes=f"probe_type=method_override override_verb={override_verb} response_status={status}")

class HttpParameterPollutionStrategy(ValidationStrategy):
    _CONFIDENCE = 0.80
    def expected_proof_type(self) -> str: return "differential"
    def expected_attack_class(self) -> str: return "http_parameter_pollution"
    def validate(self, attack_probe: RawProbe, control_probe: RawProbe | None) -> ProofArtifact | None:
        if _extract_from_request(attack_probe.request, "probe_type") != "hpp": return None
        if control_probe is None: return None
        param_name = str(_extract_from_request(attack_probe.request, "param_name") or "id")
        a_resp, c_resp = attack_probe.response or {}, control_probe.response or {}
        status_diff = a_resp.get("status") != c_resp.get("status")
        body_diff = str(a_resp.get("body", "")) != str(c_resp.get("body", ""))
        if not (status_diff or body_diff): return None
        sd = {"param_name": param_name, "values": ["1","2"], "status_diff": status_diff, "body_diff": body_diff}
        return ProofArtifact(attack_task_id=attack_probe.attack_task_id, finding_id=uuid5(NAMESPACE_URL, f"http_parameter_pollution:{attack_probe.request.get('url', '')}:{param_name}"), proof_type=self.expected_proof_type(), confidence_score=self._CONFIDENCE, attack_probe_id=attack_probe.id, control_probe_id=control_probe.id, state_diff=sd, summary="HTTP parameter pollution: response differs with duplicate parameter", evidence_notes=f"probe_type=hpp param_name={param_name} status_diff={status_diff} body_diff={body_diff}")
