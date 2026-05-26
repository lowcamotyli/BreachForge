from __future__ import annotations

import json
from typing import Any

from execution_plane.validator.strategies.base import ValidationStrategy
from storage.db.models import ProofArtifact, RawProbe

_MIN_PROOF_CONFIDENCE_THRESHOLD = 0.85


class WorkflowAbuseStrategy(ValidationStrategy):
    def requires_state_effect(self) -> bool:
        return True

    def validate(self, attack_probe: RawProbe, control_probe: RawProbe | None) -> ProofArtifact | None:
        evidence_chain = self._extract_chain_steps_from_evidence_notes(attack_probe)
        request_chain = evidence_chain or self._extract_request_chain(attack_probe)
        if len(request_chain) < 2:
            return None

        if not self._has_skipped_prerequisite(request_chain):
            return None

        if not self._confirms_bypass(attack_probe.response):
            return None

        final_state_changed = self._final_state_changed(attack_probe, control_probe)
        if not final_state_changed:
            return None

        chain_length = len(request_chain)
        steps_completed = chain_length

        confidence = 0.92
        if confidence < _MIN_PROOF_CONFIDENCE_THRESHOLD:
            return None

        chain_summary = " -> ".join(f"{step['method']} {step['url']}" for step in request_chain)
        proof_type = "differential" if evidence_chain else self.expected_proof_type()
        metadata = json.dumps(
            {
                "chain_length": chain_length,
                "steps_completed": steps_completed,
                "final_state_changed": final_state_changed,
            },
            sort_keys=True,
        )

        return ProofArtifact(
            attack_task_id=attack_probe.attack_task_id,
            proof_type=proof_type,
            confidence_score=confidence,
            attack_probe_id=attack_probe.id,
            control_probe_id=getattr(control_probe, "id", None),
            summary="Workflow abuse differential proof: skipped prerequisite caused observable state inconsistency",
            evidence_notes=f"request_chain={chain_summary}, chain_evidence={metadata}",
        )

    def expected_proof_type(self) -> str:
        return "reproduction"

    def expected_attack_class(self) -> str:
        return "workflow_abuse"

    def _extract_request_chain(self, attack_probe: RawProbe) -> list[dict[str, str]]:
        request = attack_probe.request

        chain_value = request.get("chain")
        if isinstance(chain_value, list):
            normalized = self._normalize_chain(chain_value)
            if normalized:
                return normalized

        body = request.get("body")
        if isinstance(body, str) and body.strip():
            try:
                parsed = json.loads(body)
            except (TypeError, ValueError):
                parsed = None
            if isinstance(parsed, dict):
                parsed_chain = parsed.get("request_chain")
                if isinstance(parsed_chain, list):
                    normalized = self._normalize_chain(parsed_chain)
                    if normalized:
                        return normalized

        method = str(request.get("method") or "").upper()
        url = str(request.get("url") or "").strip()
        if method and url:
            return [{"method": method, "url": url}]
        return []

    def _extract_chain_steps_from_evidence_notes(self, attack_probe: RawProbe) -> list[dict[str, str]]:
        notes = self._collect_evidence_notes_candidates(attack_probe)
        for note in notes:
            parsed = self._parse_chain_steps_note(note)
            if parsed:
                return parsed
        return []

    def _collect_evidence_notes_candidates(self, attack_probe: RawProbe) -> list[Any]:
        candidates: list[Any] = []
        request = attack_probe.request
        response = attack_probe.response

        if "evidence_notes" in request:
            candidates.append(request["evidence_notes"])
        if "evidence_notes" in response:
            candidates.append(response["evidence_notes"])

        metadata = request.get("metadata")
        if isinstance(metadata, dict) and "evidence_notes" in metadata:
            candidates.append(metadata["evidence_notes"])

        body = request.get("body")
        if isinstance(body, dict) and "evidence_notes" in body:
            candidates.append(body["evidence_notes"])
        if isinstance(body, str) and body.strip():
            try:
                parsed_body = json.loads(body)
            except (TypeError, ValueError):
                parsed_body = None
            if isinstance(parsed_body, dict) and "evidence_notes" in parsed_body:
                candidates.append(parsed_body["evidence_notes"])

        return candidates

    def _parse_chain_steps_note(self, note: Any) -> list[dict[str, str]]:
        if isinstance(note, dict):
            raw_steps = note.get("chain_steps")
            if isinstance(raw_steps, list):
                return self._normalize_chain(raw_steps)
            return []

        if not isinstance(note, str):
            return []

        raw = note.strip()
        if not raw:
            return []

        parsed_direct = self._parse_json_object(raw)
        if isinstance(parsed_direct, dict):
            direct_steps = parsed_direct.get("chain_steps")
            if isinstance(direct_steps, list):
                return self._normalize_chain(direct_steps)

        marker = "chain_steps="
        marker_index = raw.find(marker)
        if marker_index < 0:
            return []

        payload = raw[marker_index + len(marker) :].strip()
        parsed_payload = self._parse_json_object(payload)
        if isinstance(parsed_payload, dict):
            raw_steps = parsed_payload.get("chain_steps")
            if isinstance(raw_steps, list):
                return self._normalize_chain(raw_steps)
            return []
        if isinstance(parsed_payload, list):
            return self._normalize_chain(parsed_payload)

        return []

    def _parse_json_object(self, raw: str) -> Any:
        try:
            return json.loads(raw)
        except (TypeError, ValueError):
            return None

    def _normalize_chain(self, raw_chain: list[Any]) -> list[dict[str, str]]:
        normalized: list[dict[str, str]] = []
        for item in raw_chain:
            if not isinstance(item, dict):
                continue
            method = str(item.get("method") or item.get("http_method") or "").upper().strip()
            url = str(item.get("url") or item.get("path") or "").strip()
            if not method or not url:
                request = item.get("request")
                if isinstance(request, dict):
                    method = str(request.get("method") or "").upper().strip()
                    url = str(request.get("url") or "").strip()
            if not method or not url:
                continue
            normalized.append({"method": method, "url": url})
        return normalized

    def _has_skipped_prerequisite(self, chain: list[dict[str, str]]) -> bool:
        marker_tokens = ("skip", "skipped", "without", "bypass", "prerequisite")
        for step in chain:
            descriptor = f"{step['method']} {step['url']}".lower()
            if any(token in descriptor for token in marker_tokens):
                return True

        first = chain[0]["url"].lower()
        last = chain[-1]["url"].lower()
        if first != last and any(token in last for token in ("approve", "confirm", "complete", "checkout", "submit")):
            return True

        return False

    def _confirms_bypass(self, response: dict[str, Any]) -> bool:
        status = response.get("status") or response.get("status_code")
        success_by_status = isinstance(status, int) and 200 <= status < 300

        body_text = self._response_text(response).lower()
        explicit_bypass = any(token in body_text for token in ("bypass", "without prerequisite", "state violation"))
        success_keywords = any(token in body_text for token in ("approved", "confirmed", "completed", "success"))

        return explicit_bypass or (success_by_status and success_keywords)

    def _final_state_changed(self, attack_probe: RawProbe, control_probe: RawProbe | None) -> bool:
        initial_state = self._extract_initial_state(attack_probe, control_probe)
        final_state = self._extract_final_state(attack_probe)

        if initial_state is None or final_state is None:
            return False

        initial_serialized = self._state_signature(initial_state)
        final_serialized = self._state_signature(final_state)
        return initial_serialized != final_serialized

    def _extract_initial_state(self, attack_probe: RawProbe, control_probe: RawProbe | None) -> Any:
        response = attack_probe.response
        for key in ("initial_state", "state_before", "before_state", "before", "baseline_state"):
            if key in response:
                return response[key]

        if isinstance(control_probe, RawProbe):
            return self._extract_semantic_body(control_probe.response)
        return None

    def _extract_final_state(self, attack_probe: RawProbe) -> Any:
        response = attack_probe.response
        for key in ("final_state", "state_after", "after_state", "after", "current_state"):
            if key in response:
                return response[key]
        return self._extract_semantic_body(response)

    def _extract_semantic_body(self, response: dict[str, Any]) -> Any:
        for key in ("body", "json", "data", "content", "text"):
            if key in response:
                return self._normalize_state_value(response[key])
        return None

    def _normalize_state_value(self, value: Any) -> Any:
        if isinstance(value, str):
            stripped = value.strip()
            if not stripped:
                return ""
            parsed = self._parse_json_object(stripped)
            if parsed is None:
                return stripped
            return self._normalize_state_value(parsed)
        if isinstance(value, dict):
            return {str(key): self._normalize_state_value(value[key]) for key in sorted(value)}
        if isinstance(value, list):
            return [self._normalize_state_value(item) for item in value]
        return value

    def _state_signature(self, value: Any) -> str:
        normalized = self._normalize_state_value(value)
        return json.dumps(normalized, sort_keys=True, separators=(",", ":"), default=str)

    def _response_text(self, response: dict[str, Any]) -> str:
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


class ApprovalBypassValidator(ValidationStrategy):
    _SUCCESS_CONFIDENCE = 0.91
    _NO_STATE_DIFF_CAP = 0.75

    def requires_state_effect(self) -> bool:
        return True

    def expected_proof_type(self) -> str:
        return "differential"

    def expected_attack_class(self) -> str:
        return "approval_bypass"

    def validate(self, attack_probe: RawProbe, control_probe: RawProbe | None) -> ProofArtifact | None:
        response = attack_probe.response
        request = attack_probe.request
        state_diff = self._extract_state_diff(response)

        bypass_by_state = self._state_diff_confirms_bypass(state_diff)
        bypass_by_terminal_success = self._terminal_step_succeeded_without_prereq(request, response)
        if not bypass_by_state and not bypass_by_terminal_success:
            return None

        confidence = self._SUCCESS_CONFIDENCE
        if state_diff is None:
            confidence = min(confidence, self._NO_STATE_DIFF_CAP)

        summary = "Approval bypass detected: workflow terminal action accepted without required prior approval steps"
        evidence = {
            "bypass_by_state": bypass_by_state,
            "bypass_by_terminal_success": bypass_by_terminal_success,
            "state_diff_present": state_diff is not None,
            "status": response.get("status") or response.get("status_code"),
        }
        return ProofArtifact(
            attack_task_id=attack_probe.attack_task_id,
            proof_type=self.expected_proof_type(),
            confidence_score=confidence,
            attack_probe_id=attack_probe.id,
            control_probe_id=getattr(control_probe, "id", None),
            state_diff=state_diff,
            summary=summary,
            evidence_notes=json.dumps(evidence, sort_keys=True),
        )

    def _extract_state_diff(self, response: dict[str, Any]) -> dict[str, Any] | None:
        direct = response.get("state_diff")
        if isinstance(direct, dict):
            return direct

        for key in ("diff", "workflow_diff"):
            candidate = response.get(key)
            if isinstance(candidate, dict):
                return candidate

        body = response.get("body")
        parsed_body: Any = None
        if isinstance(body, str):
            try:
                parsed_body = json.loads(body)
            except (TypeError, ValueError):
                parsed_body = None
        elif isinstance(body, dict):
            parsed_body = body

        if isinstance(parsed_body, dict):
            candidate = parsed_body.get("state_diff")
            if isinstance(candidate, dict):
                return candidate
        return None

    def _state_diff_confirms_bypass(self, state_diff: dict[str, Any] | None) -> bool:
        if state_diff is None:
            return False
        serialized = json.dumps(state_diff, sort_keys=True).lower()
        has_target_state = any(token in serialized for token in ("approved", "active", "completed"))
        has_missing_intermediate = any(
            token in serialized for token in ("missing_intermediate", "skipped_state", "pending_approval")
        )
        if has_target_state and has_missing_intermediate:
            return True

        before_state = str(state_diff.get("before") or state_diff.get("from") or "").lower()
        after_state = str(state_diff.get("after") or state_diff.get("to") or "").lower()
        if before_state in {"draft", "created"} and after_state in {"approved", "active", "completed"}:
            path = str(state_diff.get("path") or state_diff.get("transition_path") or "").lower()
            if "pending" not in path and "review" not in path:
                return True
        return False

    def _terminal_step_succeeded_without_prereq(self, request: dict[str, Any], response: dict[str, Any]) -> bool:
        status = response.get("status") or response.get("status_code")
        success = isinstance(status, int) and 200 <= status < 300
        if not success:
            return False

        request_text = json.dumps(request, sort_keys=True).lower()
        url = str(request.get("url") or "").lower()
        terminal = any(token in url for token in ("approve", "confirm", "complete", "activate"))
        prereq_expected = any(
            token in request_text
            for token in ("required_step", "prerequisite", "review", "pending", "pending_approval", "workflow_approval")
        )
        return terminal and prereq_expected


WORKFLOW_ABUSE_STRATEGY_REGISTRY: dict[str, ValidationStrategy] = {
    "workflow_abuse": WorkflowAbuseStrategy(),
    "approval_bypass": ApprovalBypassValidator(),
}
