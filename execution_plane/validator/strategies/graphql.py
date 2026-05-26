from __future__ import annotations

import json
import re
from typing import Any

from execution_plane.planner.decision_log import FeedbackPayload
from execution_plane.validator.strategies.base import ValidationStrategy
from storage.db.models import ProofArtifact, RawProbe

_INTROSPECTION_CONFIDENCE = 0.95
_BATCH_CONFIDENCE = 0.88
_FIELD_SUGGESTION_CONFIDENCE = 0.85
_DEPTH_CONFIDENCE = 0.86
_DISABLED_INTROSPECTION_HINTS: tuple[str, ...] = (
    "introspection is disabled",
    "cannot query field \"__schema\"",
    "cannot query field '__schema'",
    "cannot query field \"__type\"",
    "cannot query field '__type'",
)
_SUGGESTION_RE = re.compile(r"did you mean", re.IGNORECASE)
_FIELD_NAME_RE = re.compile(r"\"([a-zA-Z_][a-zA-Z0-9_]*)\"")


class GraphqlAdaptiveFollowupMixin:
    def validate_adaptive_followup(self, feedback: FeedbackPayload, probe_result: dict) -> ProofArtifact | None:
        follow_up_hints = set(feedback.follow_up_hints)

        if "schema_driven_field_probe" in follow_up_hints:
            field_count = self._schema_field_count(probe_result)
            if field_count > 0:
                confidence_score = self._schema_field_confidence(field_count)
                return self._adaptive_artifact(
                    feedback=feedback,
                    probe_result=probe_result,
                    confidence_score=confidence_score,
                    summary="GraphQL adaptive schema field probe found schema fields.",
                    evidence_notes=(
                        "probe_type=graphql_schema_driven_field_probe; "
                        f"schema_fields={field_count}; parent_evidence_ref={feedback.parent_evidence_ref}"
                    ),
                )

        if "depth_exhaustion_probe" in follow_up_hints and self._has_depth_limit_signal(probe_result):
            return self._adaptive_artifact(
                feedback=feedback,
                probe_result=probe_result,
                confidence_score=0.75,
                summary="GraphQL adaptive depth probe found depth limit signal.",
                evidence_notes=(
                    "probe_type=graphql_depth_exhaustion_probe; depth_limit_signal=true; "
                    f"parent_evidence_ref={feedback.parent_evidence_ref}"
                ),
            )

        return None

    def _schema_field_count(self, value: Any) -> int:
        if isinstance(value, dict):
            field_count = 0
            for key, item in value.items():
                if key == "fields":
                    field_count += self._schema_entry_count(item)
                elif key == "types":
                    nested_count = self._schema_field_count(item)
                    field_count += nested_count if nested_count > 0 else self._schema_entry_count(item)
                else:
                    field_count += self._schema_field_count(item)
            return field_count
        if isinstance(value, list):
            return sum(self._schema_field_count(item) for item in value)
        return 0

    def _schema_entry_count(self, value: Any) -> int:
        if isinstance(value, list):
            return len(value)
        if isinstance(value, dict):
            return len(value)
        return 1 if value else 0

    def _schema_field_confidence(self, field_count: int) -> float:
        if field_count >= 10:
            return 0.87
        if field_count >= 5:
            return 0.75
        return 0.6

    def _has_depth_limit_signal(self, probe_result: dict) -> bool:
        errors = probe_result.get("errors")
        if errors is None:
            return False
        error_text = self._adaptive_to_text(errors).lower()
        return "maxdepth" in error_text or "depth" in error_text

    def _adaptive_artifact(
        self,
        feedback: FeedbackPayload,
        probe_result: dict,
        confidence_score: float,
        summary: str,
        evidence_notes: str,
    ) -> ProofArtifact:
        artifact = ProofArtifact(
            attack_task_id=probe_result.get("attack_task_id", feedback.task_id),
            proof_type=self.expected_proof_type(),
            confidence_score=confidence_score,
            attack_probe_id=probe_result.get("attack_probe_id", probe_result.get("probe_id", probe_result.get("id"))),
            control_probe_id=probe_result.get("control_probe_id"),
            summary=summary,
            evidence_notes=evidence_notes,
        )
        artifact.parent_evidence_ref = feedback.parent_evidence_ref
        return artifact

    def _adaptive_to_text(self, value: Any) -> str:
        if isinstance(value, str):
            return value
        if isinstance(value, (dict, list)):
            return json.dumps(value, sort_keys=True, separators=(",", ":"))
        if value is None:
            return ""
        return str(value)


class GraphqlIntrospectionStrategy(GraphqlAdaptiveFollowupMixin, ValidationStrategy):
    def validate(self, attack_probe: RawProbe, control_probe: RawProbe | None) -> ProofArtifact | None:
        primary_probe, secondary_probe = self._ordered_probes_for_introspection(attack_probe, control_probe)
        for probe in (primary_probe, secondary_probe):
            if probe is None:
                continue
            body_text = self._body_text(probe.response)
            lowered = body_text.lower()
            if any(hint in lowered for hint in _DISABLED_INTROSPECTION_HINTS):
                return None
            if self._contains_introspection_data(probe.response, lowered):
                return ProofArtifact(
                    attack_task_id=attack_probe.attack_task_id,
                    proof_type=self.expected_proof_type(),
                    confidence_score=_INTROSPECTION_CONFIDENCE,
                    attack_probe_id=attack_probe.id,
                    control_probe_id=control_probe.id if control_probe is not None else None,
                    summary="GraphQL introspection enabled (__schema/__type exposed).",
                    evidence_notes=(
                        "probe_type=graphql_introspection; proof_signal=__schema_or___type; "
                        f"probe_auth={self._request_has_auth(probe.request)}; unauth_first=true"
                    ),
                )
        return None

    def expected_proof_type(self) -> str:
        return "absolute"

    def expected_attack_class(self) -> str:
        return "graphql_introspection"

    def _ordered_probes_for_introspection(self, attack_probe: RawProbe, control_probe: RawProbe | None) -> tuple[RawProbe | None, RawProbe | None]:
        attack_has_auth = self._request_has_auth(attack_probe.request)
        control_has_auth = self._request_has_auth(control_probe.request) if control_probe is not None else False
        if control_probe is not None and attack_has_auth and not control_has_auth:
            return control_probe, attack_probe
        return attack_probe, control_probe

    def _contains_introspection_data(self, response: dict[str, Any], flattened: str) -> bool:
        data = response.get("json") or response.get("data")
        if isinstance(data, dict) and ("__schema" in data or "__type" in data):
            return True
        return "__schema" in flattened or "__type" in flattened

    def _request_has_auth(self, request: dict[str, Any]) -> bool:
        headers = request.get("headers")
        if not isinstance(headers, dict):
            return False
        return any(str(key).lower() in {"authorization", "cookie", "x-api-key"} for key in headers)

    def _body_text(self, response: dict[str, Any]) -> str:
        chunks: list[str] = []
        for key in ("body", "json", "data", "errors", "text"):
            if key in response:
                chunks.append(self._to_text(response[key]))
        return "\n".join(chunk for chunk in chunks if chunk)

    def _to_text(self, value: Any) -> str:
        if isinstance(value, str):
            return value
        if isinstance(value, (dict, list)):
            return json.dumps(value, sort_keys=True, separators=(",", ":"))
        return str(value)


class GraphqlBatchStrategy(GraphqlAdaptiveFollowupMixin, ValidationStrategy):
    _THROTTLE_STATUSES = {429, 503}

    def validate(self, attack_probe: RawProbe, control_probe: RawProbe | None) -> ProofArtifact | None:
        responses = self._batch_responses(attack_probe.response)
        if len(responses) != 20:
            return None

        statuses = [self._status_of(item) for item in responses]
        if any(status in self._THROTTLE_STATUSES for status in statuses if status is not None):
            return None

        control_status = self._status_of(control_probe.response) if control_probe is not None else None
        if control_status in self._THROTTLE_STATUSES:
            return None

        return ProofArtifact(
            attack_task_id=attack_probe.attack_task_id,
            proof_type=self.expected_proof_type(),
            confidence_score=_BATCH_CONFIDENCE,
            attack_probe_id=attack_probe.id,
            control_probe_id=control_probe.id if control_probe is not None else None,
            summary="GraphQL batch request returned 20 responses without throttling.",
            evidence_notes="probe_type=graphql_batch; batch_size=20; throttled=false",
        )

    def expected_proof_type(self) -> str:
        return "differential"

    def expected_attack_class(self) -> str:
        return "graphql_batch"

    def _batch_responses(self, response: dict[str, Any]) -> list[dict[str, Any]]:
        candidates = response.get("responses")
        if isinstance(candidates, list):
            return [item for item in candidates if isinstance(item, dict)]

        json_payload = response.get("json")
        if isinstance(json_payload, list):
            return [item for item in json_payload if isinstance(item, dict)]

        body_payload = response.get("body")
        if isinstance(body_payload, list):
            return [item for item in body_payload if isinstance(item, dict)]

        return []

    def _status_of(self, value: Any) -> int | None:
        if not isinstance(value, dict):
            return None
        for key in ("status", "status_code", "code"):
            raw = value.get(key)
            if isinstance(raw, int):
                return raw
            if isinstance(raw, str) and raw.isdigit():
                return int(raw)
        return None


class GraphqlFieldSuggestionStrategy(GraphqlAdaptiveFollowupMixin, ValidationStrategy):
    def validate(self, attack_probe: RawProbe, control_probe: RawProbe | None) -> ProofArtifact | None:
        body = self._to_text(attack_probe.response.get("body"))
        errors = self._to_text(attack_probe.response.get("errors"))
        merged = f"{body}\n{errors}".strip()
        if not merged:
            return None

        if not _SUGGESTION_RE.search(merged):
            return None

        requested_field = self._requested_field_name(attack_probe.request)
        if requested_field is None:
            return None

        if self._field_in_spec(attack_probe.request, requested_field):
            return None

        redacted = self._redact_field_names(merged)
        return ProofArtifact(
            attack_task_id=attack_probe.attack_task_id,
            proof_type=self.expected_proof_type(),
            confidence_score=_FIELD_SUGGESTION_CONFIDENCE,
            attack_probe_id=attack_probe.id,
            control_probe_id=control_probe.id if control_probe is not None else None,
            summary="GraphQL field suggestion disclosure detected.",
            evidence_notes=f"probe_type=graphql_field_suggestion; suggestion=true; details={redacted}",
        )

    def expected_proof_type(self) -> str:
        return "absolute"

    def expected_attack_class(self) -> str:
        return "graphql_field_suggestion"

    def _requested_field_name(self, request: dict[str, Any]) -> str | None:
        for key in ("invalid_field", "field", "requested_field"):
            value = request.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()

        query = request.get("query")
        if not isinstance(query, str):
            return None
        matches = _FIELD_NAME_RE.findall(query)
        if matches:
            return matches[-1]
        return None

    def _field_in_spec(self, request: dict[str, Any], field_name: str) -> bool:
        spec = request.get("schema_fields")
        if not isinstance(spec, list):
            return False
        normalized = {str(item).strip().lower() for item in spec if isinstance(item, str)}
        return field_name.lower() in normalized

    def _redact_field_names(self, text: str) -> str:
        return _FIELD_NAME_RE.sub('"<redacted>"', text)

    def _to_text(self, value: Any) -> str:
        if isinstance(value, str):
            return value
        if isinstance(value, (dict, list)):
            return json.dumps(value, sort_keys=True, separators=(",", ":"))
        if value is None:
            return ""
        return str(value)


class GraphqlDepthStrategy(GraphqlAdaptiveFollowupMixin, ValidationStrategy):
    _TIMEOUT_STATUSES = {408, 504}
    _TIMEOUT_MARKERS: tuple[str, ...] = (
        "timeout",
        "timed out",
        "query depth",
        "maximum depth",
        "query complexity",
        "complexity limit",
    )

    def validate(self, attack_probe: RawProbe, control_probe: RawProbe | None) -> ProofArtifact | None:
        if self._was_retried(attack_probe.request):
            return None

        status = self._status_of(attack_probe.response)
        body_text = self._to_text(attack_probe.response).lower()
        timeout_flag = attack_probe.response.get("timeout") is True or attack_probe.response.get("timed_out") is True
        timeout_status = status in self._TIMEOUT_STATUSES
        timeout_marker = any(marker in body_text for marker in self._TIMEOUT_MARKERS)
        if not (timeout_flag or timeout_status or timeout_marker):
            return None

        return ProofArtifact(
            attack_task_id=attack_probe.attack_task_id,
            proof_type=self.expected_proof_type(),
            confidence_score=_DEPTH_CONFIDENCE,
            attack_probe_id=attack_probe.id,
            control_probe_id=control_probe.id if control_probe is not None else None,
            summary="GraphQL depth probe triggered timeout or query complexity guard.",
            evidence_notes="probe_type=graphql_depth; max_depth=10; timeout_signal=true; retries=0",
        )

    def expected_proof_type(self) -> str:
        return "absolute"

    def expected_attack_class(self) -> str:
        return "graphql_depth"

    def _was_retried(self, request: dict[str, Any]) -> bool:
        raw_retries = request.get("retry_count", request.get("retries", 0))
        if isinstance(raw_retries, int):
            return raw_retries > 0
        if isinstance(raw_retries, str) and raw_retries.isdigit():
            return int(raw_retries) > 0
        return False

    def _status_of(self, response: dict[str, Any]) -> int | None:
        for key in ("status", "status_code", "code"):
            raw = response.get(key)
            if isinstance(raw, int):
                return raw
            if isinstance(raw, str) and raw.isdigit():
                return int(raw)
        return None

    def _to_text(self, value: Any) -> str:
        if isinstance(value, str):
            return value
        if isinstance(value, (dict, list)):
            return json.dumps(value, sort_keys=True, separators=(",", ":"))
        if value is None:
            return ""
        return str(value)
