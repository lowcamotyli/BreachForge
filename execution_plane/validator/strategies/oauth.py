from __future__ import annotations

import json
from typing import Any

from execution_plane.validator.strategies.base import ValidationStrategy
from storage.db.models import ProofArtifact, RawProbe

_REDIRECT_HIGH_CONFIDENCE = 0.95
_REDIRECT_PARTIAL_MATCH_CONFIDENCE = 0.88
_STATE_CSRF_CONFIDENCE = 0.9
_TOKEN_REUSE_CONFIDENCE = 0.92
_ERROR_DISCLOSURE_CONFIDENCE = 0.85
_ERROR_MARKERS: tuple[str, ...] = (
    "allowed_redirect_uris",
    "client_id",
    "/internal/",
    "\\internal\\",
    "stack trace",
)


class OauthRedirectStrategy(ValidationStrategy):
    def validate(self, attack_probe: RawProbe, control_probe: RawProbe | None) -> ProofArtifact | None:
        status = self._status_code(attack_probe.response)
        location = self._header_value(attack_probe.response, "location")
        body_text = self._to_text(attack_probe.response).lower()

        manipulated_host = self._request_value(attack_probe.request, "manipulated_redirect_host")
        original_redirect = self._request_value(attack_probe.request, "original_redirect_uri")
        manipulated_redirect = self._request_value(attack_probe.request, "manipulated_redirect_uri")
        partial_match = attack_probe.request.get("partial_match_probe") is True

        redirect_hit = (
            status in {301, 302, 303, 307, 308}
            and isinstance(location, str)
            and self._redirect_reaches_manipulated_target(location=location, manipulated_host=manipulated_host)
        )
        token_or_code_hit = self._response_exposes_token_or_code(
            text=body_text,
            manipulated_host=manipulated_host,
            location=location,
        )
        if not redirect_hit and not token_or_code_hit:
            return None

        confidence = _REDIRECT_PARTIAL_MATCH_CONFIDENCE if partial_match else _REDIRECT_HIGH_CONFIDENCE
        summary = "OAuth redirect accepted manipulated redirect URI and returned authorization material."
        if redirect_hit and not token_or_code_hit:
            summary = "OAuth redirect accepted manipulated redirect URI via HTTP redirect."

        return ProofArtifact(
            attack_task_id=attack_probe.attack_task_id,
            proof_type=self.expected_proof_type(),
            confidence_score=confidence,
            attack_probe_id=attack_probe.id,
            control_probe_id=control_probe.id if control_probe is not None else None,
            summary=summary,
            evidence_notes=(
                "probe_type=oauth_redirect; "
                f"status={status}; location={location or ''}; manipulated_host={manipulated_host or ''}; "
                f"original_redirect_uri={original_redirect or ''}; "
                f"manipulated_redirect_uri={manipulated_redirect or ''}; "
                f"partial_match={partial_match}"
            ),
        )

    def expected_proof_type(self) -> str:
        return "absolute"

    def expected_attack_class(self) -> str:
        return "oauth_redirect"

    def _redirect_reaches_manipulated_target(self, *, location: str, manipulated_host: str | None) -> bool:
        lowered = location.lower()
        if manipulated_host:
            return manipulated_host.lower() in lowered
        return "callback.scanner.local" in lowered or "evil." in lowered or ".evil." in lowered

    def _response_exposes_token_or_code(self, *, text: str, manipulated_host: str | None, location: str | None) -> bool:
        has_auth_material = "code=" in text or "access_token=" in text or "id_token=" in text
        if not has_auth_material:
            return False
        if location and self._redirect_reaches_manipulated_target(location=location, manipulated_host=manipulated_host):
            return True
        return manipulated_host is not None and manipulated_host.lower() in text

    def _status_code(self, response: dict[str, Any]) -> int | None:
        for key in ("status", "status_code", "code"):
            value = response.get(key)
            if isinstance(value, int):
                return value
            if isinstance(value, str) and value.isdigit():
                return int(value)
        return None

    def _header_value(self, response: dict[str, Any], header_name: str) -> str | None:
        headers = response.get("headers")
        if not isinstance(headers, dict):
            return None
        wanted = header_name.lower()
        for key, value in headers.items():
            if str(key).lower() != wanted:
                continue
            if isinstance(value, str):
                return value
            return str(value)
        return None

    def _request_value(self, request: dict[str, Any], key: str) -> str | None:
        value = request.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()

        hypothesis = request.get("hypothesis")
        if not isinstance(hypothesis, str):
            return None
        try:
            payload = json.loads(hypothesis)
        except (TypeError, ValueError):
            return None
        if not isinstance(payload, dict):
            return None
        nested = payload.get(key)
        if isinstance(nested, str) and nested.strip():
            return nested.strip()
        return None

    def _to_text(self, value: Any) -> str:
        if isinstance(value, str):
            return value
        if isinstance(value, (dict, list)):
            return json.dumps(value, sort_keys=True, separators=(",", ":"))
        if value is None:
            return ""
        return str(value)


class OauthStateCsrfStrategy(ValidationStrategy):
    def validate(self, attack_probe: RawProbe, control_probe: RawProbe | None) -> ProofArtifact | None:
        sent_without_state = attack_probe.request.get("state_omitted") is True or attack_probe.request.get("state") in {None, ""}
        if not sent_without_state:
            return None

        status = self._status_code(attack_probe.response)
        body_text = self._to_text(attack_probe.response).lower()
        if status not in {200, 302}:
            return None
        if not self._looks_like_authorization_success(body_text=body_text, response=attack_probe.response):
            return None

        return ProofArtifact(
            attack_task_id=attack_probe.attack_task_id,
            proof_type=self.expected_proof_type(),
            confidence_score=_STATE_CSRF_CONFIDENCE,
            attack_probe_id=attack_probe.id,
            control_probe_id=control_probe.id if control_probe is not None else None,
            summary="OAuth authorization flow accepted request without state parameter.",
            evidence_notes=f"probe_type=oauth_state_csrf; status={status}; state_omitted=true",
        )

    def expected_proof_type(self) -> str:
        return "absolute"

    def expected_attack_class(self) -> str:
        return "oauth_state_csrf"

    def _looks_like_authorization_success(self, *, body_text: str, response: dict[str, Any]) -> bool:
        if "code=" in body_text or "access_token=" in body_text or "id_token=" in body_text:
            return True
        location = self._header_value(response, "location")
        if not location:
            return False
        lowered = location.lower()
        return "code=" in lowered or "access_token=" in lowered or "id_token=" in lowered

    def _status_code(self, response: dict[str, Any]) -> int | None:
        for key in ("status", "status_code", "code"):
            value = response.get(key)
            if isinstance(value, int):
                return value
            if isinstance(value, str) and value.isdigit():
                return int(value)
        return None

    def _header_value(self, response: dict[str, Any], header_name: str) -> str | None:
        headers = response.get("headers")
        if not isinstance(headers, dict):
            return None
        wanted = header_name.lower()
        for key, value in headers.items():
            if str(key).lower() == wanted:
                return value if isinstance(value, str) else str(value)
        return None

    def _to_text(self, value: Any) -> str:
        if isinstance(value, str):
            return value
        if isinstance(value, (dict, list)):
            return json.dumps(value, sort_keys=True, separators=(",", ":"))
        if value is None:
            return ""
        return str(value)


class OauthTokenReuseStrategy(ValidationStrategy):
    def validate(self, attack_probe: RawProbe, control_probe: RawProbe | None) -> ProofArtifact | None:
        if attack_probe.request.get("after_logout") is not True:
            return None

        status = self._status_code(attack_probe.response)
        if status in {401, 403}:
            return None
        if status is None or status >= 400:
            return None
        elapsed_seconds = attack_probe.request.get("seconds_after_logout")

        return ProofArtifact(
            attack_task_id=attack_probe.attack_task_id,
            proof_type=self.expected_proof_type(),
            confidence_score=_TOKEN_REUSE_CONFIDENCE,
            attack_probe_id=attack_probe.id,
            control_probe_id=control_probe.id if control_probe is not None else None,
            summary="OAuth token remained valid after logout.",
            evidence_notes=(
                "probe_type=oauth_token_reuse; "
                f"status={status}; after_logout=true; seconds_after_logout={elapsed_seconds or ''}; "
                "resource_accessible=true"
            ),
        )

    def expected_proof_type(self) -> str:
        return "differential"

    def expected_attack_class(self) -> str:
        return "oauth_token_reuse"

    def _status_code(self, response: dict[str, Any]) -> int | None:
        for key in ("status", "status_code", "code"):
            value = response.get(key)
            if isinstance(value, int):
                return value
            if isinstance(value, str) and value.isdigit():
                return int(value)
        return None


class OauthErrorDisclosureStrategy(ValidationStrategy):
    def validate(self, attack_probe: RawProbe, control_probe: RawProbe | None) -> ProofArtifact | None:
        text = self._to_text(attack_probe.response).lower()
        hits = [marker for marker in _ERROR_MARKERS if marker in text]
        if not hits:
            return None

        return ProofArtifact(
            attack_task_id=attack_probe.attack_task_id,
            proof_type=self.expected_proof_type(),
            confidence_score=_ERROR_DISCLOSURE_CONFIDENCE,
            attack_probe_id=attack_probe.id,
            control_probe_id=control_probe.id if control_probe is not None else None,
            summary="OAuth error response disclosed sensitive client or redirect metadata.",
            evidence_notes=f"probe_type=oauth_error_disclosure; leaks={','.join(hits)}",
        )

    def expected_proof_type(self) -> str:
        return "absolute"

    def expected_attack_class(self) -> str:
        return "oauth_error_disclosure"

    def _to_text(self, value: Any) -> str:
        if isinstance(value, str):
            return value
        if isinstance(value, (dict, list)):
            return json.dumps(value, sort_keys=True, separators=(",", ":"))
        if value is None:
            return ""
        return str(value)
