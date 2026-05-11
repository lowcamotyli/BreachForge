from __future__ import annotations

from execution_plane.validator.strategies.base import ValidationStrategy
from storage.db.models import ProofArtifact, RawProbe


class LdapInjectionStrategy(ValidationStrategy):
    _MIN_CONFIDENCE: float = 0.70
    _LDAP_ERROR_MARKERS: tuple[str, ...] = (
        "ldap",
        "invalid dn",
        "ldap_search",
        "invalid filter",
        "javax.naming",
        "ldap error",
    )

    def validate(self, attack_probe: RawProbe, control_probe: RawProbe | None) -> ProofArtifact | None:
        attack_status = int(attack_probe.response.get("status_code") or attack_probe.response.get("status") or 200)
        control_status = (
            int(control_probe.response.get("status_code") or control_probe.response.get("status") or 200)
            if control_probe
            else 200
        )
        body = str(attack_probe.response.get("body") or attack_probe.response.get("text") or "").lower()

        confidence = 0.0
        summary = ""

        if attack_status == 200 and control_status in {401, 403}:
            confidence = 0.88
            summary = "Auth bypass via LDAP injection"
        elif any(marker in body for marker in self._LDAP_ERROR_MARKERS):
            confidence = 0.70
            summary = "LDAP error disclosure after injection probe"
        else:
            return None

        if confidence < self._MIN_CONFIDENCE:
            return None

        return ProofArtifact(
            attack_task_id=attack_probe.attack_task_id,
            proof_type=self.expected_proof_type(),
            confidence_score=confidence,
            attack_probe_id=attack_probe.id,
            control_probe_id=control_probe.id if control_probe else None,
            summary=summary,
            evidence_notes=f"attack_status={attack_status},control_status={control_status}",
        )

    def expected_proof_type(self) -> str:
        return "ldap_injection"

    def expected_attack_class(self) -> str:
        return "ldap_injection"


class XpathInjectionStrategy(ValidationStrategy):
    _MIN_CONFIDENCE: float = 0.75
    _XPATH_ERROR_MARKERS: tuple[str, ...] = (
        "xpath",
        "xpathexception",
        "invalid expression",
        "javax.xml",
        "xpath error",
        "unterminated string",
    )

    def validate(self, attack_probe: RawProbe, control_probe: RawProbe | None) -> ProofArtifact | None:
        attack_status = int(attack_probe.response.get("status_code") or attack_probe.response.get("status") or 200)
        body = str(attack_probe.response.get("body") or attack_probe.response.get("text") or "").lower()
        control_body_len = len(str(control_probe.response.get("body") or "")) if control_probe else 0
        attack_body_len = len(str(attack_probe.response.get("body") or ""))

        confidence = 0.0
        summary = ""

        if attack_status == 200 and control_body_len > 0 and attack_body_len > control_body_len * 1.5:
            confidence = 0.85
            summary = "XPath injection returns unexpected data volume"
        elif any(marker in body for marker in self._XPATH_ERROR_MARKERS):
            confidence = 0.75
            summary = "XPath error disclosure after injection probe"
        else:
            return None

        if confidence < self._MIN_CONFIDENCE:
            return None

        return ProofArtifact(
            attack_task_id=attack_probe.attack_task_id,
            proof_type=self.expected_proof_type(),
            confidence_score=confidence,
            attack_probe_id=attack_probe.id,
            control_probe_id=control_probe.id if control_probe else None,
            summary=summary,
            evidence_notes=(
                f"attack_status={attack_status},control_body_len={control_body_len},attack_body_len={attack_body_len}"
            ),
        )

    def expected_proof_type(self) -> str:
        return "xpath_injection"

    def expected_attack_class(self) -> str:
        return "xpath_injection"


class HeaderInjectionStrategy(ValidationStrategy):
    _MIN_CONFIDENCE: float = 0.80
    _INJECTED_HOST: str = "evil.com"

    def validate(self, attack_probe: RawProbe, control_probe: RawProbe | None) -> ProofArtifact | None:
        attack_status = int(attack_probe.response.get("status_code") or attack_probe.response.get("status") or 200)
        control_status = (
            int(control_probe.response.get("status_code") or control_probe.response.get("status") or 200)
            if control_probe is not None
            else 200
        )
        body = str(attack_probe.response.get("body") or attack_probe.response.get("text") or "")
        headers = attack_probe.response.get("headers")
        headers_dict = headers if isinstance(headers, dict) else {}
        location_header = str(headers_dict.get("location") or headers_dict.get("Location") or "")

        confidence = 0.0
        summary = ""

        if self._INJECTED_HOST in body or self._INJECTED_HOST in location_header:
            confidence = 0.87
            summary = "Host header reflected in response body or redirect location"
        elif control_probe is not None and attack_status != control_status:
            confidence = 0.80
            summary = (
                f"Access control changed via header injection (attack={attack_status}, control={control_status})"
            )
        else:
            return None

        if confidence < self._MIN_CONFIDENCE:
            return None

        return ProofArtifact(
            attack_task_id=attack_probe.attack_task_id,
            proof_type=self.expected_proof_type(),
            confidence_score=confidence,
            attack_probe_id=attack_probe.id,
            control_probe_id=control_probe.id if control_probe else None,
            summary=summary,
            evidence_notes=f"attack_status={attack_status},control_status={control_status}",
        )

    def expected_proof_type(self) -> str:
        return "header_injection"

    def expected_attack_class(self) -> str:
        return "header_injection"
