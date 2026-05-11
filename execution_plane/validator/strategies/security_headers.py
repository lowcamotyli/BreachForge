from __future__ import annotations

import re
from typing import Any

from execution_plane.validator.strategies.base import ValidationStrategy
from storage.db.models import ProofArtifact, RawProbe


class SecurityHeadersStrategy(ValidationStrategy):
    def expected_attack_class(self) -> str:
        return "security_headers"

    def expected_proof_type(self) -> str:
        return "security_header_missing"

    def validate(self, attack_probe: RawProbe, control_probe: RawProbe | None) -> ProofArtifact | None:
        del control_probe
        headers = self._normalized_headers(attack_probe.response)

        hsts = headers.get("strict-transport-security")
        if hsts is None:
            return self._build_proof(
                attack_probe,
                0.95,
                "HSTS header missing — HTTPS not enforced",
                "missing_header=strict-transport-security",
            )

        hsts_max_age = self._parse_hsts_max_age(hsts)
        if 0 <= hsts_max_age < 31536000:
            return self._build_proof(
                attack_probe,
                0.85,
                "HSTS max-age below 1 year",
                f"header=strict-transport-security,max_age={hsts_max_age},required_min=31536000",
            )

        csp = headers.get("content-security-policy")
        if csp is None:
            return self._build_proof(
                attack_probe,
                0.95,
                "Content-Security-Policy header missing",
                "missing_header=content-security-policy",
            )

        csp_lower = csp.lower()
        if "unsafe-inline" in csp_lower:
            return self._build_proof(
                attack_probe,
                0.90,
                "CSP allows unsafe-inline",
                "header=content-security-policy,issue=unsafe-inline",
            )

        if "unsafe-eval" in csp_lower:
            return self._build_proof(
                attack_probe,
                0.90,
                "CSP allows unsafe-eval",
                "header=content-security-policy,issue=unsafe-eval",
            )

        if self._csp_has_script_wildcard(csp_lower):
            return self._build_proof(
                attack_probe,
                0.85,
                "CSP wildcard source allows arbitrary scripts",
                "header=content-security-policy,issue=script_or_default_wildcard",
            )

        if headers.get("x-frame-options") is None:
            return self._build_proof(
                attack_probe,
                0.90,
                "X-Frame-Options missing — clickjacking possible",
                "missing_header=x-frame-options",
            )

        if headers.get("x-content-type-options") is None:
            return self._build_proof(
                attack_probe,
                0.90,
                "X-Content-Type-Options missing — MIME sniffing risk",
                "missing_header=x-content-type-options",
            )

        if headers.get("permissions-policy") is None:
            return self._build_proof(
                attack_probe,
                0.85,
                "Permissions-Policy header missing",
                "missing_header=permissions-policy",
            )

        return None

    def _build_proof(self, attack_probe: RawProbe, confidence: float, summary: str, evidence_notes: str) -> ProofArtifact:
        return ProofArtifact(
            attack_task_id=attack_probe.attack_task_id,
            proof_type=self.expected_proof_type(),
            confidence_score=confidence,
            attack_probe_id=attack_probe.id,
            control_probe_id=None,
            summary=summary,
            evidence_notes=evidence_notes,
        )

    def _normalized_headers(self, response: dict[str, Any]) -> dict[str, str]:
        headers = response.get("headers", {})
        if not isinstance(headers, dict):
            return {}

        normalized: dict[str, str] = {}
        for key, value in headers.items():
            if not isinstance(key, str):
                continue
            lowered = key.lower()
            if isinstance(value, str):
                normalized[lowered] = value
            elif isinstance(value, list):
                str_values = [item for item in value if isinstance(item, str)]
                if str_values:
                    normalized[lowered] = ", ".join(str_values)
        return normalized

    def _parse_hsts_max_age(self, value: str) -> int:
        match = re.search(r"max-age\s*=\s*(\d+)", value, re.IGNORECASE)
        if match is None:
            return -1
        try:
            return int(match.group(1))
        except ValueError:
            return -1

    def _csp_has_script_wildcard(self, csp: str) -> bool:
        directives = [part.strip() for part in csp.split(";") if part.strip()]
        for directive in directives:
            if directive.startswith("script-src") or directive.startswith("default-src"):
                tokens = directive.split()
                if any(token == "*" for token in tokens[1:]):
                    return True
        return False


class CorsAnalysisStrategy(ValidationStrategy):
    def expected_attack_class(self) -> str:
        return "cors_analysis"

    def expected_proof_type(self) -> str:
        return "cors_misconfiguration"

    def validate(self, attack_probe: RawProbe, control_probe: RawProbe | None) -> ProofArtifact | None:
        del control_probe
        headers = self._normalized_headers(attack_probe.response)

        acao = headers.get("access-control-allow-origin")
        acac = headers.get("access-control-allow-credentials")
        acac_true = isinstance(acac, str) and acac.lower() == "true"

        if acao == "*" and acac_true:
            return self._build_proof(
                attack_probe,
                0.98,
                "CORS wildcard with credentials — cross-origin session theft",
                "acao=*,acac=true",
            )

        if acao == "null":
            return self._build_proof(
                attack_probe,
                0.95,
                "CORS accepts null origin — sandboxed iframe bypass",
                "acao=null",
            )

        if acao is not None and acao not in {"*", "null"} and acac_true:
            return self._build_proof(
                attack_probe,
                0.95,
                "CORS reflects arbitrary origin with credentials",
                f"acao={acao},acac=true",
            )

        if acao is not None and acao not in {"*", "null"}:
            return self._build_proof(
                attack_probe,
                0.85,
                "CORS reflects arbitrary origin",
                f"acao={acao}",
            )

        return None

    def _build_proof(self, attack_probe: RawProbe, confidence: float, summary: str, evidence_notes: str) -> ProofArtifact:
        return ProofArtifact(
            attack_task_id=attack_probe.attack_task_id,
            proof_type=self.expected_proof_type(),
            confidence_score=confidence,
            attack_probe_id=attack_probe.id,
            control_probe_id=None,
            summary=summary,
            evidence_notes=evidence_notes,
        )

    def _normalized_headers(self, response: dict[str, Any]) -> dict[str, str]:
        headers = response.get("headers", {})
        if not isinstance(headers, dict):
            return {}

        normalized: dict[str, str] = {}
        for key, value in headers.items():
            if not isinstance(key, str):
                continue
            lowered = key.lower()
            if isinstance(value, str):
                normalized[lowered] = value
            elif isinstance(value, list):
                str_values = [item for item in value if isinstance(item, str)]
                if str_values:
                    normalized[lowered] = ", ".join(str_values)
        return normalized


class TlsAnalysisStrategy(ValidationStrategy):
    def expected_attack_class(self) -> str:
        return "tls_analysis"

    def expected_proof_type(self) -> str:
        return "tls_weak_version"

    def validate(self, attack_probe: RawProbe, control_probe: RawProbe | None) -> ProofArtifact | None:
        del control_probe
        response = attack_probe.response

        tls_value = response.get("tls_version")
        if not isinstance(tls_value, str):
            tls_value = response.get("ssl_version")
        if not isinstance(tls_value, str):
            return None

        normalized = tls_value.strip().lower()
        if normalized in {"tlsv1", "tlsv1.0", "1.0", "ssl3"}:
            return self._build_proof(
                attack_probe,
                0.90,
                "TLS 1.0 or older accepted — protocol downgrade attack possible",
                f"tls_version={tls_value}",
            )

        if normalized in {"tlsv1.1", "1.1"}:
            return self._build_proof(
                attack_probe,
                0.85,
                "TLS 1.1 accepted — deprecated protocol",
                f"tls_version={tls_value}",
            )

        return None

    def _build_proof(self, attack_probe: RawProbe, confidence: float, summary: str, evidence_notes: str) -> ProofArtifact:
        return ProofArtifact(
            attack_task_id=attack_probe.attack_task_id,
            proof_type=self.expected_proof_type(),
            confidence_score=confidence,
            attack_probe_id=attack_probe.id,
            control_probe_id=None,
            summary=summary,
            evidence_notes=evidence_notes,
        )
