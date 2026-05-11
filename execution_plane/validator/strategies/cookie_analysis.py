from __future__ import annotations

from typing import Any

from execution_plane.validator.strategies.base import ValidationStrategy
from storage.db.models import ProofArtifact, RawProbe


class CookieAnalysisStrategy(ValidationStrategy):
    _SESSION_TOKENS = ("session", "token", "auth", "sess", "jwt", "sid")

    def expected_attack_class(self) -> str:
        return "cookie_analysis"

    def expected_proof_type(self) -> str:
        return "cookie_security_flags"

    def validate(self, attack_probe: RawProbe, control_probe: RawProbe | None) -> ProofArtifact | None:
        del control_probe
        cookie_headers = self._extract_set_cookie_headers(attack_probe.response)
        if not cookie_headers:
            return None

        first_high: tuple[float, str, str, bool, str] | None = None
        first_medium: tuple[float, str, str, bool, str] | None = None

        for cookie_header in cookie_headers:
            name, attributes = self._parse_cookie(cookie_header)
            if not name:
                continue

            is_session_cookie = self._is_session_cookie(name)
            has_httponly = "httponly" in attributes
            has_secure = "secure" in attributes
            same_site = attributes.get("samesite")
            domain = attributes.get("domain")

            if not has_httponly:
                if is_session_cookie and first_high is None:
                    first_high = (
                        0.95,
                        f"Cookie {name} missing HttpOnly flag — susceptible to JavaScript theft",
                        "missing_httponly",
                        is_session_cookie,
                        name,
                    )
                if not is_session_cookie and first_medium is None:
                    first_medium = (
                        0.80,
                        f"Cookie {name} missing HttpOnly flag — susceptible to JavaScript theft",
                        "missing_httponly",
                        is_session_cookie,
                        name,
                    )

            if not has_secure and first_high is None:
                first_high = (
                    0.95,
                    f"Cookie {name} missing Secure flag — transmitted over HTTP",
                    "missing_secure",
                    is_session_cookie,
                    name,
                )

            if isinstance(same_site, str) and same_site.lower() == "none" and not has_secure and first_high is None:
                first_high = (
                    0.92,
                    f"Cookie {name} has SameSite=None without Secure — cross-site requests allowed",
                    "samesite_none_without_secure",
                    is_session_cookie,
                    name,
                )

            if "samesite" not in attributes and first_medium is None:
                first_medium = (
                    0.75,
                    f"Cookie {name} missing SameSite attribute",
                    "missing_samesite",
                    is_session_cookie,
                    name,
                )

            if isinstance(domain, str) and domain.startswith(".") and first_medium is None:
                first_medium = (
                    0.70,
                    f"Cookie {name} has overly broad domain scope",
                    "broad_domain_scope",
                    is_session_cookie,
                    name,
                )

            if first_high is not None:
                break

        finding = first_high or first_medium
        if finding is None:
            return None

        confidence, summary, issue, is_session_cookie, cookie_name = finding
        return ProofArtifact(
            attack_task_id=attack_probe.attack_task_id,
            proof_type=self.expected_proof_type(),
            confidence_score=confidence,
            attack_probe_id=attack_probe.id,
            control_probe_id=None,
            summary=summary,
            evidence_notes=f"cookie_name={cookie_name},issue={issue},is_session_cookie={is_session_cookie}",
        )

    def _extract_set_cookie_headers(self, response: dict[str, Any]) -> list[str]:
        headers = response.get("headers")
        if not isinstance(headers, dict):
            return []

        for key in ("set-cookie", "Set-Cookie"):
            if key not in headers:
                continue
            value = headers.get(key)
            if isinstance(value, str):
                return [value]
            if isinstance(value, list):
                return [item for item in value if isinstance(item, str)]
            return []

        return []

    def _parse_cookie(self, cookie_header: str) -> tuple[str, dict[str, str | None]]:
        parts = [part.strip() for part in cookie_header.split(";") if part.strip()]
        if not parts:
            return "", {}

        name_value = parts[0]
        if "=" not in name_value:
            return "", {}

        name, _value = name_value.split("=", 1)
        cookie_name = name.strip()
        attributes: dict[str, str | None] = {}

        for part in parts[1:]:
            if "=" in part:
                attr_name, attr_value = part.split("=", 1)
                attributes[attr_name.strip().lower()] = attr_value.strip()
            else:
                attributes[part.strip().lower()] = None

        return cookie_name, attributes

    def _is_session_cookie(self, cookie_name: str) -> bool:
        lowered = cookie_name.lower()
        return any(token in lowered for token in self._SESSION_TOKENS)
