from __future__ import annotations

from execution_plane.validator.strategies.base import ValidationStrategy
from storage.db.models import ProofArtifact, RawProbe


class CsrfStrategy(ValidationStrategy):
    def validate(self, attack_probe: RawProbe, control_probe: RawProbe | None) -> ProofArtifact | None:
        request = self._extract_request(attack_probe)
        hypothesis = request.get("hypothesis")
        hypothesis_dict = hypothesis if isinstance(hypothesis, dict) else {}

        probe_type = str(hypothesis_dict.get("probe_type") or request.get("probe_type") or "csrf_no_token")
        method = str(request.get("method") or "")
        path = str(request.get("path") or request.get("url") or "")
        status_code = self._extract_status_code(attack_probe.response)

        confidence: float
        summary: str
        evidence_notes: str

        if probe_type == "csrf_no_token":
            if 200 <= status_code <= 299:
                confidence = 0.90
                summary = (
                    f"CSRF: {method} {path} accepted without Origin/Referer header "
                    f"and without CSRF token (HTTP {status_code})"
                )
                evidence_notes = (
                    f"probe_type=csrf_no_token,method={method},status={status_code},"
                    "missing_headers=Origin,Referer"
                )
            elif status_code == 302:
                return None
            elif status_code in {400, 403, 422}:
                return None
            elif 400 <= status_code <= 599:
                return None
            else:
                return None
        elif probe_type == "csrf_double_submit":
            if 200 <= status_code <= 299:
                confidence = 0.88
                summary = (
                    f"CSRF double-submit weakness: mismatched cookie/header token accepted at "
                    f"{method} {path}"
                )
                evidence_notes = (
                    f"probe_type=csrf_double_submit,method={method},status={status_code}"
                )
            else:
                return None
        else:
            return None

        return ProofArtifact(
            attack_task_id=attack_probe.attack_task_id,
            proof_type=self.expected_proof_type(),
            confidence_score=confidence,
            attack_probe_id=attack_probe.id,
            control_probe_id=control_probe.id if control_probe else None,
            summary=summary,
            evidence_notes=evidence_notes,
        )

    def expected_attack_class(self) -> str:
        return "csrf"

    def expected_proof_type(self) -> str:
        return "csrf_missing_protection"

    def _extract_request(self, attack_probe: RawProbe) -> dict[str, object]:
        request = attack_probe.request
        return request if isinstance(request, dict) else {}

    def _extract_status_code(self, response: dict[str, object]) -> int:
        raw_status = response.get("status_code") or response.get("status") or 0
        try:
            return int(raw_status)
        except (TypeError, ValueError):
            return 0
