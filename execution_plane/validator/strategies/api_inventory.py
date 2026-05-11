from __future__ import annotations

import json

from execution_plane.validator.strategies.base import ValidationStrategy
from storage.db.models import ProofArtifact, RawProbe

_MIN_CONFIDENCE: float = 0.85


class ApiInventoryStrategy(ValidationStrategy):
    """Validates shadow API findings: deprecated endpoints and admin panel access."""

    def expected_attack_class(self) -> str:
        return "api_inventory"

    def expected_proof_type(self) -> str:
        return "shadow_api"

    def validate(self, attack_probe: RawProbe, control_probe: RawProbe | None) -> ProofArtifact | None:
        del control_probe

        status_code = int(attack_probe.response.get("status_code", 0))
        if status_code in {404, 410, 301, 302, 308, 403}:
            return None
        if status_code != 200:
            return None

        content_type = str(attack_probe.response.get("content_type", ""))
        has_json = "json" in content_type.lower()
        confidence = 0.87 if has_json else 0.85
        if confidence < _MIN_CONFIDENCE:
            return None

        hypothesis_raw = attack_probe.request.get("body") or "{}"
        try:
            probe_ctx = json.loads(str(hypothesis_raw))
        except (json.JSONDecodeError, TypeError):
            probe_ctx = {}

        probe_type = str(probe_ctx.get("probe_type", "shadow_api"))
        target_url = str(probe_ctx.get("target_url", attack_probe.request.get("url", "")))
        summary = f"Shadow API active: {target_url} responds {status_code} ({probe_type})"
        evidence_notes = (
            f"probe_type={probe_type}; status_code={status_code}; "
            f"content_type={content_type}; has_json_body={has_json}"
        )

        return ProofArtifact(
            attack_task_id=attack_probe.attack_task_id,
            proof_type=self.expected_proof_type(),
            confidence_score=confidence,
            attack_probe_id=attack_probe.id,
            control_probe_id=None,
            summary=summary,
            evidence_notes=evidence_notes,
        )


class ApiDocExposureStrategy(ValidationStrategy):
    """Validates API documentation exposure (swagger/openapi spec publicly accessible)."""

    _SPEC_SIGNATURES: frozenset[str] = frozenset({"swagger", "openapi", "paths", "definitions", "components"})
    _LARGE_BODY_LIMIT: int = 1_048_576

    def expected_attack_class(self) -> str:
        return "api_doc_exposure"

    def expected_proof_type(self) -> str:
        return "api_doc_exposure"

    def validate(self, attack_probe: RawProbe, control_probe: RawProbe | None) -> ProofArtifact | None:
        del control_probe

        status_code = int(attack_probe.response.get("status_code", 0))
        if status_code != 200:
            return None

        body = str(attack_probe.response.get("body", ""))
        if len(body) > self._LARGE_BODY_LIMIT:
            body = body[:1024]
        body_lower = body.lower()

        matched = sum(1 for sig in self._SPEC_SIGNATURES if sig.lower() in body_lower)
        if matched < 2:
            return None

        spec_type = "swagger" if "swagger" in body_lower else "openapi"
        endpoint_count = 0
        try:
            parsed = json.loads(body)
            if isinstance(parsed, dict):
                endpoint_count = len(parsed.get("paths", {}))
        except (json.JSONDecodeError, ValueError):
            pass

        target_url = str(attack_probe.request.get("url", ""))
        summary = f"API spec publicly exposed at {target_url} ({spec_type}, {endpoint_count} paths)"
        evidence_notes = (
            f"spec_type={spec_type}; endpoint_count={endpoint_count}; "
            f"status_code={status_code}; signatures_matched={matched}"
        )

        return ProofArtifact(
            attack_task_id=attack_probe.attack_task_id,
            proof_type=self.expected_proof_type(),
            confidence_score=0.93,
            attack_probe_id=attack_probe.id,
            control_probe_id=None,
            summary=summary,
            evidence_notes=evidence_notes,
        )


class BackupFileExposureStrategy(ValidationStrategy):
    """Validates backup file exposure (.bak, .old, .swp etc accessible)."""

    _ALLOWED_CONTENT_TYPES: tuple[str, ...] = (
        "text/plain",
        "text/xml",
        "application/octet-stream",
        "application/",
    )
    _BLOCKED_CONTENT_TYPES: tuple[str, ...] = ("text/html", "text/javascript", "image/", "video/", "audio/")
    _PREVIEW_LIMIT: int = 256

    def expected_attack_class(self) -> str:
        return "backup_file_exposure"

    def expected_proof_type(self) -> str:
        return "backup_file_exposure"

    def validate(self, attack_probe: RawProbe, control_probe: RawProbe | None) -> ProofArtifact | None:
        del control_probe

        status_code = int(attack_probe.response.get("status_code", 0))
        if status_code != 200:
            return None

        content_type = str(attack_probe.response.get("content_type", "")).lower()
        if any(blocked in content_type for blocked in self._BLOCKED_CONTENT_TYPES):
            return None
        if not any(allowed in content_type for allowed in self._ALLOWED_CONTENT_TYPES):
            return None

        body = str(attack_probe.response.get("body", ""))
        preview = body[: self._PREVIEW_LIMIT]
        target_url = str(attack_probe.request.get("url", ""))
        summary = f"Backup file exposed at {target_url} ({content_type})"
        evidence_notes = (
            f"status_code={status_code}; content_type={content_type}; "
            f"preview_bytes={len(preview)}; full_body_truncated=true"
        )

        return ProofArtifact(
            attack_task_id=attack_probe.attack_task_id,
            proof_type=self.expected_proof_type(),
            confidence_score=0.90,
            attack_probe_id=attack_probe.id,
            control_probe_id=None,
            summary=summary,
            evidence_notes=evidence_notes,
        )
