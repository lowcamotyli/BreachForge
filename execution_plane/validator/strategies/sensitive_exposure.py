from __future__ import annotations

import json
import re
from typing import Any

from execution_plane.validator.secret_leak_source import SecretLeakSourceClassifier
from execution_plane.validator.secret_intelligence import SecretType, bucket_ttl, classify
from execution_plane.validator.strategies.base import ValidationStrategy
from storage.db.models import ProofArtifact, RawProbe

_LEAK_SOURCE_CLASSIFIER = SecretLeakSourceClassifier()
_MIN_PROOF_CONFIDENCE_THRESHOLD = 0.85
_AUTH_HEADER_NAMES: set[str] = {"authorization", "cookie", "x-api-key", "x-auth-token", "proxy-authorization"}
_PATTERN_REGISTRY: dict[str, tuple[re.Pattern[str], ...]] = {
    "credential": (
        re.compile(r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"]?[^'\"\s]{6,}"),
        re.compile(r"(?i)(api[_-]?key|secret|client[_-]?secret)\s*[:=]\s*['\"]?[a-z0-9_\-\.=]{8,}"),
        re.compile(r"[A-Za-z0-9_-]{20,}"),
        re.compile(r'"password"\s*:\s*"[^"]+"'),
    ),
    "token": (
        re.compile(r"(?i)bearer\s+[a-z0-9\-\._~\+/]+=*"),
        re.compile(r"(?i)(access[_-]?token|refresh[_-]?token|session[_-]?token|jwt)\s*[:=]\s*['\"]?[a-z0-9\-\._~\+/]+=*"),
        re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),
    ),
    "pii": (
        re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
        re.compile(r"\b(?:\d[ -]*?){13,16}\b"),
        re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"),
        re.compile(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b"),
    ),
}


class SensitiveExposureStrategy(ValidationStrategy):
    def validate(self, attack_probe: RawProbe, control_probe: RawProbe | None) -> ProofArtifact | None:
        del control_probe

        probe_context = self._extract_probe_context(attack_probe.request)
        candidate = probe_context.get("candidate")
        unauth_mode = bool(getattr(candidate, "unauth_mode", False))
        if not unauth_mode and isinstance(candidate, dict):
            unauth_mode = bool(candidate.get("unauth_mode"))
        if not unauth_mode:
            unauth_mode = bool(getattr(attack_probe, "unauth_mode", False))
        if not unauth_mode:
            unauth_mode = bool(probe_context.get("unauth_mode"))

        if unauth_mode:
            public_responses = self._extract_public_responses(probe_context)
            public_findings = self.scan_public_responses(public_responses, probe_context)
            if public_findings:
                first_finding = public_findings[0]
                confidence = float(first_finding.get("confidence", _MIN_PROOF_CONFIDENCE_THRESHOLD))
                if confidence >= _MIN_PROOF_CONFIDENCE_THRESHOLD:
                    return ProofArtifact(
                        attack_task_id=attack_probe.attack_task_id,
                        proof_type=self.expected_proof_type(),
                        confidence_score=confidence,
                        attack_probe_id=attack_probe.id,
                        control_probe_id=None,
                        summary="Sensitive exposure proof: unauthenticated baseline response contains sensitive indicator patterns",
                        evidence_notes=(
                            f"public_response_findings={len(public_findings)}; "
                            f"url={first_finding.get('url', '')}; "
                            f"pattern_matched={first_finding.get('pattern_matched', '')}; "
                            f"snippet={first_finding.get('evidence_snippet', '')}"
                        ),
                    )

        flattened = self._flatten_response(attack_probe.response)
        matches_by_category = self._find_matches(flattened)
        if not matches_by_category:
            return None
        matched_values: list[str] = []
        for values in matches_by_category.values():
            matched_values.extend(values)
        first_matched_secret = matched_values[0] if matched_values else None
        secret_type = SecretType.GENERIC_SECRET.value
        secret_fingerprint = "n/a"
        ttl_bucket = "n/a"
        if first_matched_secret:
            meta = classify(first_matched_secret)
            secret_type = meta.secret_type.value
            secret_fingerprint = meta.fingerprint
            if meta.jwt_meta is not None:
                ttl_bucket = bucket_ttl(meta.jwt_meta.ttl_seconds, meta.jwt_meta.expired)
            else:
                ttl_bucket = bucket_ttl(None, False)

        request_has_auth = self._request_has_auth_headers(attack_probe.request)
        confidence = 0.90 if len(matches_by_category) > 1 else 0.85
        if request_has_auth:
            confidence = 0.85
        else:
            confidence += 0.05
        if str(probe_context.get("probe_type") or "") == "unauth_baseline":
            confidence += 0.03
        if confidence < _MIN_PROOF_CONFIDENCE_THRESHOLD:
            return None

        probe_type = str(probe_context.get("probe_type") or "")
        parent_finding_id = probe_context.get("parent_finding_id")
        _resp_headers = attack_probe.response.get("headers", {})
        _headers_text = self._to_text(_resp_headers)
        _found_in_headers = bool(self._find_matches(_headers_text))
        _classification = _LEAK_SOURCE_CLASSIFIER.classify(
            url=str(attack_probe.request.get("url", "")),
            response_content_type=str(attack_probe.response.get("content_type", "")),
            response_body=str(attack_probe.response.get("body", "")),
            found_in_response_headers=_found_in_headers,
        )

        summary = "Sensitive exposure proof: response contains credential/token/PII indicator patterns"
        evidence_notes = f"matches={', '.join(sorted(matches_by_category))}; request_has_auth={request_has_auth}"
        evidence_notes = (
            f"{evidence_notes}; secret_type={secret_type}; "
            f"secret_fingerprint={secret_fingerprint}; ttl_bucket={ttl_bucket}; active_during_scan=false"
        )
        if probe_type.startswith("impact_"):
            summary = f"Sensitive exposure impact proof: {probe_type} confirmed sensitive material remains reachable"
            evidence_notes = (
                f"{evidence_notes}; follow_up=true; impact_probe={probe_type}; "
                f"parent_finding_id={parent_finding_id or 'unknown'}; safe_mode=true"
            )
        evidence_notes = (
            f"{evidence_notes}; leak_source={_classification.source.value}; "
            f"leak_source_confidence={_classification.confidence:.2f}"
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

    def scan_public_responses(self, responses: list[dict], context: dict) -> list:
        findings: list[dict[str, Any]] = []
        for response in responses:
            if not isinstance(response, dict):
                continue
            flattened = self._flatten_response(response)
            if not flattened:
                continue
            matches_by_category = self._find_matches(flattened)
            if not matches_by_category:
                continue
            confidence = 0.90 if len(matches_by_category) > 1 else 0.85
            confidence += 0.05
            if confidence < _MIN_PROOF_CONFIDENCE_THRESHOLD:
                continue
            first_match = ""
            for values in matches_by_category.values():
                if values:
                    first_match = values[0]
                    break
            if not first_match:
                continue
            match_index = flattened.find(first_match)
            if match_index >= 0:
                context_start = max(0, match_index - 100)
                context_end = min(len(flattened), match_index + len(first_match) + 100)
                evidence_snippet = flattened[context_start:context_end][:200]
            else:
                evidence_snippet = first_match[:200]
            findings.append(
                {
                    "url": str(response.get("url") or context.get("url") or ""),
                    "finding_type": "sensitive_exposure",
                    "pattern_matched": first_match,
                    "confidence": confidence,
                    "evidence_snippet": evidence_snippet,
                }
            )
        return findings

    def expected_proof_type(self) -> str:
        return "absolute"

    def expected_attack_class(self) -> str:
        return "sensitive_exposure"

    def _flatten_response(self, response: dict[str, Any]) -> str:
        chunks: list[str] = []
        for key in ("body", "json", "data", "text", "headers"):
            if key not in response:
                continue
            value = response[key]
            chunks.append(self._to_text(value))
        return "\n".join(chunk for chunk in chunks if chunk)

    def _to_text(self, value: Any) -> str:
        if isinstance(value, str):
            stripped = value.strip()
            if not stripped:
                return ""
            try:
                parsed = json.loads(stripped)
            except (TypeError, ValueError):
                return stripped
            return self._to_text(parsed)
        if isinstance(value, dict):
            ordered = {str(key): value[key] for key in sorted(value)}
            return json.dumps(ordered, sort_keys=True, separators=(",", ":"))
        if isinstance(value, list):
            return json.dumps(value, separators=(",", ":"))
        return str(value)

    def _find_matches(self, content: str) -> dict[str, list[str]]:
        discovered: dict[str, list[str]] = {}
        for group_name, patterns in _PATTERN_REGISTRY.items():
            matched_values: list[str] = []
            seen_values: set[str] = set()
            for pattern in patterns:
                for match in pattern.finditer(content):
                    matched_value = match.group(0)
                    if matched_value in seen_values:
                        continue
                    seen_values.add(matched_value)
                    matched_values.append(matched_value)
            if matched_values:
                discovered[group_name] = matched_values
        return discovered

    def _request_has_auth_headers(self, request: dict[str, Any]) -> bool:
        headers = request.get("headers")
        if isinstance(headers, dict):
            for header_name in headers:
                if str(header_name).lower() in _AUTH_HEADER_NAMES:
                    return True

        for key in request:
            if key.lower() in _AUTH_HEADER_NAMES:
                return True
        return False

    def _extract_probe_context(self, request: dict[str, Any]) -> dict[str, Any]:
        body = request.get("body")
        if not isinstance(body, str) or not body.strip():
            return {}
        try:
            parsed = json.loads(body)
        except json.JSONDecodeError:
            return {}
        if not isinstance(parsed, dict):
            return {}
        return parsed

    def _extract_public_responses(self, probe_context: dict[str, Any]) -> list[dict[str, Any]]:
        for key in (
            "baseline_responses",
            "unauth_baseline_responses",
            "public_responses",
            "responses",
        ):
            value = probe_context.get(key)
            if isinstance(value, list):
                return [item for item in value if isinstance(item, dict)]

        for key in ("baseline_response", "unauth_response", "public_response", "response"):
            value = probe_context.get(key)
            if isinstance(value, dict):
                return [value]

        return []
