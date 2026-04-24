from __future__ import annotations

import copy
import gzip
import json
import re
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

import structlog
from botocore.exceptions import BotoCoreError, ClientError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from storage.db.models import Finding, ProofArtifact, Scan, Severity
from storage.evidence.store import EvidenceStore

logger = structlog.get_logger(__name__)

REDACTED = "[REDACTED]"
_SENSITIVE_KEY_PATTERN = re.compile(r"authorization|cookie|password|token|secret", re.IGNORECASE)
_REQUEST_HEADER_SENSITIVE_KEYS: tuple[str, ...] = ("authorization", "cookie", "password", "token", "x-api-key")
_SENSITIVE_VALUE_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(?i)\bbearer\s+[a-z0-9\-\._~\+/]+=*"),
    re.compile(r"(?i)\beyJ[a-z0-9\-_]+\.[a-z0-9\-_]+(?:\.[a-z0-9\-_]+)?"),
    re.compile(r"(?i)(access[_-]?token|refresh[_-]?token|session[_-]?token|api[_-]?key|client[_-]?secret)\s*[:=]"),
    re.compile(r"(?i)\b(secret|password)\b\s*[:=]"),
)


class ReportingService:
    def __init__(self, db: AsyncSession, evidence_store: EvidenceStore | None = None) -> None:
        self._db = db
        if evidence_store is not None:
            self._evidence_store = evidence_store
            return
        try:
            self._evidence_store = EvidenceStore()
        except Exception:
            self._evidence_store = None

    async def assemble_report(self, scan_id: UUID) -> dict[str, Any]:
        scan_result = await self._db.execute(select(Scan.id).where(Scan.id == scan_id))
        if scan_result.scalar_one_or_none() is None:
            raise LookupError(f"Scan not found: {scan_id}")

        findings_result = await self._db.execute(
            select(Finding)
            .where(Finding.scan_id == scan_id)
            .options(
                selectinload(Finding.affected_endpoint),
                selectinload(Finding.proof_artifacts).selectinload(ProofArtifact.attack_probe),
                selectinload(Finding.proof_artifacts).selectinload(ProofArtifact.control_probe),
            )
        )
        findings = findings_result.scalars().all()

        report_findings: list[dict[str, Any]] = []
        for finding in findings:
            artifacts: list[dict[str, Any]] = []
            for artifact in finding.proof_artifacts:
                artifacts.append(self._artifact_payload(scan_id=scan_id, finding_id=finding.id, artifact=artifact))

            attack_path = self._build_attack_path(
                attack_class=finding.attack_class,
                endpoint_method=finding.affected_endpoint.method,
                endpoint_url=finding.affected_endpoint.url_pattern,
                artifacts=artifacts,
            )

            report_findings.append(
                {
                    "id": str(finding.id),
                    "title": finding.title,
                    "severity": self._severity_value(finding.severity),
                    "attack_class": finding.attack_class,
                    "description": finding.description,
                    "repro_steps": finding.repro_steps,
                    "fix_guidance": finding.fix_guidance,
                    "affected_endpoint": finding.affected_endpoint.url_pattern,
                    "proof_artifacts": artifacts,
                    "attack_path": attack_path,
                    "kill_chain": self._build_kill_chain(
                        attack_class=finding.attack_class,
                        endpoint_method=finding.affected_endpoint.method,
                        endpoint_url=finding.affected_endpoint.url_pattern,
                        finding_description=finding.description,
                        artifacts=artifacts,
                    ),
                    "attacker_impact": self._build_attacker_impact(
                        attack_class=finding.attack_class,
                        endpoint_method=finding.affected_endpoint.method,
                        endpoint_url=finding.affected_endpoint.url_pattern,
                        artifacts=artifacts,
                    ),
                    "score_explanation": self._score_explanation_for_artifacts(artifacts),
                }
            )

        return {
            "scan_id": str(scan_id),
            "generated_at": datetime.now(UTC).isoformat(),
            "findings": report_findings,
        }

    def render_markdown(self, report: dict[str, Any]) -> str:
        lines: list[str] = [f"# Scan Report: {report['scan_id']}", ""]
        findings = report.get("findings", [])

        for index, finding in enumerate(findings, start=1):
            lines.extend(
                [
                    f"## {index}. {finding.get('title', '')}",
                    f"- Severity: {finding.get('severity', '')}",
                    f"- Attack Class: {finding.get('attack_class', '')}",
                    f"- Affected Endpoint: {finding.get('affected_endpoint', '')}",
                    f"- Score Explanation: {finding.get('score_explanation', '')}",
                    "",
                    "### Description",
                    str(finding.get("description", "")),
                    "",
                    "### Reproduction Steps",
                    str(finding.get("repro_steps", "")),
                    "",
                    "### Fix Guidance",
                    str(finding.get("fix_guidance", "")),
                    "",
                    "### Attack Path",
                ]
            )

            attack_path = finding.get("attack_path", [])
            if not attack_path:
                lines.extend(["- No attack path available", ""])
            else:
                for path_step in attack_path:
                    lines.append(
                        f"- Step {path_step.get('step', '')}: "
                        f"{path_step.get('method', '')} {path_step.get('url', '')} "
                        f"({path_step.get('description', '')})"
                    )
                lines.append("")

            lines.append("### Kill Chain")
            kill_chain = finding.get("kill_chain", [])
            if not kill_chain:
                lines.extend(["- No kill chain available", ""])
            else:
                for step_index, kill_chain_step in enumerate(kill_chain, start=1):
                    lines.append(
                        f"{step_index}. [{kill_chain_step.get('phase', '')}] "
                        f"{kill_chain_step.get('description', '')} "
                        f"(endpoint: {kill_chain_step.get('endpoint', '')}, "
                        f"evidence: {kill_chain_step.get('evidence_ref', '')})"
                    )
                lines.append("")

            lines.append("### Proof Artifacts")

            proof_artifacts = finding.get("proof_artifacts", [])
            if not proof_artifacts:
                lines.extend(["- No proof artifacts available", ""])
                continue

            for artifact in proof_artifacts:
                lines.extend(
                    [
                        f"#### Artifact {artifact.get('artifact_id', '')}",
                        f"- Type: {artifact.get('proof_type', '')}",
                        f"- Confidence Score: {artifact.get('confidence_score', '')}",
                        f"- Summary: {artifact.get('summary', '')}",
                        f"- Evidence Notes: {artifact.get('evidence_notes', '')}",
                        "",
                        "##### Exact Request",
                        "```json",
                        json.dumps(artifact.get("request", {}), indent=2, ensure_ascii=False),
                        "```",
                        "",
                        "##### Exact Response",
                        "```json",
                        json.dumps(artifact.get("response", {}), indent=2, ensure_ascii=False),
                        "```",
                        "",
                    ]
                )

            lines.append("### Attacker Impact")
            attacker_impact = finding.get("attacker_impact", [])
            if not attacker_impact:
                lines.extend(["- No attacker impact expansion available", ""])
            else:
                for impact_item in attacker_impact:
                    lines.append(
                        f"- {impact_item.get('stage', '')}: {impact_item.get('description', '')} "
                        f"(confidence: {impact_item.get('confidence', '')})"
                    )
                lines.append("")

        return "\n".join(lines)

    def render_json(self, report: dict[str, Any]) -> str:
        return json.dumps(report, indent=2, ensure_ascii=False)

    async def export(self, scan_id: UUID, fmt: str = "json") -> str:
        report = await self.assemble_report(scan_id)
        redacted_report = self._redact_report(report)

        if fmt == "markdown":
            return self.render_markdown(redacted_report)
        if fmt == "json":
            return self.render_json(redacted_report)
        raise ValueError(f"Unsupported export format: {fmt}")

    def _artifact_payload(self, scan_id: UUID, finding_id: UUID, artifact: ProofArtifact) -> dict[str, Any]:
        evidence_payload = self._read_evidence_payload(scan_id=scan_id, finding_id=finding_id, artifact=artifact)
        if evidence_payload is not None:
            return evidence_payload

        attack_probe = artifact.attack_probe
        request_payload = attack_probe.request if attack_probe is not None else {}
        response_payload = attack_probe.response if attack_probe is not None else {}
        exploitability_v2: dict[str, float] | None = None
        score_explanation: str | None = None
        score_impact = getattr(artifact, "_score_impact", None)
        score_reachability = getattr(artifact, "_score_reachability", None)
        score_repeatability = getattr(artifact, "_score_repeatability", None)
        score_blast_radius = getattr(artifact, "_score_blast_radius", None)
        if all(component is not None for component in (score_impact, score_reachability, score_repeatability, score_blast_radius)):
            exploitability_v2 = {
                "impact": float(score_impact),
                "reachability": float(score_reachability),
                "repeatability": float(score_repeatability),
                "blast_radius": float(score_blast_radius),
            }
            score_explanation = compute_score_v2(
                confidence=float(artifact.confidence_score),
                impact=exploitability_v2["impact"],
                reachability=exploitability_v2["reachability"],
                repeatability=exploitability_v2["repeatability"],
                blast_radius=exploitability_v2["blast_radius"],
            ).explanation

        return {
            "artifact_id": str(artifact.id),
            "proof_type": artifact.proof_type,
            "confidence_score": artifact.confidence_score,
            "identity_role": artifact.identity_role,
            "summary": artifact.summary,
            "evidence_notes": artifact.evidence_notes,
            "score_explanation": score_explanation,
            "exploitability_v2": exploitability_v2,
            "request": request_payload,
            "response": response_payload,
        }

    def _read_evidence_payload(self, scan_id: UUID, finding_id: UUID, artifact: ProofArtifact) -> dict[str, Any] | None:
        if self._evidence_store is None:
            return None

        artifact_key = f"{scan_id}/{finding_id}/proof_{artifact.id}.json.gz"
        artifact_payload = self._read_gzip_json(artifact_key)
        if artifact_payload is None:
            return None

        attack_probe_key = f"{scan_id}/{finding_id}/{artifact.attack_probe_id}.json.gz"
        attack_probe_payload = self._read_gzip_json(attack_probe_key)
        if attack_probe_payload is None:
            return None

        return {
            "artifact_id": str(artifact_payload.get("artifact_id", artifact.id)),
            "proof_type": str(artifact_payload.get("proof_type", artifact.proof_type)),
            "confidence_score": artifact_payload.get("confidence_score", artifact.confidence_score),
            "identity_role": artifact_payload.get("identity_role", artifact.identity_role),
            "summary": str(artifact_payload.get("summary", artifact.summary)),
            "evidence_notes": str(artifact_payload.get("evidence_notes", artifact.evidence_notes)),
            "score_explanation": artifact_payload.get("score_explanation"),
            "exploitability_v2": artifact_payload.get("exploitability_v2"),
            "request": attack_probe_payload.get("request", {}),
            "response": attack_probe_payload.get("response", {}),
        }

    def _read_gzip_json(self, key: str) -> dict[str, Any] | None:
        if self._evidence_store is None:
            return None

        s3_client = getattr(self._evidence_store, "_s3", None)
        bucket_name = getattr(self._evidence_store, "_bucket_name", None)
        if s3_client is None or bucket_name is None:
            return None

        try:
            response = s3_client.get_object(Bucket=bucket_name, Key=key)
            body = response["Body"].read()
            return json.loads(gzip.decompress(body).decode("utf-8"))
        except (ClientError, BotoCoreError, OSError, json.JSONDecodeError):
            logger.debug("evidence_payload_unavailable", key=key)
            return None

    def _severity_value(self, severity: Severity | str) -> str:
        if isinstance(severity, Severity):
            return severity.value
        return str(severity)

    def _redact_report(self, report: dict[str, Any]) -> dict[str, Any]:
        redacted = copy.deepcopy(report)
        findings = redacted.get("findings")
        if isinstance(findings, list):
            for finding in findings:
                if not isinstance(finding, dict):
                    continue

                request_payload = finding.get("request")
                if isinstance(request_payload, dict):
                    finding["request"] = self._redact_evidence(request_payload)

                response_payload = finding.get("response")
                if isinstance(response_payload, dict):
                    finding["response"] = self._redact_evidence(response_payload)

                proof_artifacts = finding.get("proof_artifacts")
                if isinstance(proof_artifacts, list):
                    for artifact in proof_artifacts:
                        if not isinstance(artifact, dict):
                            continue
                        artifact_request = artifact.get("request")
                        if isinstance(artifact_request, dict):
                            artifact["request"] = self._redact_evidence(artifact_request)
                        artifact_response = artifact.get("response")
                        if isinstance(artifact_response, dict):
                            artifact["response"] = self._redact_evidence(artifact_response)

        return self._redact_value(redacted)

    def _redact_evidence(self, evidence: dict[str, Any]) -> dict[str, Any]:
        redacted = copy.deepcopy(evidence)
        request_headers = redacted.get("request_headers")
        if isinstance(request_headers, dict):
            redacted["request_headers"] = self._redact_request_headers(request_headers)

        headers = redacted.get("headers")
        if isinstance(headers, dict):
            redacted["headers"] = self._redact_request_headers(headers)

        return self._redact_value(redacted)

    def _redact_request_headers(self, headers: dict[str, Any]) -> dict[str, Any]:
        redacted_headers = copy.deepcopy(headers)
        for key in redacted_headers:
            normalized_key = str(key).lower()
            if any(sensitive_key in normalized_key for sensitive_key in _REQUEST_HEADER_SENSITIVE_KEYS):
                redacted_headers[key] = REDACTED
        return redacted_headers

    def _build_attack_path(
        self,
        attack_class: str,
        endpoint_method: str,
        endpoint_url: str,
        artifacts: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        for artifact in artifacts:
            evidence_notes = artifact.get("evidence_notes")
            if not isinstance(evidence_notes, str):
                continue
            parsed_chain = self._parse_chain_from_evidence_notes(evidence_notes)
            if parsed_chain:
                attack_path: list[dict[str, Any]] = []
                for index, chain_step in enumerate(parsed_chain, start=1):
                    attack_path.append(
                        {
                            "step": index,
                            "method": chain_step["method"],
                            "url": chain_step["url"],
                            "description": f"Derived from evidence chain for {attack_class}",
                        }
                    )
                return attack_path

        return [
            {
                "step": 1,
                "method": endpoint_method.upper(),
                "url": endpoint_url,
                "description": f"Primary affected endpoint for {attack_class}",
            }
        ]

    def _parse_chain_from_evidence_notes(self, evidence_notes: str) -> list[dict[str, str]]:
        chain_match = re.search(r"request_chain=(.+?)(?:,\s*\w+=|$)", evidence_notes, flags=re.IGNORECASE)
        if chain_match is None:
            return []

        chain_text = chain_match.group(1).strip()
        if not chain_text:
            return []

        parsed_steps: list[dict[str, str]] = []
        for raw_step in chain_text.split("->"):
            step_text = raw_step.strip()
            if not step_text:
                continue
            method, _, url = step_text.partition(" ")
            method_normalized = method.strip().upper()
            url_normalized = url.strip()
            if not method_normalized or not url_normalized:
                continue
            parsed_steps.append({"method": method_normalized, "url": url_normalized})
        return parsed_steps

    def _build_kill_chain(
        self,
        attack_class: str,
        endpoint_method: str,
        endpoint_url: str,
        finding_description: str,
        artifacts: list[dict[str, Any]],
    ) -> list[dict[str, str]]:
        if not artifacts:
            return []

        primary_artifact = self._primary_artifact(artifacts)
        if primary_artifact is None:
            return []

        attack_path = self._build_attack_path(
            attack_class=attack_class,
            endpoint_method=endpoint_method,
            endpoint_url=endpoint_url,
            artifacts=artifacts,
        )
        entry_endpoint = endpoint_url
        if attack_path:
            entry_endpoint = str(attack_path[0].get("url", endpoint_url))

        artifact_id = str(primary_artifact.get("artifact_id", ""))
        identity_role = str(primary_artifact.get("identity_role") or "unknown identity context")
        summary = str(primary_artifact.get("summary") or "")
        evidence_notes = str(primary_artifact.get("evidence_notes") or "")

        return [
            {
                "phase": "entry",
                "description": f"Recon identified reachable attack surface for {attack_class}.",
                "endpoint": entry_endpoint,
                "evidence_ref": artifact_id,
            },
            {
                "phase": "pivot",
                "description": f"Attack executed under auth context '{identity_role}'.",
                "endpoint": endpoint_url,
                "evidence_ref": artifact_id,
            },
            {
                "phase": "exploit",
                "description": summary or f"Exploit step validated for {attack_class}.",
                "endpoint": endpoint_url,
                "evidence_ref": artifact_id,
            },
            {
                "phase": "impact",
                "description": finding_description or evidence_notes or "Impact confirmed from validation evidence.",
                "endpoint": endpoint_url,
                "evidence_ref": artifact_id,
            },
        ]

    def _score_explanation_for_artifacts(self, artifacts: list[dict[str, Any]]) -> str:
        primary_artifact = self._primary_artifact(artifacts)
        if primary_artifact is None:
            return ""

        score_explanation = primary_artifact.get("score_explanation")
        if isinstance(score_explanation, str) and score_explanation:
            return score_explanation

        confidence_raw = primary_artifact.get("confidence_score")
        try:
            confidence = float(confidence_raw)
        except (TypeError, ValueError):
            return ""

        v2_payload = primary_artifact.get("exploitability_v2")
        if isinstance(v2_payload, dict):
            impact = v2_payload.get("impact")
            reachability = v2_payload.get("reachability")
            repeatability = v2_payload.get("repeatability")
            blast_radius = v2_payload.get("blast_radius")
            if all(component is not None for component in (impact, reachability, repeatability, blast_radius)):
                try:
                    from control_plane.finding_scorer import compute_score_v2
                    return compute_score_v2(
                        confidence=confidence,
                        impact=float(impact),
                        reachability=float(reachability),
                        repeatability=float(repeatability),
                        blast_radius=float(blast_radius),
                    ).explanation
                except (TypeError, ValueError):
                    pass

        return f"conf={confidence:.2f}"

    def _primary_artifact(self, artifacts: list[dict[str, Any]]) -> dict[str, Any] | None:
        scored_artifacts: list[tuple[float, dict[str, Any]]] = []
        for artifact in artifacts:
            confidence_raw = artifact.get("confidence_score")
            try:
                confidence = float(confidence_raw)
            except (TypeError, ValueError):
                confidence = -1.0
            scored_artifacts.append((confidence, artifact))
        if not scored_artifacts:
            return None
        scored_artifacts.sort(key=lambda item: item[0], reverse=True)
        return scored_artifacts[0][1]

    def _build_attacker_impact(
        self,
        *,
        attack_class: str,
        endpoint_method: str,
        endpoint_url: str,
        artifacts: list[dict[str, Any]],
    ) -> list[dict[str, str]]:
        if attack_class != "sensitive_exposure":
            return []

        notes = " ".join(str(artifact.get("evidence_notes") or "") for artifact in artifacts)
        evidence_text = " ".join(
            json.dumps(artifact.get(key, {}), ensure_ascii=False, default=str)
            for artifact in artifacts
            for key in ("request", "response")
        )
        combined = f"{notes}\n{evidence_text}".lower()
        unauthenticated = "request_has_auth=false" in combined

        impacts: list[dict[str, str]] = [
            {
                "stage": "exposure",
                "description": (
                    f"{endpoint_method.upper()} {endpoint_url} returned sensitive-looking material "
                    f"{'without authentication' if unauthenticated else 'inside an authenticated response'}."
                ),
                "confidence": "high" if unauthenticated else "medium",
            }
        ]

        if "devtools://" in combined or "__nextjs_attach-nodejs-inspector" in combined or "127.0.0.1:9229" in combined:
            impacts.append(
                {
                    "stage": "pivot",
                    "description": (
                        "The response exposes a Next.js/Node inspector attachment signal. "
                        "A real attacker would next check whether any debug transport is reachable from their network "
                        "and whether it exposes runtime inspection or source/context data."
                    ),
                    "confidence": "high",
                }
            )

        if "matches=token" in combined or "bearer" in combined or "session" in combined:
            impacts.append(
                {
                    "stage": "credential replay",
                    "description": (
                        "Token-like material was detected. The next proof step is a constrained replay check against "
                        "an in-scope low-risk endpoint to determine whether the token is valid, scoped, and expired."
                    ),
                    "confidence": "medium",
                }
            )

        if "matches=credential" in combined or "api_key" in combined or "secret" in combined or "password" in combined:
            impacts.append(
                {
                    "stage": "secret use",
                    "description": (
                        "Credential-like material was detected. A real attacker would classify the secret type, infer "
                        "its service boundary, then try read-only access first; defenders should rotate it and review logs."
                    ),
                    "confidence": "medium",
                }
            )

        if "matches=pii" in combined or "email" in combined:
            impacts.append(
                {
                    "stage": "data abuse",
                    "description": (
                        "PII-like material was detected. Practical impact includes account targeting, phishing context, "
                        "and privacy exposure, even when no direct account takeover is proven."
                    ),
                    "confidence": "medium",
                }
            )

        impacts.append(
            {
                "stage": "next safe probe",
                "description": (
                    "Recommended follow-up: run an in-scope, read-only validation probe that proves reachability or "
                    "scope of the exposed material without mutating data or reusing credentials destructively."
                ),
                "confidence": "advisory",
            }
        )
        return impacts

    def _redact_value(self, value: Any) -> Any:
        if isinstance(value, dict):
            output: dict[str, Any] = {}
            for key, item in value.items():
                if _SENSITIVE_KEY_PATTERN.search(key):
                    output[key] = REDACTED
                else:
                    output[key] = self._redact_value(item)
            return output
        if isinstance(value, list):
            return [self._redact_value(item) for item in value]
        if isinstance(value, str):
            for pattern in _SENSITIVE_VALUE_PATTERNS:
                if pattern.search(value):
                    return REDACTED
        return value
