from __future__ import annotations

import copy
import gzip
import json
import os
import re
import uuid as _uuid_mod
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

import structlog
from botocore.exceptions import BotoCoreError, ClientError
from sqlalchemy import distinct, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from api.models.responses import AttackChain, AttackChainReportResponse, AttackChainScoreFactors, AttackChainStep
from control_plane.attack_chain_builder import (
    ChainConfidenceResult,
    adjust_chain_severity,
    build_remediation,
    compute_chain_confidence,
    compute_chain_score,
)
from storage.db.models import AuditEvent, AuditEventType, AttackTask, Finding, ProofArtifact, RawProbe, Scan, Severity
from storage.evidence.store import EvidenceStore

logger = structlog.get_logger(__name__)

REDACTED = "[REDACTED]"
_SENSITIVE_KEY_PATTERN = re.compile(r"authorization|cookie|password|token|secret", re.IGNORECASE)
_REQUEST_HEADER_SENSITIVE_KEYS: tuple[str, ...] = ("authorization", "cookie", "password", "token", "x-api-key")
_SAFE_SECRET_METADATA_KEYS: tuple[str, ...] = ("secret_blast_radius", "secret_blast_radius_matrix")
_SAFE_IDENTITY_KEYS: frozenset[str] = frozenset({"name", "role_hint", "tenant_hint", "identity_labels"})
_IDENTITY_CREDENTIAL_KEYS: frozenset[str] = frozenset(
    {"credentials", "cookies", "bearer_token", "password", "token", "secret", "auth_headers"}
)
_SENSITIVE_VALUE_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(?i)\bbearer\s+[a-z0-9\-\._~\+/]+=*"),
    re.compile(r"(?i)\beyJ[a-z0-9\-_]+\.[a-z0-9\-_]+(?:\.[a-z0-9\-_]+)?"),
    re.compile(r"(?i)(access[_-]?token|refresh[_-]?token|session[_-]?token|api[_-]?key|client[_-]?secret)\s*[:=]"),
    re.compile(r"(?i)\b(secret|password)\b\s*[:=]"),
)
LEAK_SOURCE_GUIDANCE: dict[str, str] = {
    "debug_endpoint": "Disable or restrict access to debug endpoints in production. Remove the route or add authentication.",
    "config_json": "Remove secrets from configuration files served over HTTP. Use environment variables or a secret manager.",
    "source_map": "Disable source map generation in production builds or restrict access to .map files.",
    "stack_trace": "Suppress stack traces in HTTP error responses. Configure the error handler to return generic messages.",
    "response_header": "Audit response headers. Remove headers that expose credentials or tokens.",
    "public_asset": "Audit publicly accessible static assets. Remove or protect files that contain secrets.",
    "response_body": "Sanitize API responses. Ensure secrets are not included in response payloads.",
    "unknown": "Review the endpoint response to identify and remove exposed secrets.",
}
BUSINESS_IMPACT_DESCRIPTIONS: dict[str, str] = {
    "coupon_stacking": "Attacker can apply multiple discount codes to a single order, reducing revenue per transaction.",
    "negative_quantity": "Attacker can manipulate cart totals to negative values, potentially receiving refunds or credits without valid purchases.",
    "price_tampering": "Attacker can modify item prices at checkout, purchasing goods below cost or for free.",
    "inventory_reservation_abuse": "Attacker can indefinitely hold inventory without purchasing, causing denial of stock to legitimate buyers.",
    "approval_bypass": "Attacker can skip required approval steps in workflows, executing unauthorized state transitions.",
    "double_spend": "Attacker can spend the same balance or coupon multiple times via concurrent requests.",
    "bfla": "Attacker can perform administrative or privileged actions without proper authorization.",
    "bola": "Attacker can access or modify other users data by manipulating object identifiers.",
    "privilege_escalation": "Attacker can gain higher privilege level than intended, accessing restricted functionality.",
}
_UNTESTED_CLASS_DESCRIPTIONS: dict[str, str] = {
    "bola": "Tests object-level access control. Requires authenticated user to manipulate another user IDs.",
    "idor": "Tests object-level access control. Requires authenticated user to manipulate another user IDs.",
    "tenant_isolation": "Tests cross-tenant data isolation. Requires two separate authenticated tenant sessions.",
    "privilege_escalation": "Tests vertical privilege abuse. Requires low-privilege auth session + admin target endpoints.",
    "auth_bypass": "Tests authentication bypass. Requires valid session baseline to compare against.",
    "mass_assignment": "Tests field injection on write endpoints. Requires auth to reach protected write APIs.",
    "csrf": "Tests state-changing requests without tokens. Requires authenticated session context.",
    "jwt_attack": "Tests JWT manipulation. Requires JWT token in session (or from JS/HAR leak).",
    "oauth": "Tests OAuth flow manipulation. Requires active OAuth session.",
    "session_misuse": "Tests session fixation/hijacking. Requires active session.",
    "business_logic_advanced": "Tests advanced business logic. Requires auth to reach business endpoints.",
}
_DEFAULT_UNTESTED_REASON = "Requires authenticated session. Re-run with credentials for full coverage."
_RACE_TIMELINE_CLASSES: frozenset[str] = frozenset(
    {"double_spend", "limit_override_race", "inventory_reservation_abuse", "idempotency_bypass"}
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
        scan_result = await self._db.execute(select(Scan).where(Scan.id == scan_id).options(selectinload(Scan.target)))
        scan = scan_result.scalar_one_or_none()
        if scan is None:
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

        actions_performed = await self._actions_performed(scan_id)
        skipped_blocked = await self._skipped_blocked(scan_id)
        report_findings: list[dict[str, Any]] = []
        for finding in findings:
            metadata = copy.deepcopy(finding.extra_metadata) if isinstance(finding.extra_metadata, dict) else {}
            severity = self._severity_value(finding.severity)
            artifacts: list[dict[str, Any]] = []
            for artifact in finding.proof_artifacts:
                artifacts.append(self._artifact_payload(scan_id=scan_id, finding_id=finding.id, artifact=artifact))

            attack_path = self._build_attack_path(
                attack_class=finding.attack_class,
                endpoint_method=finding.affected_endpoint.method,
                endpoint_url=finding.affected_endpoint.url_pattern,
                artifacts=artifacts,
            )

            report_finding = {
                "id": str(finding.id),
                "title": finding.title,
                "severity": severity,
                "severity_factors": self._severity_factors_from_metadata(metadata),
                "remediation_priority": self._remediation_priority(severity, metadata),
                "attack_class": finding.attack_class,
                "description": finding.description,
                "business_impact": BUSINESS_IMPACT_DESCRIPTIONS.get(
                    finding.attack_class,
                    "Unauthorized access or manipulation of application resources.",
                ),
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
                "secret_blast_radius": self._build_secret_blast_radius_payload(
                    self._extract_secret_blast_radius_matrix_from_metadata(metadata)
                ),
                "audit_event_ids": await self._audit_event_ids_for_finding(scan_id=scan_id, finding_id=finding.id),
                "score_explanation": self._score_explanation_for_artifacts(artifacts),
                "metadata": metadata,
            }
            identity_context = self._identity_context_from_artifacts(artifacts)
            if identity_context:
                report_finding["identity_context"] = identity_context
            report_findings.append(report_finding)

        return {
            "scan_id": str(scan_id),
            "generated_at": datetime.now(UTC).isoformat(),
            "scan_config": scan.target.config if scan.target is not None else {},
            "actions_performed": actions_performed,
            "skipped_blocked": skipped_blocked,
            "findings": report_findings,
        }

    async def _actions_performed(self, scan_id: UUID) -> dict[str, Any]:
        empty = {
            "total_requests_sent": 0,
            "requests_by_attack_class": {},
            "tasks_dispatched": 0,
            "tasks_with_findings": 0,
        }
        try:
            total_requests_result = await self._db.execute(
                select(func.count(RawProbe.id)).join(AttackTask).where(AttackTask.scan_id == scan_id)
            )
            tasks_dispatched_result = await self._db.execute(
                select(func.count(AttackTask.id)).where(AttackTask.scan_id == scan_id)
            )
            by_class_result = await self._db.execute(
                select(AttackTask.attack_class, func.count(RawProbe.id))
                .join(RawProbe, RawProbe.attack_task_id == AttackTask.id)
                .where(AttackTask.scan_id == scan_id)
                .group_by(AttackTask.attack_class)
            )
            tasks_with_findings_result = await self._db.execute(
                select(func.count(distinct(ProofArtifact.attack_task_id)))
                .join(AttackTask, AttackTask.id == ProofArtifact.attack_task_id)
                .where(AttackTask.scan_id == scan_id, ProofArtifact.finding_id.is_not(None))
            )
        except Exception:
            return empty

        return {
            "total_requests_sent": int(total_requests_result.scalar_one() or 0),
            "requests_by_attack_class": {
                str(attack_class): int(count or 0) for attack_class, count in by_class_result.all()
            },
            "tasks_dispatched": int(tasks_dispatched_result.scalar_one() or 0),
            "tasks_with_findings": int(tasks_with_findings_result.scalar_one() or 0),
        }

    async def _skipped_blocked(self, scan_id: UUID) -> dict[str, Any]:
        skipped_details: list[dict[str, str]] = []
        redis_url = os.getenv("REDIS_URL")
        if not redis_url:
            return {"tasks_skipped": 0, "skipped_details": skipped_details}

        try:
            from redis.asyncio import Redis as AsyncRedis

            redis_client = AsyncRedis.from_url(redis_url, decode_responses=True)
            try:
                raw_records = await redis_client.lrange(f"skipped_tasks:{scan_id}", 0, -1)
            finally:
                await redis_client.aclose()
        except Exception:
            return {"tasks_skipped": 0, "skipped_details": skipped_details}

        for raw_record in raw_records:
            try:
                parsed = json.loads(raw_record)
            except (TypeError, ValueError, json.JSONDecodeError):
                continue
            if not isinstance(parsed, dict):
                continue
            skipped_details.append(
                {
                    "task_id": str(parsed.get("task_id", "")),
                    "reason": str(parsed.get("reason", "")),
                    "attack_class": str(parsed.get("attack_class", "")),
                }
            )
        return {"tasks_skipped": len(skipped_details), "skipped_details": skipped_details}

    async def _audit_event_ids_for_finding(self, *, scan_id: UUID, finding_id: UUID) -> list[str]:
        try:
            result = await self._db.execute(
                select(AuditEvent.id).where(
                    AuditEvent.scan_id == scan_id,
                    AuditEvent.event_type.in_(
                        [AuditEventType.TASK_DISPATCHED, AuditEventType.FINDING_RECORDED]
                    ),
                    AuditEvent.details["finding_id"].as_string() == str(finding_id),
                )
            )
        except Exception:
            return []
        return [str(event_id) for event_id in result.scalars().all()]

    async def assemble_chain_report(self, scan_id: UUID) -> dict[str, Any]:
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

        grouped_findings: dict[str, list[Finding]] = {}
        for finding in findings:
            group_key = str(finding.attack_class)
            metadata_raw = getattr(finding, "extra_metadata", None)
            if isinstance(metadata_raw, dict):
                race_group_id = metadata_raw.get("_race_group_id") or metadata_raw.get("race_group_id")
                if isinstance(race_group_id, str) and race_group_id.strip():
                    group_key = f"{group_key}:{race_group_id.strip()}"
            grouped_findings.setdefault(group_key, []).append(finding)

        chains: list[AttackChain] = []
        for attack_class, group in grouped_findings.items():
            if not group:
                continue

            steps: list[AttackChainStep] = []
            step_confidences: list[tuple[str, float]] = []
            identity_set: set[str] = set()

            for index, finding in enumerate(group):
                phase = "entry" if index == 0 else "exploit"
                metadata_raw = getattr(finding, "extra_metadata", None)
                if not isinstance(metadata_raw, dict):
                    metadata_raw = getattr(finding, "metadata", None)

                confidence_raw: Any = 0.9
                if isinstance(metadata_raw, dict):
                    confidence_raw = metadata_raw.get("proof_confidence", 0.9)
                    identity_ids = metadata_raw.get("identity_ids", [])
                    if isinstance(identity_ids, list):
                        for identity_id in identity_ids:
                            if identity_id is None:
                                continue
                            identity_set.add(str(identity_id))

                artifacts = [
                    self._artifact_payload(scan_id=scan_id, finding_id=finding.id, artifact=artifact)
                    for artifact in finding.proof_artifacts
                ]
                identity_context = self._identity_context_from_artifacts(artifacts)
                if identity_context is not None:
                    for identity_label in identity_context["identities_used"]:
                        identity_set.add(identity_label)

                try:
                    confidence = float(confidence_raw)
                except (TypeError, ValueError):
                    confidence = 0.9
                confidence = min(max(confidence, 0.0), 1.0)

                endpoint = str(getattr(finding.affected_endpoint, "url_pattern", finding.affected_endpoint))
                step = AttackChainStep(
                    phase=phase,
                    description=finding.title,
                    endpoint=endpoint,
                    evidence_ref=str(finding.id),
                    confidence=confidence,
                )
                steps.append(step)
                step_confidences.append((step.phase, confidence))

            chain_identities = sorted(identity_set)
            chain_conf_result: ChainConfidenceResult = compute_chain_confidence(
                step_confidences=step_confidences,
                has_differential=False,
                has_reproducible=True,
            )

            base_severity = (
                group[0].severity.value if isinstance(group[0].severity, Severity) else str(group[0].severity)
            )
            severity_adjustment = adjust_chain_severity(
                base_severity=base_severity.lower(),
                chain_confidence=chain_conf_result.chain_confidence,
                has_impact_evidence=len(group) > 1,
                step_count=len(group),
            )

            score_result = compute_chain_score(
                impact=0.8,
                reachability=0.7,
                privilege=0.6,
                repeatability=0.8,
                blast_radius=0.5,
                safety_confidence=chain_conf_result.chain_confidence,
            )
            score_factors = AttackChainScoreFactors(**score_result)

            root_endpoint = str(getattr(group[0].affected_endpoint, "url_pattern", group[0].affected_endpoint))
            remediation = build_remediation(
                attack_class=attack_class,
                root_cause_endpoint=root_endpoint,
                step_count=len(group),
                identities=chain_identities,
            )

            chains.append(
                AttackChain(
                    id=str(_uuid_mod.uuid4()),
                    root_cause_id=f"{attack_class}_{str(scan_id)[:8]}",
                    steps=steps,
                    identities=chain_identities,
                    evidence_refs=[str(finding.id) for finding in group],
                    chain_confidence=chain_conf_result.chain_confidence,
                    severity=severity_adjustment.adjusted,
                    severity_explanation=severity_adjustment.explanation,
                    score_factors=score_factors,
                    remediation=remediation,
                )
            )

        _existing_report = await self.assemble_report(scan_id)
        _ = _existing_report.get("findings", [])

        return {
            "scan_id": str(scan_id),
            "chains": [chain.model_dump() for chain in chains],
            "findings": [],
            "generated_at": datetime.now(UTC).isoformat(),
        }

    def render_markdown(self, report: dict[str, Any]) -> str:
        lines: list[str] = [f"# Scan Report: {report['scan_id']}", ""]
        scan_config_raw = report.get("scan_config")
        scan_config = scan_config_raw if isinstance(scan_config_raw, dict) else {}
        unauth_mode = bool(scan_config.get("unauth_mode", False))
        active_rules: list[str] = []
        skipped_rules: list[str] = []
        all_rules: list[str] = []
        if unauth_mode:
            all_rules = self._normalize_rule_list(scan_config.get("all_rules"))
            active_rules = self._normalize_rule_list(scan_config.get("active_rules"))
            skipped_rules = self._normalize_rule_list(scan_config.get("skipped_rules"))
            if not all_rules or not active_rules:
                planner_all_rules, planner_active_rules, planner_skipped_rules = self._resolve_unauth_rule_sets()
                if not all_rules:
                    all_rules = planner_all_rules
                if not active_rules:
                    active_rules = planner_active_rules
                if not skipped_rules:
                    skipped_rules = planner_skipped_rules
            if skipped_rules:
                lines.extend([self.generate_untested_classes_section(scan_config=scan_config, skipped_rules=skipped_rules), ""])
        findings = report.get("findings", [])

        for index, finding in enumerate(findings, start=1):
            leak_source_section = ""
            metadata = finding.get("metadata")
            if isinstance(metadata, dict):
                leak_source_section = self._format_leak_source_section(metadata)
            severity = str(finding.get("severity", ""))
            severity_factors = self._severity_factors_for_finding(finding)
            lines.extend(
                [
                    f"## {index}. {finding.get('title', '')}",
                    f"- Severity: {severity}",
                ]
            )
            if finding.get("attack_class") == "sensitive_exposure":
                summary = self._build_executive_summary(finding)
                if unauth_mode:
                    coverage = self.calculate_unauth_coverage(all_rules=all_rules, active_rules=active_rules)
                    summary = (
                        f"{summary} Unauth coverage: {coverage:.0f}% of attack classes tested without credentials."
                    ).strip()
                lines.extend(
                    [
                        "### Executive Summary",
                        "",
                        summary,
                        "",
                        "#### Attack Narrative",
                        "",
                        self._build_attack_narrative(finding),
                        "",
                    ]
                )
            if severity_factors:
                lines.extend(
                    [
                        f"**Why Severity Is {severity}:**",
                        *[
                            f"- {factor['description']} "
                            f"(source: {factor['source']}, confidence: {factor['confidence']:.0%})"
                            for factor in severity_factors
                        ],
                    ]
                )
            lines.extend(
                [
                    f"- Remediation Priority: {self._remediation_priority(severity, metadata)}",
                    f"- Attack Class: {finding.get('attack_class', '')}",
                    f"- Affected Endpoint: {finding.get('affected_endpoint', '')}",
                    f"- Score Explanation: {finding.get('score_explanation', '')}",
                    "",
                    "### Description",
                    str(finding.get("description", "")),
                    "",
                    "## Business Impact",
                    str(
                        finding.get(
                            "business_impact",
                            "Unauthorized access or manipulation of application resources.",
                        )
                    ),
                    "",
                    "### Reproduction Steps",
                    str(finding.get("repro_steps", "")),
                    "",
                    "### Fix Guidance",
                    str(finding.get("fix_guidance", "")),
                ]
            )
            race_timeline_section = self._build_race_timeline(finding)
            if race_timeline_section:
                lines.extend(["", race_timeline_section])
            if leak_source_section:
                lines.extend(["", leak_source_section])
            lines.extend(["", "### Attack Path"])

            secret_metadata = self._parse_secret_metadata(str(finding.get("evidence_notes", "")))
            if secret_metadata is not None:
                lines.extend(
                    [
                        "### Secret Properties",
                        f"- Type: {secret_metadata.get('secret_type', '')}",
                        f"- Fingerprint: `{secret_metadata.get('secret_fingerprint', '')}` (dedup hash, not the secret value)",
                        f"- TTL Bucket: {secret_metadata.get('ttl_bucket', '')}",
                        "",
                        "### Expiration and Revocation",
                        f"- Lifecycle Guidance: {self._lifecycle_guidance(secret_metadata)}",
                        "",
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
            else:
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

            secret_blast_radius = self._secret_blast_radius_for_finding(finding)
            if secret_blast_radius is not None:
                lines.extend(
                    [
                        "### Secret Blast Radius",
                        "| Endpoint | Method | Status | Content-Type | Response Size | Auth Accepted |",
                        "|---|---|---|---|---|---|",
                    ]
                )
                for entry in secret_blast_radius["matrix"]:
                    endpoint_raw = entry.get("endpoint")
                    endpoint_text = "-" if endpoint_raw is None else self._truncate_markdown_cell(str(endpoint_raw), limit=80)
                    method_text = "-" if entry.get("method") is None else str(entry["method"])
                    status_text = "-" if entry.get("status") is None else str(entry["status"])
                    content_type_text = "-" if entry.get("content_type") is None else str(entry["content_type"])
                    response_size_text = "-" if entry.get("response_size") is None else str(entry["response_size"])
                    auth_text = "YES" if entry.get("auth_accepted") else "NO"
                    lines.append(
                        f"| {endpoint_text} | {method_text} | {status_text} | {content_type_text} | {response_size_text} | {auth_text} |"
                    )
                lines.append("")

            privilege_fp: dict[str, Any] | None = None
            metadata = finding.get("metadata")
            if isinstance(metadata, dict):
                privilege_fp_entry = metadata.get("privilege_fingerprint")
                if isinstance(privilege_fp_entry, dict):
                    privilege_fp = privilege_fp_entry
            if privilege_fp:
                lines.append("### Privilege Fingerprint")
                lines.append("- **Observed access level:** " + str(privilege_fp.get("observed_access_level", "unknown")))
                lines.append("- **Inferred level (JWT hints):** " + str(privilege_fp.get("inferred_level", "unknown")))
                confidence_val_raw = privilege_fp.get("confidence", 0.0)
                try:
                    confidence_val = float(confidence_val_raw)
                except (TypeError, ValueError):
                    confidence_val = 0.0
                lines.append(f"- **Confidence:** {confidence_val:.2f}")
                evidence_eps_raw = privilege_fp.get("evidence_endpoints", [])
                evidence_eps: list[str] = []
                if isinstance(evidence_eps_raw, list):
                    evidence_eps = [str(endpoint) for endpoint in evidence_eps_raw if endpoint is not None]
                if evidence_eps:
                    lines.append("- **Evidence endpoints:** " + ", ".join(evidence_eps))
                else:
                    lines.append("- **Evidence endpoints:** none observed")
                lines.append("")
                lines.append("#### Remediation")
                level = str(privilege_fp.get("observed_access_level", "unknown"))
                if level in ("admin", "service"):
                    lines.append(
                        "**Critical:** Secret grants admin/service-level access. Rotate immediately and audit all usage in the last 90 days."
                    )
                elif level == "elevated_user":
                    lines.append(
                        "**High:** Secret grants elevated access beyond standard user scope. Rotate and review granted permissions."
                    )
                else:
                    lines.append(
                        "**Standard:** Rotate the secret and review whether the access scope matches the principle of least privilege."
                    )
                lines.append("")

            if finding.get("attack_class") == "sensitive_exposure":
                lines.extend(
                    [
                        "",
                        self._build_remediation_plan_section(finding),
                        "",
                    ]
                )

        return "\n".join(lines)

    def render_json(self, report: dict[str, Any]) -> str:
        output = copy.deepcopy(report)
        findings = output.get("findings")
        if isinstance(findings, list):
            for finding in findings:
                if not isinstance(finding, dict):
                    continue
                finding["secret_blast_radius"] = self._secret_blast_radius_for_finding(finding)
                privilege_fp_entry: Any = None
                metadata = finding.get("metadata")
                if isinstance(metadata, dict):
                    privilege_fp_entry = metadata.get("privilege_fingerprint")
                severity = str(finding.get("severity", ""))
                finding["severity_factors"] = self._severity_factors_for_finding(finding)
                finding["remediation_priority"] = self._remediation_priority(severity, metadata)
                finding["leak_source"] = metadata.get("leak_source") if isinstance(metadata, dict) else None
                finding["privilege_fingerprint"] = privilege_fp_entry
                if str(finding.get("attack_class", "")) == "sensitive_exposure":
                    evidence_notes = str(finding.get("evidence_notes", ""))
                    if not evidence_notes:
                        proof_artifacts = finding.get("proof_artifacts")
                        if isinstance(proof_artifacts, list):
                            primary_artifact = self._primary_artifact(
                                [artifact for artifact in proof_artifacts if isinstance(artifact, dict)]
                            )
                            if primary_artifact is not None:
                                evidence_notes = str(primary_artifact.get("evidence_notes", ""))
                    secret_metadata = self._parse_secret_metadata(evidence_notes)
                    if secret_metadata is not None:
                        finding["lifecycle"] = {
                            "ttl_bucket": secret_metadata.get("ttl_bucket", ""),
                            "active_during_scan": secret_metadata.get("active_during_scan", "false") == "true",
                            "guidance": self._lifecycle_guidance(secret_metadata),
                        }
                finding["secret_exposure_evidence_pack"] = self._build_secret_exposure_evidence_pack(finding)
        return json.dumps(output, indent=2, ensure_ascii=False)

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

    def _identity_context_from_artifacts(self, artifacts: list[dict[str, Any]]) -> dict[str, list[str]] | None:
        identities_used: list[str] = []
        seen: set[str] = set()
        for artifact in artifacts:
            for identity_data in self._identity_data_candidates(artifact):
                redacted_identity = self._redact_identity_info(identity_data)
                labels = redacted_identity.get("identity_labels")
                if not isinstance(labels, list):
                    continue
                for label in labels:
                    if not isinstance(label, str):
                        continue
                    label_text = label.strip()
                    if not label_text or label_text in seen:
                        continue
                    seen.add(label_text)
                    identities_used.append(label_text)

        if not identities_used:
            return None
        return {"identities_used": identities_used}

    def _identity_data_candidates(self, artifact: dict[str, Any]) -> list[dict[str, Any]]:
        candidates: list[dict[str, Any]] = [artifact]
        for key in ("identity_context", "identity_info", "identity"):
            value = artifact.get(key)
            if isinstance(value, dict):
                candidates.append(value)
        return candidates

    def _redact_identity_info(self, identity_data: dict[str, Any]) -> dict[str, Any]:
        redacted: dict[str, Any] = {}
        for key, value in identity_data.items():
            key_text = str(key)
            normalized_key = key_text.lower()
            if normalized_key in _IDENTITY_CREDENTIAL_KEYS:
                continue
            if normalized_key not in _SAFE_IDENTITY_KEYS:
                continue
            redacted[normalized_key] = copy.deepcopy(value)
        return redacted

    def _severity_value(self, severity: Severity | str) -> str:
        if isinstance(severity, Severity):
            return severity.value
        return str(severity)

    def _severity_factors_for_finding(self, finding: dict[str, Any]) -> list[dict[str, Any]]:
        factors = finding.get("severity_factors")
        if isinstance(factors, list):
            normalized = self._normalize_severity_factors(factors)
            if normalized:
                return normalized
        return self._severity_factors_from_metadata(finding.get("metadata"))

    def _severity_factors_from_metadata(self, metadata: Any) -> list[dict[str, Any]]:
        if not isinstance(metadata, dict):
            return []
        return self._normalize_severity_factors(metadata.get("severity_factors"))

    def _normalize_severity_factors(self, factors: Any) -> list[dict[str, Any]]:
        if not isinstance(factors, list):
            return []

        normalized: list[dict[str, Any]] = []
        for factor in factors:
            if not isinstance(factor, dict):
                continue
            confidence = 0.0
            try:
                confidence = float(factor.get("confidence", 0.0))
            except (TypeError, ValueError):
                confidence = 0.0
            normalized.append(
                {
                    "source": str(factor.get("source", "")),
                    "confidence": confidence,
                    "description": str(factor.get("description", "")),
                }
            )
        return normalized

    def _remediation_priority(self, severity: str, metadata: Any) -> str:
        normalized_severity = severity.strip().lower()
        metadata_dict = metadata if isinstance(metadata, dict) else {}
        if normalized_severity == "critical" and metadata_dict.get("active_replay"):
            return "Priority 1: Rotate immediately"

        blast_radius_score = 0.0
        try:
            blast_radius_score = float(metadata_dict.get("blast_radius_score", 0.0))
        except (TypeError, ValueError):
            blast_radius_score = 0.0
        if normalized_severity == "high" and blast_radius_score >= 0.7:
            return "Priority 2: Rotate within 24h"

        return "Priority 3: Rotate in next maintenance window"

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

    def _parse_secret_metadata(self, evidence_notes: str) -> dict[str, str] | None:
        parsed: dict[str, str] = {}
        for key, value in re.findall(r"([A-Za-z_][A-Za-z0-9_]*)=([^;,\n]+)", evidence_notes):
            parsed[key.strip()] = value.strip()
        if "secret_type" not in parsed:
            return None
        return parsed

    def _lifecycle_guidance(self, secret_metadata: dict[str, str]) -> str:
        if secret_metadata.get("active_during_scan") == "true":
            return "Immediately rotate or revoke — confirmed active during scan."
        ttl_bucket = secret_metadata.get("ttl_bucket", "")
        if ttl_bucket == "expired":
            return "Secret appears expired. Confirm revocation is complete and purge from all consumers."
        if ttl_bucket == "long":
            return "Secret is long-lived. Reduce TTL, bind audience (aud claim), and narrow scope."
        if ttl_bucket in ("unknown", ""):
            return "No expiry detected. Add expiration, bind audience, and restrict scope."
        if ttl_bucket == "short":
            return "TTL is short. Ensure automated rotation is in place."
        return "Rotate this secret and review access logs."

    def _format_leak_source_section(self, metadata: dict[str, Any]) -> str:
        leak_source = metadata.get("leak_source")
        if not isinstance(leak_source, dict):
            return ""
        source_type = str(leak_source.get("type") or "unknown")
        confidence_raw = leak_source.get("confidence")
        confidence = 0.0
        try:
            confidence = float(confidence_raw)
        except (TypeError, ValueError):
            confidence = 0.0
        guidance = LEAK_SOURCE_GUIDANCE.get(source_type, LEAK_SOURCE_GUIDANCE["unknown"])
        return f"**Leak Source:** {source_type} (confidence: {confidence:.0%})\n**Remediation:** {guidance}"

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
                if key in _SAFE_SECRET_METADATA_KEYS:
                    output[key] = self._redact_value(item)
                elif _SENSITIVE_KEY_PATTERN.search(key):
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

    def _extract_secret_blast_radius_matrix_from_metadata(self, metadata: Any) -> list[dict[str, Any]]:
        if not isinstance(metadata, dict):
            return []
        matrix = metadata.get("secret_blast_radius_matrix")
        if not isinstance(matrix, list):
            return []

        normalized_matrix: list[dict[str, Any]] = []
        for raw_entry in matrix:
            if not isinstance(raw_entry, dict):
                continue
            endpoint_raw = raw_entry.get("url_pattern")
            if endpoint_raw is None:
                endpoint_raw = raw_entry.get("endpoint")
            method_raw = raw_entry.get("method")
            status_raw = raw_entry.get("status")
            content_type_raw = raw_entry.get("content_type")
            response_size_raw = raw_entry.get("response_size")
            auth_accepted_raw = raw_entry.get("auth_accepted")

            status_value: int | None = None
            if isinstance(status_raw, int):
                status_value = status_raw
            else:
                try:
                    status_value = int(status_raw) if status_raw is not None else None
                except (TypeError, ValueError):
                    status_value = None

            response_size_value: int | None = None
            if isinstance(response_size_raw, int):
                response_size_value = response_size_raw
            else:
                try:
                    response_size_value = int(response_size_raw) if response_size_raw is not None else None
                except (TypeError, ValueError):
                    response_size_value = None

            auth_accepted_value = False
            if isinstance(auth_accepted_raw, bool):
                auth_accepted_value = auth_accepted_raw
            elif isinstance(auth_accepted_raw, (int, float)):
                auth_accepted_value = auth_accepted_raw != 0
            elif isinstance(auth_accepted_raw, str):
                auth_accepted_value = auth_accepted_raw.strip().lower() in {"1", "true", "yes", "y"}

            normalized_matrix.append(
                {
                    "endpoint": str(endpoint_raw) if endpoint_raw is not None else None,
                    "method": str(method_raw) if method_raw is not None else None,
                    "status": status_value,
                    "content_type": str(content_type_raw) if content_type_raw is not None else None,
                    "response_size": response_size_value,
                    "auth_accepted": auth_accepted_value,
                }
            )

        return normalized_matrix

    def _secret_blast_radius_for_finding(self, finding: dict[str, Any]) -> dict[str, Any] | None:
        secret_blast_radius = finding.get("secret_blast_radius")
        if isinstance(secret_blast_radius, dict):
            matrix_raw = secret_blast_radius.get("matrix")
            if isinstance(matrix_raw, list):
                matrix = self._extract_secret_blast_radius_matrix_from_metadata(
                    {"secret_blast_radius_matrix": matrix_raw}
                )
                if matrix:
                    return self._build_secret_blast_radius_payload(matrix)

        matrix = self._extract_secret_blast_radius_matrix_from_metadata(finding.get("metadata"))
        if matrix:
            return self._build_secret_blast_radius_payload(matrix)

        matrix = self._extract_secret_blast_radius_matrix_from_metadata(
            {"secret_blast_radius_matrix": finding.get("secret_blast_radius_matrix")}
        )
        return self._build_secret_blast_radius_payload(matrix)

    def _build_secret_blast_radius_payload(self, matrix: list[dict[str, Any]]) -> dict[str, Any] | None:
        if not matrix:
            return None
        auth_accepted_count = sum(1 for entry in matrix if entry.get("auth_accepted") is True)
        return {
            "matrix": matrix,
            "endpoints_tested": len(matrix),
            "auth_accepted_count": auth_accepted_count,
        }

    def _build_executive_summary(self, finding: dict[str, Any]) -> str:
        if finding.get("attack_class") != "sensitive_exposure":
            return ""
        metadata_raw = finding.get("metadata") or {}
        metadata = metadata_raw if isinstance(metadata_raw, dict) else {}
        secret_meta = self._parse_secret_metadata(str(finding.get("evidence_notes", ""))) or {}
        priv_raw = metadata.get("privilege_fingerprint") or {}
        priv = priv_raw if isinstance(priv_raw, dict) else {}
        secret_type = secret_meta.get("secret_type") or "credential"
        endpoint = finding.get("affected_endpoint", "an endpoint")
        level = str(priv.get("observed_access_level", "")).lower()
        if "admin" in level or "privileged" in level:
            impact = "An attacker with this credential could gain administrative access."
        elif "user" in level or "authenticated" in level:
            impact = "An attacker could access user-scoped data and API resources."
        else:
            impact = "An attacker could make authenticated API calls."
        if str(secret_meta.get("active_during_scan", "")).lower() == "true":
            activity = "The credential was confirmed active during the scan."
        else:
            activity = "Active status was not confirmed during the scan."
        return f"A {secret_type} was discovered exposed at {endpoint}. {impact} {activity}"

    def _build_attack_narrative(self, finding: dict[str, Any]) -> str:
        if finding.get("attack_class") != "sensitive_exposure":
            return ""
        metadata_raw = finding.get("metadata") or {}
        metadata = metadata_raw if isinstance(metadata_raw, dict) else {}
        secret_meta = self._parse_secret_metadata(str(finding.get("evidence_notes", ""))) or {}
        leak_source = metadata.get("leak_source") if isinstance(metadata, dict) else None
        blast_radius = self._secret_blast_radius_for_finding(finding)
        priv_raw = metadata.get("privilege_fingerprint") or {}
        priv = priv_raw if isinstance(priv_raw, dict) else {}
        factors = self._severity_factors_for_finding(finding)

        lines: list[str] = []
        n = 1
        if leak_source:
            leak_type = "unknown"
            leak_confidence = 0.0
            if isinstance(leak_source, dict):
                leak_type = str(leak_source.get("type") or "unknown")
                try:
                    leak_confidence = float(leak_source.get("confidence", 0.0))
                except (TypeError, ValueError):
                    leak_confidence = 0.0
            else:
                leak_type = str(leak_source)
            lines.append(f"{n}. **Discovered**: Secret found at {leak_type} ({leak_confidence * 100:.0f}% confidence)")
        else:
            lines.append(f"{n}. **Discovered**: Secret found in response at {finding.get('affected_endpoint')}")
        n += 1

        if secret_meta.get("secret_type"):
            lines.append(
                f"{n}. **Classified**: Type: {secret_meta.get('secret_type')}, "
                f"Fingerprint: `{secret_meta.get('secret_fingerprint')}` (dedup hash, not the secret value)"
            )
            n += 1
        if blast_radius:
            lines.append(f"{n}. **Replayed**: Tested against {blast_radius.get('endpoints_tested')} endpoint(s)")
            n += 1
            lines.append(
                f"{n}. **Blast Radius**: {blast_radius.get('auth_accepted_count')} "
                f"of {blast_radius.get('endpoints_tested')} endpoints accepted the credential"
            )
            n += 1
        if priv.get("observed_access_level"):
            lines.append(f"{n}. **Privilege**: Observed access level: {priv.get('observed_access_level')}")
            n += 1
        if secret_meta.get("ttl_bucket"):
            lines.append(
                f"{n}. **Lifecycle**: TTL bucket: {secret_meta.get('ttl_bucket')}, "
                f"active during scan: {secret_meta.get('active_during_scan')}"
            )
            n += 1
        if factors:
            first_factor = factors[0] if isinstance(factors[0], dict) else {}
            lines.append(f"{n}. **Severity Factor**: {first_factor.get('description', '')}")
        return "\n".join(lines)

    def _build_remediation_plan_section(self, finding: dict[str, Any]) -> str:
        if finding.get("attack_class") != "sensitive_exposure":
            return ""
        metadata_raw = finding.get("metadata") or {}
        metadata = metadata_raw if isinstance(metadata_raw, dict) else {}
        priv_raw = metadata.get("privilege_fingerprint") or {}
        priv = priv_raw if isinstance(priv_raw, dict) else {}
        leak_source = metadata.get("leak_source") if isinstance(metadata, dict) else None
        blast_radius = self._secret_blast_radius_for_finding(finding)

        items: list[str] = [
            "1. **Rotate / Revoke**: Immediately invalidate the exposed credential and replace it with a new one."
        ]
        n = 2

        observed_level = str(priv.get("observed_access_level", "")).lower()
        if "admin" in observed_level or "privileged" in observed_level:
            items.append(f"{n}. **Restrict Scope**: Downscope permissions to minimum required by the service.")
            n += 1

        leak_type = ""
        if leak_source:
            if isinstance(leak_source, dict):
                leak_type = str(leak_source.get("type") or "unknown")
            else:
                leak_type = str(leak_source)
            guidance_map = {
                "debug_endpoint": "Disable or restrict access to debug endpoints in production.",
                "config_json": "Remove credentials from public-facing config responses.",
                "source_map": "Restrict .map files from production deployments.",
                "env_file": "Remove .env files from web-accessible paths and rotate affected secrets.",
                "backup_file": "Restrict access to backup and archive files.",
            }
            guidance = guidance_map.get(leak_type, "Audit the endpoint returning this secret and restrict access.")
            items.append(f"{n}. **Fix Source ({leak_type})**: {guidance}")
            n += 1

        accepted_count = 0
        if blast_radius:
            try:
                accepted_count = int(blast_radius.get("auth_accepted_count", 0))
            except (TypeError, ValueError):
                accepted_count = 0
        if blast_radius and accepted_count > 2:
            items.append(f"{n}. **Audit Access Logs**: Review server logs for unauthorized access using this credential.")
            n += 1

        if isinstance(metadata, dict) and metadata.get("cors_permissive"):
            items.append(f"{n}. **CORS Policy**: Tighten CORS headers to prevent cross-origin credential harvesting.")
            n += 1

        if isinstance(metadata, dict) and metadata.get("cache_permissive"):
            items.append(f"{n}. **Cache Control**: Add Cache-Control: no-store to responses containing credentials.")

        return "#### Remediation Plan\n\n" + "\n".join(items)

    def _build_secret_exposure_evidence_pack(self, finding: dict[str, Any]) -> dict[str, Any] | None:
        if finding.get("attack_class") != "sensitive_exposure":
            return None
        metadata = finding.get("metadata") or {}
        secret_meta = self._parse_secret_metadata(str(finding.get("evidence_notes", "")))
        blast_radius = self._secret_blast_radius_for_finding(finding)
        priv = metadata.get("privilege_fingerprint") if isinstance(metadata, dict) else None
        lifecycle: dict[str, Any] | None = None
        if secret_meta:
            lifecycle = {
                "ttl_bucket": secret_meta.get("ttl_bucket"),
                "active_during_scan": secret_meta.get("active_during_scan"),
                "guidance": self._lifecycle_guidance(secret_meta),
            }
        return {
            "secret_properties": secret_meta,
            "blast_radius": blast_radius,
            "privilege_fingerprint": priv,
            "lifecycle": lifecycle,
            "severity_factors": self._severity_factors_for_finding(finding),
            "leak_source": metadata.get("leak_source") if isinstance(metadata, dict) else None,
            "remediation_priority": self._remediation_priority(str(finding.get("severity", "")), metadata),
        }

    def _build_race_timeline(self, finding: dict[str, Any]) -> str:
        attack_class = str(finding.get("attack_class", "")).strip().lower()
        if attack_class not in _RACE_TIMELINE_CLASSES:
            return ""
        metadata = finding.get("metadata")
        if not isinstance(metadata, dict):
            return ""
        race_group_raw = metadata.get("_race_group_id") or metadata.get("race_group_id")
        if not isinstance(race_group_raw, str) or not race_group_raw.strip():
            return ""
        race_group_id = race_group_raw.strip()

        proof_artifacts = finding.get("proof_artifacts")
        if not isinstance(proof_artifacts, list) or not proof_artifacts:
            return ""

        rows: list[str] = []
        row_index = 1
        for artifact in proof_artifacts:
            if not isinstance(artifact, dict):
                continue
            response_raw = artifact.get("response")
            response = self._redact_evidence(response_raw) if isinstance(response_raw, dict) else {}
            request_raw = artifact.get("request")
            request = self._redact_evidence(request_raw) if isinstance(request_raw, dict) else {}
            timestamp_candidates = [
                artifact.get("timestamp"),
                response.get("timestamp"),
                response.get("time"),
                request.get("timestamp"),
                request.get("time"),
            ]
            timestamp = "-"
            for candidate in timestamp_candidates:
                if isinstance(candidate, str) and candidate.strip():
                    timestamp = self._truncate_markdown_cell(candidate.strip().replace("|", "/"), limit=40)
                    break
            status_value = response.get("status")
            if status_value is None:
                status_value = response.get("status_code")
            status = "-" if status_value is None else self._truncate_markdown_cell(str(status_value), limit=12)
            response_text_source = (
                artifact.get("summary")
                or response.get("body_excerpt")
                or response.get("body")
                or response.get("message")
                or artifact.get("evidence_notes")
                or "-"
            )
            response_text = self._truncate_markdown_cell(str(self._redact_value(response_text_source)).replace("|", "/"), limit=96)
            rows.append(f"| {row_index} | {timestamp} | {status} | {response_text} |")
            row_index += 1

        if not rows:
            return ""
        return "\n".join(
            [
                f"**Race Timeline** (group: {race_group_id})",
                "| # | Timestamp | Status | Response |",
                "|---|---|---|---|",
                *rows,
            ]
        )

    def _truncate_markdown_cell(self, value: str, limit: int) -> str:
        if len(value) <= limit:
            return value
        return f"{value[: limit - 3]}..."

    def generate_untested_classes_section(self, scan_config: dict, skipped_rules: list[str]) -> str:
        _ = scan_config
        lines: list[str] = [
            "## Untested Attack Classes (Require Authentication)",
            "| Attack Class | Why Skipped | How to Enable |",
            "|---|---|---|",
        ]
        for rule_name in skipped_rules:
            description = _UNTESTED_CLASS_DESCRIPTIONS.get(rule_name, _DEFAULT_UNTESTED_REASON)
            lines.append(f"| {rule_name} | {description} | Provide credentials or session cookies |")
        return "\n".join(lines)

    def calculate_unauth_coverage(self, all_rules: list, active_rules: list) -> float:
        if not all_rules:
            return 0.0
        return (len(active_rules) / len(all_rules)) * 100.0

    def _normalize_rule_list(self, raw_rules: Any) -> list[str]:
        if not isinstance(raw_rules, list):
            return []
        normalized: list[str] = []
        for item in raw_rules:
            if item is None:
                continue
            item_text = str(item).strip()
            if item_text:
                normalized.append(item_text)
        return normalized

    def _resolve_unauth_rule_sets(self) -> tuple[list[str], list[str], list[str]]:
        try:
            from execution_plane.planner.planner import AttackPlanner
        except Exception:
            return [], [], []
        planner = AttackPlanner()
        all_rules: list[str] = []
        active_rules: list[str] = []
        skipped_rules: list[str] = []
        for rule in planner.rules:
            name = str(getattr(rule, "name", "")).strip()
            if not name:
                continue
            all_rules.append(name)
            if bool(getattr(rule, "requires_auth", False)):
                skipped_rules.append(name)
            else:
                active_rules.append(name)
        return all_rules, active_rules, skipped_rules
