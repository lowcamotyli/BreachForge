from __future__ import annotations

import copy
import gzip
import json
import os
import re
import uuid as _uuid_mod
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Literal
from urllib.parse import urlparse
from uuid import UUID

import structlog
from botocore.exceptions import BotoCoreError, ClientError
from sqlalchemy import distinct, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from api.models.responses import AttackChain, AttackChainReportResponse, AttackChainScoreFactors, AttackChainStep
from api.models.requests import ScanPolicyV2
from api.models.responses import AuthorizationPackResponse
from control_plane.attack_chain_builder import (
    ChainConfidenceResult,
    adjust_chain_severity,
    build_remediation,
    compute_chain_confidence,
    compute_chain_score,
)
from control_plane.exporters.replay_exporter import ReplayExporter
from control_plane.ownership import OwnershipResolver
from storage.db.models import (
    AssetMap,
    AuditEvent,
    AuditEventType,
    AttackTask,
    AttackTaskStatus,
    AuthContext,
    Endpoint,
    Finding,
    ProofArtifact,
    RawProbe,
    Scan,
    Severity,
)
from storage.evidence.store import EvidenceStore

if TYPE_CHECKING:
    from control_plane.auth_manager import IdentityHealthMatrix
    from control_plane.orchestrator import PreflightResult

logger = structlog.get_logger(__name__)

REDACTED = "[REDACTED]"
_SENSITIVE_KEY_PATTERN = re.compile(r"authorization|cookie|credential|password|token|secret", re.IGNORECASE)
_REQUEST_HEADER_SENSITIVE_KEYS: tuple[str, ...] = ("authorization", "cookie", "password", "token", "x-api-key")
_SAFE_SECRET_METADATA_KEYS: tuple[str, ...] = (
    "secret_blast_radius",
    "secret_blast_radius_matrix",
    "secret_exposure_evidence_pack",
    "secret_properties",
    "secret_type",
    "secret_fingerprint",
)
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
_DISCOVERY_SOURCES: tuple[str, ...] = ("crawler", "har", "openapi", "js", "wordlist", "manual")
_EXPECTED_SURFACE_KEYS: tuple[str, ...] = ("expected_surface", "expected_endpoints")
_DISCOVERED_SURFACE_KEYS: tuple[str, ...] = ("discovered_surface", "discovered_endpoints")
_MANUAL_EXCLUDED_PATH_KEYS: tuple[str, ...] = (
    "manual_excluded_paths",
    "manually_excluded_paths",
    "excluded_paths",
    "exclude_paths",
    "path_exclusions",
)
_IDENTITY_FAILURE_REASONS: frozenset[str] = frozenset(
    {"expired", "missing", "forbidden", "csrf_failed", "refresh_failed"}
)


def build_attack_chain_timeline(finding: Finding, tasks_by_id: dict[object, AttackTask]) -> list[dict[str, Any]]:
    chain: list[dict[str, Any]] = []
    task_id = getattr(finding, "attack_task_id", None)
    if task_id is None:
        proof_artifacts = getattr(finding, "proof_artifacts", [])
        if isinstance(proof_artifacts, list) and proof_artifacts:
            task_id = getattr(proof_artifacts[0], "attack_task_id", None)

    task = tasks_by_id.get(task_id) or tasks_by_id.get(str(task_id))
    seen: set[str] = set()
    while task is not None:
        task_key = str(getattr(task, "id", ""))
        if not task_key or task_key in seen:
            break
        seen.add(task_key)
        chain.insert(
            0,
            {
                "task_id": task_key,
                "attack_class": str(getattr(task, "attack_class", "")),
                "endpoint_id": str(getattr(task, "endpoint_id", "")),
                "replan_reason": getattr(task, "replan_reason", None),
                "timestamp": _task_timestamp(task),
            },
        )
        parent_task_id = getattr(task, "parent_task_id", None)
        if parent_task_id is None:
            break
        parent_task = tasks_by_id.get(parent_task_id) or tasks_by_id.get(str(parent_task_id))
        if parent_task is None:
            parent_task = getattr(task, "parent_task", None)
        task = parent_task

    return [
        {
            "step": f"step_{index}",
            **entry,
        }
        for index, entry in enumerate(chain, start=1)
    ]


def _task_timestamp(task: AttackTask) -> str | None:
    for attr_name in ("created_at", "updated_at", "timestamp"):
        value = getattr(task, attr_name, None)
        if isinstance(value, datetime):
            return value.isoformat()
        if isinstance(value, str) and value:
            return value
    return None


class ReportingService:
    def __init__(
        self,
        db: AsyncSession,
        evidence_store: EvidenceStore | None = None,
        auth_manager: Any | None = None,
    ) -> None:
        self._db = db
        self._auth_manager = auth_manager
        if evidence_store is not None:
            self._evidence_store = evidence_store
            return
        try:
            self._evidence_store = EvidenceStore()
        except Exception:
            self._evidence_store = None

    async def assemble_report(self, scan_id: UUID) -> dict[str, Any]:
        scan_result = await self._db.execute(
            select(Scan)
            .where(Scan.id == scan_id)
            .options(
                selectinload(Scan.target),
                selectinload(Scan.auth_context),
                selectinload(Scan.asset_map).selectinload(AssetMap.endpoints),
            )
        )
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
                selectinload(Finding.proof_artifacts)
                .selectinload(ProofArtifact.attack_task)
                .selectinload(AttackTask.parent_task)
                .selectinload(AttackTask.parent_task),
            )
        )
        findings = findings_result.scalars().all()

        actions_performed = await self._actions_performed(scan_id)
        skipped_blocked = await self._skipped_blocked(scan_id)
        auth_manager = self._auth_manager or await self._build_report_auth_manager(scan_id=scan_id, scan=scan)
        auth_reliability = await self._auth_reliability(scan_id=scan_id, scan=scan, auth_manager=auth_manager)
        identity_health_matrix = getattr(auth_manager, "identity_health_matrix", None)
        auth_setup = self.auth_setup_report_section(
            identity_health_matrix,
            self._preflight_result_for_report(scan=scan, auth_manager=auth_manager),
        )
        discovery_coverage_metrics = await self._discovery_coverage_metrics(scan_id=scan_id, scan=scan)
        scan_blind_spots = self._scan_blind_spots(
            auth_reliability=auth_reliability,
            discovery_coverage_metrics=discovery_coverage_metrics,
            skipped_blocked=skipped_blocked,
            scan=scan,
        )
        report_findings: list[dict[str, Any]] = []
        for finding in findings:
            metadata = copy.deepcopy(finding.extra_metadata) if isinstance(finding.extra_metadata, dict) else {}
            metadata_owner = metadata.get("owner") if isinstance(metadata.get("owner"), dict) else {}
            finding_owner = getattr(finding, "owner", None)
            owner_data: dict[str, Any] = metadata_owner
            if not owner_data and isinstance(finding_owner, dict):
                owner_data = finding_owner
            owner_team = owner_data.get("team", getattr(finding_owner, "team", None))
            owner_service = owner_data.get("service", getattr(finding_owner, "service", None))
            owner_confidence = owner_data.get("confidence", getattr(finding_owner, "confidence", None))
            owner_repo_hint = owner_data.get("repo_hint", getattr(finding_owner, "repo_hint", None))

            if not owner_team:
                endpoint_url = getattr(getattr(finding, "affected_endpoint", None), "url_pattern", None)
                if not endpoint_url and hasattr(finding, "get"):
                    endpoint_url = finding.get("endpoint_url")
                if not endpoint_url:
                    endpoint_meta = metadata.get("endpoint") if isinstance(metadata.get("endpoint"), dict) else {}
                    endpoint_url = (
                        metadata.get("endpoint_url")
                        or metadata.get("affected_endpoint")
                        or endpoint_meta.get("url_pattern")
                        or endpoint_meta.get("url")
                    )
                if endpoint_url:
                    try:
                        resolver = OwnershipResolver()
                        resolved_owner = await resolver.resolve(str(endpoint_url))
                    except Exception:
                        resolved_owner = None
                    if resolved_owner is not None:
                        owner_team = owner_team or resolved_owner.team
                        owner_service = owner_service or resolved_owner.service
                        owner_confidence = owner_confidence or resolved_owner.confidence
                        owner_repo_hint = owner_repo_hint or resolved_owner.repo_hint
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
            tasks_by_id = self._tasks_by_id_for_finding(finding)
            attack_chain_timeline = build_attack_chain_timeline(finding, tasks_by_id)
            replay_exports = self._build_replay_exports(finding=finding, artifacts=artifacts, metadata=metadata)

            report_finding = {
                "id": str(finding.id),
                "title": finding.title,
                "severity": severity,
                "severity_factors": self._severity_factors_from_metadata(metadata),
                "remediation_priority": self._remediation_priority(severity, metadata),
                "provider_attribution": {"engine": self._get_provider_id(finding)},
                "validator_confirmation": {"strategy": self._get_validator_strategy(finding)},
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
                "audit_trail": await self._audit_event_ids_for_finding(
                    scan_id=scan_id,
                    finding_id=finding.id,
                    task_ids={artifact.attack_task_id for artifact in finding.proof_artifacts},
                ),
                "score_explanation": self._score_explanation_for_artifacts(artifacts),
                "metadata": metadata,
                "replay_exports": replay_exports,
            }
            if owner_data or finding_owner is not None or owner_team or owner_service or owner_confidence or owner_repo_hint:
                report_finding["owner_team"] = owner_team
                report_finding["owner_service"] = owner_service
                report_finding["owner_confidence"] = owner_confidence
                report_finding["owner_repo_hint"] = owner_repo_hint
            if len(attack_chain_timeline) > 1:
                report_finding["attack_chain_timeline"] = attack_chain_timeline
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
            "auth_reliability": auth_reliability,
            "auth_setup": auth_setup,
            "discovery_coverage_metrics": discovery_coverage_metrics,
            "scan_blind_spots": scan_blind_spots,
            "findings": report_findings,
        }

    def _build_replay_exports(
        self, finding: Finding, artifacts: list[dict[str, Any]], metadata: dict[str, Any]
    ) -> dict[str, Any] | None:
        bundle = self._extract_replay_bundle(finding=finding, artifacts=artifacts, metadata=metadata)
        if not bundle:
            return None

        return {
            "curl": ReplayExporter.to_curl(bundle),
            "httpie": ReplayExporter.to_httpie(bundle),
            "postman": ReplayExporter.to_postman(bundle),
            "har": ReplayExporter.to_har_subset(bundle),
        }

    def _extract_replay_bundle(
        self, finding: Finding, artifacts: list[dict[str, Any]], metadata: dict[str, Any]
    ) -> dict[str, Any] | None:
        finding_bundle = getattr(finding, "bundle", None)
        finding_attack_request = getattr(finding, "attack_request", None)
        candidate_bundle: dict[str, Any] = {}

        if isinstance(finding_attack_request, dict) and finding_attack_request:
            candidate_bundle["attack_request"] = finding_attack_request
        elif isinstance(finding_bundle, dict) and finding_bundle:
            candidate_bundle = dict(finding_bundle)
        elif isinstance(metadata.get("attack_request"), dict) and metadata.get("attack_request"):
            candidate_bundle["attack_request"] = dict(metadata["attack_request"])
        elif isinstance(metadata.get("bundle"), dict) and metadata.get("bundle"):
            candidate_bundle = dict(metadata["bundle"])

        if not candidate_bundle:
            for artifact in artifacts:
                request_payload = artifact.get("request")
                if isinstance(request_payload, dict) and request_payload:
                    candidate_bundle = {"attack_request": request_payload}
                    break

        attack_request = candidate_bundle.get("attack_request")
        if not isinstance(attack_request, dict) or not attack_request:
            return None
        return candidate_bundle

    def _tasks_by_id_for_finding(self, finding: Finding) -> dict[object, AttackTask]:
        tasks_by_id: dict[object, AttackTask] = {}
        proof_artifacts = getattr(finding, "proof_artifacts", [])
        if not isinstance(proof_artifacts, list):
            return tasks_by_id

        for artifact in proof_artifacts:
            task = getattr(artifact, "attack_task", None)
            while isinstance(task, AttackTask):
                task_id = getattr(task, "id", None)
                if task_id is None or task_id in tasks_by_id:
                    break
                tasks_by_id[task_id] = task
                tasks_by_id[str(task_id)] = task
                try:
                    task = getattr(task, "parent_task", None)
                except Exception:
                    break
        return tasks_by_id

    async def _actions_performed(self, scan_id: UUID) -> dict[str, Any]:
        empty = {
            "total_requests": 0,
            "by_class": {},
            "total_requests_sent": 0,
            "requests_by_attack_class": {},
            "tasks_dispatched": 0,
            "tasks_with_findings": 0,
        }
        try:
            total_requests_result = await self._db.execute(
                select(func.count(RawProbe.id))
                .join(AttackTask, RawProbe.attack_task_id == AttackTask.id)
                .where(AttackTask.scan_id == scan_id, AttackTask.status == AttackTaskStatus.done)
            )
            tasks_dispatched_result = await self._db.execute(
                select(func.count(AttackTask.id)).where(AttackTask.scan_id == scan_id)
            )
            by_class_result = await self._db.execute(
                select(AttackTask.attack_class, func.count(RawProbe.id))
                .join(RawProbe, RawProbe.attack_task_id == AttackTask.id)
                .where(AttackTask.scan_id == scan_id, AttackTask.status == AttackTaskStatus.done)
                .group_by(AttackTask.attack_class)
            )
            tasks_with_findings_result = await self._db.execute(
                select(func.count(distinct(ProofArtifact.attack_task_id)))
                .join(AttackTask, AttackTask.id == ProofArtifact.attack_task_id)
                .where(AttackTask.scan_id == scan_id, ProofArtifact.finding_id.is_not(None))
            )
        except Exception:
            return empty

        by_class: dict[str, int] = {}
        for attack_class, count in by_class_result.all():
            key = str(attack_class).strip() if attack_class is not None else ""
            by_class[key or "unknown"] = by_class.get(key or "unknown", 0) + int(count or 0)

        total_requests = int(total_requests_result.scalar_one() or 0)
        return {
            "total_requests": total_requests,
            "by_class": by_class,
            "total_requests_sent": total_requests,
            "requests_by_attack_class": by_class,
            "tasks_dispatched": int(tasks_dispatched_result.scalar_one() or 0),
            "tasks_with_findings": int(tasks_with_findings_result.scalar_one() or 0),
        }

    async def _skipped_blocked(self, scan_id: UUID) -> dict[str, Any]:
        skipped_details: list[dict[str, str]] = []
        skipped_by_task: dict[str, dict[str, str]] = {}

        try:
            task_rows_result = await self._db.execute(
                select(AttackTask.id, AttackTask.attack_class, Endpoint.url_pattern)
                .join(Endpoint, Endpoint.id == AttackTask.endpoint_id)
                .where(AttackTask.scan_id == scan_id)
            )
        except Exception:
            task_rows_result = None
        task_context_by_id: dict[str, dict[str, str]] = {}
        if task_rows_result is not None:
            for task_id, attack_class, endpoint in task_rows_result.all():
                task_context_by_id[str(task_id)] = {
                    "attack_class": str(attack_class or "unknown"),
                    "endpoint": str(endpoint or ""),
                }

        try:
            skipped_events_result = await self._db.execute(
                select(AuditEvent.id, AuditEvent.details)
                .where(AuditEvent.scan_id == scan_id, AuditEvent.event_type == AuditEventType.TASK_SKIPPED)
                .order_by(AuditEvent.created_at.asc())
            )
            for _, details in skipped_events_result.all():
                if not isinstance(details, dict):
                    continue
                task_id_raw = details.get("task_id")
                if task_id_raw is None:
                    continue
                task_id = str(task_id_raw)
                if not task_id:
                    continue
                policy_reason = details.get("policy_skip_reason") or details.get("reason") or ""
                reason_str = str(policy_reason or "")
                if reason_str and not reason_str.startswith("policy:"):
                    reason_str = f"policy:{reason_str}"
                task_context = task_context_by_id.get(task_id, {})
                skipped_by_task[task_id] = {
                    "task_id": task_id,
                    "attack_class": str(task_context.get("attack_class") or details.get("attack_class") or "unknown"),
                    "reason": reason_str,
                    "endpoint": str(task_context.get("endpoint") or details.get("endpoint") or ""),
                }
        except Exception:
            pass

        redis_url = os.getenv("REDIS_URL")
        if redis_url:
            try:
                from redis.asyncio import Redis as AsyncRedis

                redis_client = AsyncRedis.from_url(redis_url, decode_responses=True)
                try:
                    raw_records = await redis_client.lrange(f"skipped_tasks:{scan_id}", 0, -1)
                finally:
                    await redis_client.aclose()
            except Exception:
                raw_records = []

            for raw_record in raw_records:
                try:
                    parsed = json.loads(raw_record)
                except (TypeError, ValueError, json.JSONDecodeError):
                    continue
                if not isinstance(parsed, dict):
                    continue
                task_id = str(parsed.get("task_id") or "")
                if not task_id:
                    continue
                task_context = task_context_by_id.get(task_id, {})
                raw_reason = str(parsed.get("policy_skip_reason") or parsed.get("reason") or "")
                reason = raw_reason if raw_reason.startswith("policy:") else (f"policy:{raw_reason}" if raw_reason else "")
                skipped_by_task[task_id] = {
                    "task_id": task_id,
                    "attack_class": str(parsed.get("attack_class") or task_context.get("attack_class") or "unknown"),
                    "reason": reason,
                    "endpoint": str(parsed.get("endpoint") or task_context.get("endpoint") or ""),
                }

        skipped_details = list(skipped_by_task.values())
        return {"tasks_skipped": len(skipped_details), "skipped_details": skipped_details}

    async def _auth_reliability(self, *, scan_id: UUID, scan: Scan, auth_manager: Any | None = None) -> dict[str, Any]:
        auth_manager = auth_manager or self._auth_manager or await self._build_report_auth_manager(scan_id=scan_id, scan=scan)
        metrics = self._empty_auth_coverage_metrics()
        failures: list[Any] = []

        get_metrics = getattr(auth_manager, "get_auth_coverage_metrics", None)
        if callable(get_metrics):
            try:
                raw_metrics = get_metrics()
                if isinstance(raw_metrics, dict):
                    metrics = self._normalize_auth_coverage_metrics(raw_metrics)
            except Exception:
                metrics = self._empty_auth_coverage_metrics()

        get_failures = getattr(auth_manager, "get_identity_failures", None)
        if callable(get_failures):
            try:
                raw_failures = get_failures()
                failures = await raw_failures if hasattr(raw_failures, "__await__") else raw_failures
            except Exception:
                failures = []

        identity_matrix = {}
        raw_identity_matrix = getattr(auth_manager, "identity_health_matrix", None)
        if raw_identity_matrix is not None:
            try:
                identity_matrix = self.auth_identity_matrix_section(raw_identity_matrix)
            except Exception:
                identity_matrix = {}

        return {
            **metrics,
            "identity_failures": self._identity_failure_rows(failures),
            "identity_matrix": identity_matrix,
        }

    def auth_identity_matrix_section(self, matrix: IdentityHealthMatrix) -> dict[str, Any]:
        summary = matrix.summary
        per_role = summary.get("per_role")
        per_tenant = summary.get("per_tenant")
        role_markers = summary.get("role_markers")
        tenant_markers = summary.get("tenant_markers")
        return {
            "per_role": per_role if isinstance(per_role, dict) else {},
            "per_tenant": per_tenant if isinstance(per_tenant, dict) else {},
            "role_markers": role_markers if isinstance(role_markers, list) else [],
            "tenant_markers": tenant_markers if isinstance(tenant_markers, list) else [],
        }

    def auth_setup_report_section(
        self,
        matrix: IdentityHealthMatrix | None,
        preflight_result: PreflightResult | None,
    ) -> dict[str, Any]:
        identity_rows = self._auth_setup_identity_rows(matrix)
        weighted_successes = 0.0
        weighted_total = 0
        per_identity_blind_spots: list[dict[str, Any]] = []
        auth_warnings: list[str] = []

        for row in identity_rows:
            identity = row["identity"]
            role = row["role"]
            pass_rate = row["pass_rate"]
            total_probes = row["total_probes"]
            failed_probes = row["failed_probes"]
            degraded_probes = row["degraded_probes"]
            blind_spots: list[str] = []

            if total_probes == 0:
                blind_spots.append("unchecked identity")
                auth_warnings.append(f"{role} identity had 0 probes ({identity})")
            if failed_probes:
                blind_spots.append(f"{failed_probes} failed probes")
            if degraded_probes:
                blind_spots.append(f"{degraded_probes} degraded probes")
            if total_probes > 0 and pass_rate == 0.0:
                auth_warnings.append(f"{role} identity had 0 successful probes ({identity})")
            if pass_rate < 1.0 and total_probes > 0:
                auth_warnings.append(f"{role} identity pass rate was {pass_rate:.0%} ({identity})")

            if total_probes > 0:
                weighted_successes += pass_rate * total_probes
                weighted_total += total_probes

            if pass_rate < 1.0 or degraded_probes > 0:
                per_identity_blind_spots.append(
                    {
                        "identity": identity,
                        "role": role,
                        "pass_rate": pass_rate,
                        "blind_spots": blind_spots,
                    }
                )

        preflight_status = self._preflight_status(preflight_result)
        preflight_failed = preflight_status == "failed"
        if preflight_failed:
            auth_warnings.append("auth preflight failed")

        return {
            "overall_reliability_score": (weighted_successes / weighted_total) if weighted_total else 0.0,
            "per_identity_blind_spots": per_identity_blind_spots,
            "auth_warnings": list(dict.fromkeys(auth_warnings)),
            "preflight_status": preflight_status,
            "is_clean_report_reliable": not (
                preflight_failed or any(row["pass_rate"] < 0.8 for row in identity_rows)
            ),
        }

    def _auth_setup_identity_rows(self, matrix: IdentityHealthMatrix | None) -> list[dict[str, Any]]:
        if matrix is None:
            return []
        try:
            matrix_section = self.auth_identity_matrix_section(matrix)
        except Exception:
            return []

        rows: list[dict[str, Any]] = []
        rows.extend(
            self._auth_setup_rows_from_bucket(
                bucket=matrix_section.get("per_role"),
                markers=matrix_section.get("role_markers"),
                role_fallback="role",
            )
        )
        rows.extend(
            self._auth_setup_rows_from_bucket(
                bucket=matrix_section.get("per_tenant"),
                markers=matrix_section.get("tenant_markers"),
                role_fallback="tenant",
            )
        )
        return rows

    def _auth_setup_rows_from_bucket(
        self,
        *,
        bucket: Any,
        markers: Any,
        role_fallback: str,
    ) -> list[dict[str, Any]]:
        stats_by_identity = bucket if isinstance(bucket, dict) else {}
        marker_list = markers if isinstance(markers, list) else []
        identities = list(dict.fromkeys([*(str(marker) for marker in marker_list), *(str(key) for key in stats_by_identity)]))
        rows: list[dict[str, Any]] = []
        for identity_raw in identities:
            identity = self._safe_report_label(identity_raw or "unknown")
            stats = stats_by_identity.get(identity_raw)
            stats = stats if isinstance(stats, dict) else {}
            total_probes = self._coerce_int(stats.get("total_probes"), default=0)
            rows.append(
                {
                    "identity": identity,
                    "role": identity if role_fallback == "role" else role_fallback,
                    "pass_rate": max(0.0, min(1.0, self._coerce_float(stats.get("pass_rate"), default=0.0))),
                    "total_probes": total_probes,
                    "failed_probes": self._coerce_int(stats.get("failed_probes"), default=0),
                    "degraded_probes": self._coerce_int(stats.get("degraded_probes"), default=0),
                }
            )
        return rows

    def _preflight_status(self, preflight_result: PreflightResult | None) -> str:
        if preflight_result is None:
            return "unknown"
        if isinstance(preflight_result, dict):
            return str(preflight_result.get("status") or "unknown").strip().lower() or "unknown"
        return str(getattr(preflight_result, "status", "unknown") or "unknown").strip().lower() or "unknown"

    def _preflight_result_for_report(self, *, scan: Scan, auth_manager: Any | None) -> Any | None:
        preflight_result = getattr(auth_manager, "preflight_result", None)
        if preflight_result is not None:
            return preflight_result
        auth_context = getattr(scan, "auth_context", None)
        if not isinstance(auth_context, AuthContext):
            auth_context = getattr(scan, "auth_context_ref", None)
        health_payload = getattr(auth_context, "health", None)
        if not isinstance(health_payload, dict):
            return None
        for key in ("preflight_result", "preflight", "auth_preflight"):
            candidate = health_payload.get(key)
            if isinstance(candidate, dict):
                return candidate
        return None

    async def _build_report_auth_manager(self, *, scan_id: UUID, scan: Scan) -> Any | None:
        try:
            from control_plane.auth_manager import AuthManager, IdentityFailure, IdentityRole, SessionSnapshot
        except Exception:
            return None

        async def _noop_pause_scan(_scan_id: UUID, _reason: str) -> None:
            return None

        def _unused_session_factory() -> None:
            raise RuntimeError("Reporting auth metrics do not open a session")

        manager = AuthManager(scan_id, _unused_session_factory, _noop_pause_scan)
        auth_context = await self._auth_context_for_scan(scan_id=scan_id, scan=scan)
        if auth_context is None:
            return manager

        snapshot_payload = auth_context.session_snapshot if isinstance(auth_context.session_snapshot, dict) else {}
        health_payload = auth_context.health if isinstance(auth_context.health, dict) else {}
        captured_at = self._parse_datetime(snapshot_payload.get("captured_at")) or datetime.now(UTC)
        expires_at = self._parse_datetime(snapshot_payload.get("expires_at"))

        cookies: list[dict[str, str]] = []
        if self._snapshot_has_material(snapshot_payload.get("cookies")):
            cookies = [{"name": "session", "value": "present"}]

        auth_headers: dict[str, str] = {}
        if self._snapshot_has_material(snapshot_payload.get("auth_headers")) or self._snapshot_has_material(
            snapshot_payload.get("bearer_token")
        ):
            auth_headers["Authorization"] = "present"

        session_snapshot = SessionSnapshot(
            scan_id=scan_id,
            cookies=cookies,
            auth_headers=auth_headers,
            csrf_tokens={},
            captured_at=captured_at,
            expires_at=expires_at,
        )
        manager._session_snapshot = session_snapshot
        manager._identity_contexts = manager._build_identity_contexts(session_snapshot)
        manager._health_check_results = self._health_check_results_from_payload(health_payload)
        self._hydrate_named_identities(
            manager=manager,
            scan_id=scan_id,
            raw_identities=snapshot_payload.get("identities"),
            captured_at=captured_at,
        )
        self._hydrate_identity_failures_from_health(
            manager=manager,
            identity_failure_type=IdentityFailure,
            health_payload=health_payload,
        )
        for failure in await self._redis_identity_failures(scan_id):
            try:
                manager._identity_failures.append(
                    IdentityFailure(
                        identity_id=failure["identity_id"],
                        reason=failure["reason"],
                        timestamp=self._parse_datetime(failure.get("timestamp")) or datetime.now(UTC),
                    )
                )
            except Exception:
                continue
        return manager

    async def _auth_context_for_scan(self, *, scan_id: UUID, scan: Scan) -> AuthContext | None:
        auth_context = getattr(scan, "auth_context", None)
        if isinstance(auth_context, AuthContext):
            return auth_context
        auth_context_ref = getattr(scan, "auth_context_ref", None)
        if isinstance(auth_context_ref, AuthContext):
            return auth_context_ref
        try:
            result = await self._db.execute(select(AuthContext).where(AuthContext.scan_id == scan_id))
        except Exception:
            return None
        return result.scalar_one_or_none()

    def _hydrate_named_identities(
        self,
        *,
        manager: Any,
        scan_id: UUID,
        raw_identities: Any,
        captured_at: datetime,
    ) -> None:
        if not isinstance(raw_identities, list):
            return
        try:
            from control_plane.auth_manager import IdentityContext, IdentityRole
        except Exception:
            return

        for raw_identity in raw_identities:
            if not isinstance(raw_identity, dict):
                continue
            identity_id = self._safe_report_label(str(raw_identity.get("name") or "unknown"))
            auth_state = str(raw_identity.get("auth_state") or "active").strip().lower()
            if auth_state not in {"active", "expired", "none", "pending"}:
                auth_state = "none"

            auth_context = raw_identity.get("auth_context")
            auth_context_dict = auth_context if isinstance(auth_context, dict) else {}
            has_cookies = self._snapshot_has_material(auth_context_dict.get("cookies"))
            has_token = self._snapshot_has_material(auth_context_dict.get("bearer_token"))
            role_hint = str(raw_identity.get("role_hint") or IdentityRole.user.value)
            try:
                role = IdentityRole(role_hint)
            except ValueError:
                role = IdentityRole.user

            context = IdentityContext(
                scan_id=scan_id,
                role=role,
                cookies=[{"name": "session", "value": "present"}] if has_cookies else [],
                auth_headers={"Authorization": "present"} if has_token else {},
                csrf_tokens={},
                captured_at=captured_at,
                name=identity_id,
                tenant_hint=(
                    str(raw_identity.get("tenant_hint")) if raw_identity.get("tenant_hint") is not None else None
                ),
                auth_state="active" if auth_state == "active" else "expired",
                active=auth_state == "active",
            )
            manager._named_identities[identity_id] = context
            manager._identity_contexts[identity_id] = context
            if auth_state in {"expired", "none"}:
                reason = "expired" if auth_state == "expired" else "missing"
                manager._record_identity_failure(identity_id=identity_id, reason=reason)
            elif not has_cookies and not has_token:
                manager._record_identity_failure(identity_id=identity_id, reason="missing")

    def _hydrate_identity_failures_from_health(
        self,
        *,
        manager: Any,
        identity_failure_type: Any,
        health_payload: dict[str, Any],
    ) -> None:
        raw_failures = health_payload.get("identity_failures")
        if isinstance(raw_failures, list):
            for raw_failure in raw_failures:
                if not isinstance(raw_failure, dict):
                    continue
                reason = self._identity_failure_reason(raw_failure.get("reason"))
                if reason is None:
                    continue
                identity_id = self._safe_report_label(str(raw_failure.get("identity_id") or "unknown"))
                timestamp = self._parse_datetime(raw_failure.get("timestamp")) or datetime.now(UTC)
                manager._identity_failures.append(
                    identity_failure_type(identity_id=identity_id, reason=reason, timestamp=timestamp)
                )

        validation_payload = health_payload.get("session_validation")
        if isinstance(validation_payload, dict) and validation_payload.get("valid") is False:
            reason = self._identity_failure_reason(validation_payload.get("reason")) or "refresh_failed"
            manager._identity_failures.append(
                identity_failure_type(identity_id="session", reason=reason, timestamp=datetime.now(UTC))
            )

        status_value = str(health_payload.get("status") or "").lower()
        if status_value == "unhealthy" and not raw_failures:
            reason = self._identity_failure_reason(health_payload.get("error")) or "refresh_failed"
            manager._identity_failures.append(
                identity_failure_type(identity_id="session", reason=reason, timestamp=datetime.now(UTC))
            )

    async def _redis_identity_failures(self, scan_id: UUID) -> list[dict[str, str]]:
        redis_url = os.getenv("REDIS_URL")
        if not redis_url:
            return []
        try:
            from redis.asyncio import Redis as AsyncRedis

            redis_client = AsyncRedis.from_url(redis_url, decode_responses=True)
            try:
                raw_events = await redis_client.xrange(f"scan_events:{scan_id}", "-", "+")
            finally:
                await redis_client.aclose()
        except Exception:
            return []

        failures: list[dict[str, str]] = []
        for event_id, payload in raw_events:
            if not isinstance(payload, dict) or payload.get("event") != "identity_health_failed":
                continue
            identity_id = self._safe_report_label(str(payload.get("identity_name") or "unknown"))
            timestamp = self._timestamp_from_redis_event_id(str(event_id)) or datetime.now(UTC).isoformat()
            failures.append({"identity_id": identity_id, "reason": "expired", "timestamp": timestamp})
        return failures

    def _timestamp_from_redis_event_id(self, event_id: str) -> str | None:
        millis_text, _, _sequence = event_id.partition("-")
        try:
            millis = int(millis_text)
        except ValueError:
            return None
        return datetime.fromtimestamp(millis / 1000, tz=UTC).isoformat()

    def _empty_auth_coverage_metrics(self) -> dict[str, Any]:
        return {
            "session_valid_count": 0,
            "role_count": 0,
            "tenant_count": 0,
            "health_check_pass_rate": 0.0,
        }

    def _normalize_auth_coverage_metrics(self, raw_metrics: dict[str, Any]) -> dict[str, Any]:
        metrics = self._empty_auth_coverage_metrics()
        for key in ("session_valid_count", "role_count", "tenant_count"):
            metrics[key] = self._coerce_int(raw_metrics.get(key), default=0)
        metrics["health_check_pass_rate"] = self._coerce_float(
            raw_metrics.get("health_check_pass_rate"),
            default=0.0,
        )
        return metrics

    def _identity_failure_rows(self, failures: Any) -> list[dict[str, str]]:
        if not isinstance(failures, list):
            return []
        rows: list[dict[str, str]] = []
        for failure in failures:
            identity_id = self._safe_report_label(str(getattr(failure, "identity_id", "unknown") or "unknown"))
            reason = self._identity_failure_reason(getattr(failure, "reason", None))
            timestamp_raw = getattr(failure, "timestamp", None)
            timestamp = timestamp_raw.isoformat() if isinstance(timestamp_raw, datetime) else str(timestamp_raw or "")
            if reason is None:
                continue
            rows.append({"identity_id": identity_id, "reason": reason, "timestamp": timestamp})
        return rows

    def _identity_failure_reason(self, value: Any) -> str | None:
        text = str(value or "").strip().lower()
        for reason in _IDENTITY_FAILURE_REASONS:
            if reason in text:
                return reason
        return None

    def _health_check_results_from_payload(self, health_payload: dict[str, Any]) -> list[bool]:
        raw_results = health_payload.get("health_check_results")
        if isinstance(raw_results, list):
            return [bool(result) for result in raw_results if isinstance(result, (bool, int, float))]

        session_validation = health_payload.get("session_validation")
        if isinstance(session_validation, dict) and isinstance(session_validation.get("valid"), bool):
            return [bool(session_validation["valid"])]

        status_value = str(health_payload.get("status") or "").strip().lower()
        if status_value == "healthy":
            return [True]
        if status_value == "unhealthy":
            return [False]
        return []

    def _snapshot_has_material(self, value: Any) -> bool:
        if value is None:
            return False
        if isinstance(value, str):
            return bool(value.strip())
        if isinstance(value, list):
            return bool(value)
        if isinstance(value, dict):
            if value.get("_encrypted") == "kms_envelope_v1":
                return bool(value.get("ciphertext"))
            return any(self._snapshot_has_material(item) for item in value.values())
        return bool(value)

    async def _discovery_coverage_metrics(self, *, scan_id: UUID, scan: Scan) -> dict[str, Any]:
        discovered_rows = await self._discovered_surface_rows(scan_id=scan_id, scan=scan)
        discovered_surface = sorted({row["endpoint"] for row in discovered_rows if row.get("endpoint")})
        source_attribution = {source: 0 for source in _DISCOVERY_SOURCES}
        for row in discovered_rows:
            source = self._normalize_discovery_source(row.get("source"))
            source_attribution[source] = source_attribution.get(source, 0) + 1

        expected_surface = self._expected_surface(scan=scan)
        if not discovered_surface:
            discovered_surface = self._configured_surface(scan=scan, keys=_DISCOVERED_SURFACE_KEYS)

        expected_set = set(expected_surface)
        discovered_set = set(discovered_surface)
        blind_spots = sorted(expected_set - discovered_set)
        if expected_set:
            coverage_pct = round((len(expected_set & discovered_set) / len(expected_set)) * 100.0, 1)
        else:
            coverage_pct = 0.0

        configured_source_counts = self._configured_source_attribution(scan=scan)
        if configured_source_counts:
            source_attribution.update(configured_source_counts)

        return {
            "label": "Discovery Coverage Metrics",
            "expected_surface_count": len(expected_surface),
            "discovered_surface_count": len(discovered_surface),
            "coverage_pct": coverage_pct,
            "blind_spot_endpoints": blind_spots,
            "source_attribution": source_attribution,
        }

    async def _discovered_surface_rows(self, *, scan_id: UUID, scan: Scan) -> list[dict[str, str]]:
        rows: list[dict[str, str]] = []
        asset_map = getattr(scan, "asset_map", None)
        endpoints = getattr(asset_map, "endpoints", None)
        if isinstance(endpoints, list):
            for endpoint in endpoints:
                endpoint_label = self._normalize_endpoint_label(getattr(endpoint, "url_pattern", ""))
                if not endpoint_label:
                    continue
                rows.append(
                    {
                        "endpoint": endpoint_label,
                        "source": self._normalize_discovery_source(getattr(endpoint, "source", None)),
                    }
                )
            return rows

        try:
            result = await self._db.execute(
                select(Endpoint.url_pattern, Endpoint.source)
                .select_from(AssetMap)
                .join(Endpoint, Endpoint.asset_map_id == AssetMap.id)
                .where(AssetMap.scan_id == scan_id)
            )
        except Exception:
            return rows

        for url_pattern, source in result.all():
            endpoint_label = self._normalize_endpoint_label(url_pattern)
            if not endpoint_label:
                continue
            rows.append({"endpoint": endpoint_label, "source": self._normalize_discovery_source(source)})
        return rows

    def _expected_surface(self, *, scan: Scan) -> list[str]:
        return self._configured_surface(scan=scan, keys=_EXPECTED_SURFACE_KEYS)

    def _configured_surface(self, *, scan: Scan, keys: tuple[str, ...]) -> list[str]:
        endpoints: list[str] = []
        for container in self._scan_config_containers(scan):
            for key in keys:
                raw_value = container.get(key)
                endpoints.extend(self._normalize_endpoint_list(raw_value))
        return sorted(dict.fromkeys(endpoints))

    def _configured_source_attribution(self, *, scan: Scan) -> dict[str, int]:
        for container in self._scan_config_containers(scan):
            raw_value = container.get("source_attribution") or container.get("source_attribution_summary")
            if not isinstance(raw_value, dict):
                continue
            counts: dict[str, int] = {}
            for key, value in raw_value.items():
                source = self._normalize_discovery_source(key)
                counts[source] = self._coerce_int(value, default=0)
            return counts
        return {}

    def _scan_config_containers(self, scan: Scan) -> list[dict[str, Any]]:
        containers: list[dict[str, Any]] = []
        target = getattr(scan, "target", None)
        target_config = getattr(target, "config", None)
        if isinstance(target_config, dict):
            containers.append(target_config)
            for key in ("benchmark", "ground_truth", "discovery", "crawler"):
                nested = target_config.get(key)
                if isinstance(nested, dict):
                    containers.append(nested)
        scan_policy = getattr(scan, "policy", None)
        if isinstance(scan_policy, dict):
            containers.append(scan_policy)
        return containers

    def _normalize_endpoint_list(self, raw_value: Any) -> list[str]:
        if isinstance(raw_value, str):
            return [endpoint for endpoint in [self._normalize_endpoint_label(raw_value)] if endpoint]
        if not isinstance(raw_value, list):
            return []
        endpoints: list[str] = []
        for item in raw_value:
            endpoint = self._normalize_endpoint_label(item)
            if endpoint:
                endpoints.append(endpoint)
        return endpoints

    def _normalize_endpoint_label(self, value: Any) -> str:
        if value is None:
            return ""
        text = str(value).strip()
        if not text:
            return ""
        method_match = re.match(r"^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(.+)$", text, flags=re.IGNORECASE)
        if method_match is not None:
            text = method_match.group(2).strip()
        parsed = urlparse(text)
        if parsed.scheme and parsed.netloc:
            text = parsed.path or "/"
        if len(text) > 1:
            text = text.rstrip("/")
        try:
            from execution_plane.crawler.asset_map import normalize_url_pattern

            text = normalize_url_pattern(text)
        except Exception:
            pass
        redacted = self._redact_value(text)
        return str(redacted) if isinstance(redacted, str) else REDACTED

    def _normalize_discovery_source(self, value: Any) -> str:
        source = str(value or "crawler").strip().lower()
        aliases = {"javascript": "js", "sourcemap": "js", "open_api": "openapi", "open-api": "openapi"}
        source = aliases.get(source, source)
        return source if source in _DISCOVERY_SOURCES else "manual"

    def _scan_blind_spots(
        self,
        *,
        auth_reliability: dict[str, Any],
        discovery_coverage_metrics: dict[str, Any],
        skipped_blocked: dict[str, Any],
        scan: Scan,
    ) -> dict[str, Any]:
        identity_failures = auth_reliability.get("identity_failures")
        auth_failures = identity_failures if isinstance(identity_failures, list) else []
        discovery_gaps = discovery_coverage_metrics.get("blind_spot_endpoints")
        policy_skipped = self._policy_skipped_attack_classes(skipped_blocked)
        manual_excluded_paths = self._manual_excluded_paths(scan)
        return {
            "label": "Scan Blind Spots",
            "auth_failures": auth_failures,
            "discovery_gaps": discovery_gaps if isinstance(discovery_gaps, list) else [],
            "policy_skipped_attack_classes": policy_skipped,
            "manually_excluded_paths": manual_excluded_paths,
            "summary": {
                "auth_failure_count": len(auth_failures),
                "discovery_gap_count": len(discovery_gaps) if isinstance(discovery_gaps, list) else 0,
                "policy_skipped_attack_class_count": len(policy_skipped),
                "manually_excluded_path_count": len(manual_excluded_paths),
            },
        }

    def _policy_skipped_attack_classes(self, skipped_blocked: dict[str, Any]) -> list[dict[str, Any]]:
        skipped_details = skipped_blocked.get("skipped_details")
        if not isinstance(skipped_details, list):
            return []
        aggregated: dict[tuple[str, str], int] = {}
        for detail in skipped_details:
            if not isinstance(detail, dict):
                continue
            reason = str(detail.get("reason") or "")
            if not reason.startswith("policy:"):
                continue
            attack_class = self._safe_report_label(str(detail.get("attack_class") or "unknown"))
            key = (attack_class, self._safe_report_label(reason))
            aggregated[key] = aggregated.get(key, 0) + 1
        return [
            {"attack_class": attack_class, "reason": reason, "count": count}
            for (attack_class, reason), count in sorted(aggregated.items())
        ]

    def _manual_excluded_paths(self, scan: Scan) -> list[str]:
        paths: list[str] = []
        for container in self._scan_config_containers(scan):
            for key in _MANUAL_EXCLUDED_PATH_KEYS:
                paths.extend(self._normalize_endpoint_list(container.get(key)))
        return sorted(dict.fromkeys(paths))

    def _safe_report_label(self, value: str) -> str:
        redacted = self._redact_value(value.strip())
        if not isinstance(redacted, str):
            return REDACTED
        return self._truncate_markdown_cell(redacted.replace("|", "/"), limit=160)

    def _parse_datetime(self, value: Any) -> datetime | None:
        if isinstance(value, datetime):
            return value if value.tzinfo is not None else value.replace(tzinfo=UTC)
        if not isinstance(value, str) or not value.strip():
            return None
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
        return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)

    def _coerce_int(self, value: Any, *, default: int) -> int:
        if isinstance(value, bool):
            return int(value)
        try:
            return int(value)
        except (TypeError, ValueError):
            return default

    def _coerce_float(self, value: Any, *, default: float) -> float:
        try:
            return float(value)
        except (TypeError, ValueError):
            return default

    async def _audit_event_ids_for_finding(
        self, *, scan_id: UUID, finding_id: UUID, task_ids: set[UUID] | None = None
    ) -> list[str]:
        try:
            predicates = [AuditEvent.details["finding_id"].as_string() == str(finding_id)]
            if task_ids:
                task_id_values = [str(task_id) for task_id in task_ids]
                if task_id_values:
                    predicates.append(AuditEvent.details["task_id"].as_string().in_(task_id_values))
            result = await self._db.execute(
                select(AuditEvent.id).where(AuditEvent.scan_id == scan_id, or_(*predicates))
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
        report = self._redact_report(report)
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
        operator_sections = self._render_operator_sections(report)
        if operator_sections:
            lines.extend([operator_sections, ""])
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
            attack_chain_timeline_section = self._build_attack_chain_timeline_section(finding)
            if attack_chain_timeline_section:
                lines.extend(["", attack_chain_timeline_section])
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

    def _render_operator_sections(self, report: dict[str, Any]) -> str:
        sections: list[str] = []
        auth_reliability = report.get("auth_reliability")
        if isinstance(auth_reliability, dict):
            sections.append(self._render_auth_reliability_section(auth_reliability))

        auth_setup = report.get("auth_setup")
        if isinstance(auth_setup, dict):
            sections.append(self._render_auth_setup_section(auth_setup))

        discovery_coverage = report.get("discovery_coverage_metrics")
        if isinstance(discovery_coverage, dict):
            sections.append(self._render_discovery_coverage_section(discovery_coverage))

        scan_blind_spots = report.get("scan_blind_spots")
        if isinstance(scan_blind_spots, dict):
            sections.append(self._render_scan_blind_spots_section(scan_blind_spots))

        return "\n\n".join(section for section in sections if section)

    def _render_auth_reliability_section(self, auth_reliability: dict[str, Any]) -> str:
        failures = auth_reliability.get("identity_failures")
        failure_rows = failures if isinstance(failures, list) else []
        lines: list[str] = [
            "## Auth Reliability",
            f"- Session Valid Count: {self._coerce_int(auth_reliability.get('session_valid_count'), default=0)}",
            f"- Role Count: {self._coerce_int(auth_reliability.get('role_count'), default=0)}",
            f"- Tenant Count: {self._coerce_int(auth_reliability.get('tenant_count'), default=0)}",
            (
                "- Health Check Pass Rate: "
                f"{self._coerce_float(auth_reliability.get('health_check_pass_rate'), default=0.0):.0%}"
            ),
            "",
            "### Identity Failures",
        ]
        if not failure_rows:
            lines.append("- None recorded")
            return "\n".join(lines)

        lines.extend(["| Identity ID | Reason | Timestamp |", "|---|---|---|"])
        for failure in failure_rows:
            if not isinstance(failure, dict):
                continue
            identity_id = self._safe_report_label(str(failure.get("identity_id") or "unknown"))
            reason = self._safe_report_label(str(failure.get("reason") or "unknown"))
            timestamp = self._safe_report_label(str(failure.get("timestamp") or ""))
            lines.append(f"| {identity_id} | {reason} | {timestamp} |")
        return "\n".join(lines)

    def _render_auth_setup_section(self, auth_setup: dict[str, Any]) -> str:
        blind_spots = auth_setup.get("per_identity_blind_spots")
        blind_spot_rows = blind_spots if isinstance(blind_spots, list) else []
        warnings = auth_setup.get("auth_warnings")
        warning_rows = warnings if isinstance(warnings, list) else []
        lines: list[str] = [
            "## Auth Setup",
            (
                "- Overall Reliability Score: "
                f"{self._coerce_float(auth_setup.get('overall_reliability_score'), default=0.0):.0%}"
            ),
            f"- Preflight Status: {self._safe_report_label(str(auth_setup.get('preflight_status') or 'unknown'))}",
            f"- Clean Report Reliable: {'yes' if bool(auth_setup.get('is_clean_report_reliable')) else 'no'}",
            "",
            "### Auth Warnings",
        ]
        if warning_rows:
            lines.extend(f"- {self._safe_report_label(str(warning))}" for warning in warning_rows)
        else:
            lines.append("- None")

        lines.extend(["", "### Per-Identity Blind Spots"])
        if not blind_spot_rows:
            lines.append("- None")
            return "\n".join(lines)

        lines.extend(["| Identity | Role | Pass Rate | Blind Spots |", "|---|---|---:|---|"])
        for row in blind_spot_rows:
            if not isinstance(row, dict):
                continue
            identity = self._safe_report_label(str(row.get("identity") or "unknown"))
            role = self._safe_report_label(str(row.get("role") or "unknown"))
            pass_rate = self._coerce_float(row.get("pass_rate"), default=0.0)
            raw_spots = row.get("blind_spots")
            spots = raw_spots if isinstance(raw_spots, list) else []
            spot_text = ", ".join(self._safe_report_label(str(spot)) for spot in spots) or "-"
            lines.append(f"| {identity} | {role} | {pass_rate:.0%} | {spot_text} |")
        return "\n".join(lines)

    def _render_discovery_coverage_section(self, discovery_coverage: dict[str, Any]) -> str:
        blind_spots = discovery_coverage.get("blind_spot_endpoints")
        blind_spot_rows = blind_spots if isinstance(blind_spots, list) else []
        source_attribution = discovery_coverage.get("source_attribution")
        source_counts = source_attribution if isinstance(source_attribution, dict) else {}
        lines: list[str] = [
            "## Discovery Coverage Metrics",
            (
                "- Expected Surface Count: "
                f"{self._coerce_int(discovery_coverage.get('expected_surface_count'), default=0)}"
            ),
            (
                "- Discovered Surface Count: "
                f"{self._coerce_int(discovery_coverage.get('discovered_surface_count'), default=0)}"
            ),
            f"- Coverage: {self._coerce_float(discovery_coverage.get('coverage_pct'), default=0.0):.1f}%",
            "",
            "### Blind Spot Endpoints",
        ]
        if blind_spot_rows:
            lines.extend(f"- {self._safe_report_label(str(endpoint))}" for endpoint in blind_spot_rows)
        else:
            lines.append("- None")

        lines.extend(["", "### Source Attribution", "| Source | Endpoint Count |", "|---|---:|"])
        for source in _DISCOVERY_SOURCES:
            lines.append(f"| {source} | {self._coerce_int(source_counts.get(source), default=0)} |")
        extra_sources = sorted(set(str(source) for source in source_counts) - set(_DISCOVERY_SOURCES))
        for source in extra_sources:
            count = self._coerce_int(source_counts.get(source), default=0)
            lines.append(f"| {self._safe_report_label(source)} | {count} |")
        return "\n".join(lines)

    def _render_scan_blind_spots_section(self, scan_blind_spots: dict[str, Any]) -> str:
        auth_failures = scan_blind_spots.get("auth_failures")
        discovery_gaps = scan_blind_spots.get("discovery_gaps")
        policy_skipped = scan_blind_spots.get("policy_skipped_attack_classes")
        manual_paths = scan_blind_spots.get("manually_excluded_paths")
        auth_failure_rows = auth_failures if isinstance(auth_failures, list) else []
        discovery_gap_rows = discovery_gaps if isinstance(discovery_gaps, list) else []
        policy_rows = policy_skipped if isinstance(policy_skipped, list) else []
        manual_path_rows = manual_paths if isinstance(manual_paths, list) else []

        lines: list[str] = ["## Scan Blind Spots", "### Auth Failures That Skipped Coverage"]
        if auth_failure_rows:
            lines.extend(["| Identity ID | Reason | Timestamp |", "|---|---|---|"])
            for failure in auth_failure_rows:
                if not isinstance(failure, dict):
                    continue
                identity_id = self._safe_report_label(str(failure.get("identity_id") or "unknown"))
                reason = self._safe_report_label(str(failure.get("reason") or "unknown"))
                timestamp = self._safe_report_label(str(failure.get("timestamp") or ""))
                lines.append(f"| {identity_id} | {reason} | {timestamp} |")
        else:
            lines.append("- None recorded")

        lines.extend(["", "### Discovery Gaps"])
        if discovery_gap_rows:
            lines.extend(f"- {self._safe_report_label(str(endpoint))}" for endpoint in discovery_gap_rows)
        else:
            lines.append("- None")

        lines.extend(["", "### Policy-Skipped Attack Classes"])
        if policy_rows:
            lines.extend(["| Attack Class | Reason | Count |", "|---|---|---:|"])
            for item in policy_rows:
                if not isinstance(item, dict):
                    continue
                attack_class = self._safe_report_label(str(item.get("attack_class") or "unknown"))
                reason = self._safe_report_label(str(item.get("reason") or "unknown"))
                count = self._coerce_int(item.get("count"), default=0)
                lines.append(f"| {attack_class} | {reason} | {count} |")
        else:
            lines.append("- None")

        lines.extend(["", "### Manually Excluded Paths"])
        if manual_path_rows:
            lines.extend(f"- {self._safe_report_label(str(path))}" for path in manual_path_rows)
        else:
            lines.append("- None")
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
        output = self._redact_report(output)
        return json.dumps(output, indent=2, ensure_ascii=False)

    def _export_sarif(self, scan_data: dict[str, Any], findings: list[dict[str, Any]]) -> str:
        results: list[dict[str, Any]] = []
        for finding in findings:
            confidence_score = finding.get("confidence_score", 0.0)
            try:
                confidence_value = float(confidence_score)
            except (TypeError, ValueError):
                confidence_value = 0.0
            if confidence_value < 0.85:
                continue

            attack_class = str(finding.get("attack_class", "unknown"))
            severity = str(finding.get("severity", "")).strip().lower()
            affected_endpoint = str(finding.get("affected_endpoint") or "unknown")
            level = "note"
            if severity in ("high", "critical"):
                level = "error"
            elif severity == "medium":
                level = "warning"

            results.append(
                {
                    "ruleId": attack_class,
                    "level": level,
                    "message": {
                        "text": f"{attack_class} vulnerability detected at {affected_endpoint} with confidence {confidence_value:.2f}"
                    },
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {
                                    "uri": affected_endpoint or "unknown",
                                }
                            }
                        }
                    ],
                }
            )

        output = {
            "version": "2.1.0",
            "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "ProofScan",
                            "version": "1.0",
                            "informationUri": "https://proofscan.io",
                            "rules": [],
                        }
                    },
                    "results": results,
                }
            ],
        }
        return json.dumps(output, indent=2, ensure_ascii=False)

    def _export_html(self, scan_data: dict[str, Any], findings: list[dict[str, Any]]) -> str:
        def esc(value: Any) -> str:
            return str(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

        high_count = 0
        medium_count = 0
        low_count = 0
        for finding in findings:
            severity = str(finding.get("severity", "")).strip().lower()
            if severity in ("high", "critical"):
                high_count += 1
            elif severity == "medium":
                medium_count += 1
            elif severity == "low":
                low_count += 1

        rows: list[str] = []
        for finding in findings:
            confidence_score = finding.get("confidence_score", 0.0)
            try:
                confidence_display = f"{float(confidence_score):.2f}"
            except (TypeError, ValueError):
                confidence_display = "0.00"
            rows.append(
                "<tr>"
                f"<td>{esc(finding.get('id', ''))}</td>"
                f"<td>{esc(finding.get('severity', ''))}</td>"
                f"<td>{esc(finding.get('affected_endpoint', 'unknown'))}</td>"
                f"<td>{esc(finding.get('attack_class', 'unknown'))}</td>"
                f"<td>{esc(confidence_display)}</td>"
                "</tr>"
            )

        findings_table_rows = "".join(rows) if rows else "<tr><td colspan='5'>No findings</td></tr>"
        scan_id = esc(scan_data.get("scan_id", ""))
        target = esc(scan_data.get("target", ""))
        total_findings = len(findings)

        return (
            "<!DOCTYPE html>"
            "<html>"
            "<head>"
            "<meta charset='utf-8' />"
            "<title>ProofScan Report</title>"
            "<style>"
            "body{font-family:Arial,sans-serif;margin:24px;color:#1a1a1a;}"
            "table{border-collapse:collapse;width:100%;margin-bottom:24px;}"
            "th,td{border:1px solid #d1d5db;padding:8px;text-align:left;}"
            "th{background:#f3f4f6;}"
            "h1,h2{margin-bottom:12px;}"
            "</style>"
            "</head>"
            "<body>"
            "<h1>ProofScan Report</h1>"
            "<h2>Executive Summary</h2>"
            "<table>"
            "<tr><th>scan_id</th><th>target</th><th>total_findings</th><th>high_count</th><th>medium_count</th><th>low_count</th></tr>"
            f"<tr><td>{scan_id}</td><td>{target}</td><td>{total_findings}</td><td>{high_count}</td><td>{medium_count}</td><td>{low_count}</td></tr>"
            "</table>"
            "<h2>Findings</h2>"
            "<table>"
            "<tr><th>ID</th><th>Severity</th><th>Endpoint</th><th>Attack Class</th><th>Confidence</th></tr>"
            f"{findings_table_rows}"
            "</table>"
            "<h2>Compliance Mapping</h2>"
            "<p>Compliance mapping placeholder: map findings to applicable control frameworks.</p>"
            "</body>"
            "</html>"
        )

    async def export(
        self, scan_id: UUID, fmt: Literal["json", "markdown", "sarif", "html"] = "json"
    ) -> str:
        report = await self.assemble_report(scan_id)
        redacted_report = self._redact_report(report)
        findings = redacted_report.get("findings")
        findings_list = findings if isinstance(findings, list) else []

        if fmt == "markdown":
            return self.render_markdown(redacted_report)
        if fmt == "json":
            return self.render_json(redacted_report)
        if fmt == "sarif":
            return self._export_sarif(redacted_report, findings_list)
        if fmt == "html":
            return self._export_html(redacted_report, findings_list)
        raise ValueError(f"Unsupported export format: {fmt}")

    async def generate_executive_summary(self, scan_id: str, scan_data: dict, findings: list[dict]) -> dict:
        logger.debug("generate_executive_summary_started", scan_id=scan_id, findings_count=len(findings))
        exploitable_risk: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            confidence_score = finding.get("confidence_score")
            if confidence_score is None:
                proof_artifacts = finding.get("proof_artifacts")
                if isinstance(proof_artifacts, list):
                    confidence_score = max(
                        (
                            float(item.get("confidence_score", 0.0))
                            for item in proof_artifacts
                            if isinstance(item, dict)
                        ),
                        default=0.0,
                    )
            try:
                confidence_value = float(confidence_score)
            except (TypeError, ValueError):
                confidence_value = 0.0
            if confidence_value < 0.85:
                continue
            severity_key = str(finding.get("severity", "")).strip().lower()
            if severity_key in exploitable_risk:
                exploitable_risk[severity_key] += 1

        skipped_blocked = scan_data.get("skipped_blocked") if isinstance(scan_data, dict) else {}
        coverage_truth: list[dict[str, Any]] = []
        if isinstance(skipped_blocked, dict):
            for attack_class in skipped_blocked.get("skipped", []) or []:
                coverage_truth.append({"attack_class": str(attack_class), "status": "skipped", "reason": None})
            for item in skipped_blocked.get("blocked", []) or []:
                if isinstance(item, dict):
                    coverage_truth.append(
                        {
                            "attack_class": str(item.get("attack_class", "unknown")),
                            "status": "blocked",
                            "reason": item.get("reason"),
                        }
                    )
                else:
                    coverage_truth.append({"attack_class": str(item), "status": "blocked", "reason": None})

        seen_classes = {str(item.get("attack_class")) for item in coverage_truth if isinstance(item, dict)}
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            attack_class = str(finding.get("attack_class", "unknown"))
            if attack_class not in seen_classes:
                seen_classes.add(attack_class)
                coverage_truth.append({"attack_class": attack_class, "status": "tested", "reason": None})

        owners: dict[str, dict[str, Any]] = {}
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            metadata = finding.get("metadata")
            owner = "unassigned"
            if isinstance(metadata, dict):
                owner_annotation = metadata.get("owner")
                if isinstance(owner_annotation, str) and owner_annotation.strip():
                    owner = owner_annotation.strip()
                elif isinstance(owner_annotation, dict):
                    owner = str(
                        owner_annotation.get("team")
                        or owner_annotation.get("service")
                        or owner_annotation.get("owner")
                        or "unassigned"
                    ).strip() or "unassigned"
            endpoint = str(finding.get("affected_endpoint") or "unknown")
            bucket = owners.setdefault(owner, {"owner": owner, "finding_count": 0, "endpoints": set()})
            bucket["finding_count"] += 1
            bucket["endpoints"].add(endpoint)

        top_service_owners: list[dict[str, Any]] = []
        for owner_data in sorted(owners.values(), key=lambda item: item["finding_count"], reverse=True):
            top_service_owners.append(
                {
                    "owner": owner_data["owner"],
                    "finding_count": owner_data["finding_count"],
                    "endpoints": sorted(owner_data["endpoints"]),
                }
            )

        release_gate_status = "PASS" if (exploitable_risk["critical"] + exploitable_risk["high"]) == 0 else "BLOCK"
        summary = {
            "exploitable_risk": exploitable_risk,
            "coverage_truth": coverage_truth,
            "top_service_owners": top_service_owners,
            "release_gate_status": release_gate_status,
            "generated_at": datetime.now(UTC).isoformat(),
        }
        logger.debug("generate_executive_summary_completed", scan_id=scan_id, release_gate_status=release_gate_status)
        return summary

    async def generate_developer_report(self, scan_id: str, findings: list[dict]) -> list[dict]:
        logger.debug("generate_developer_report_started", scan_id=scan_id, findings_count=len(findings))
        fix_hints = {
            "bola": "Enforce object-level authorization checks for every resource access.",
            "idor": "Validate ownership for object identifiers on read/write operations.",
            "bfla": "Apply function-level authorization middleware before handler execution.",
            "auth_bypass": "Require authentication on this route and deny anonymous fallback paths.",
            "privilege_escalation": "Bind action permissions to verified role claims on each request.",
            "mass_assignment": "Use explicit allowlists for writable fields in request payloads.",
            "sensitive_exposure": "Remove secrets from responses and source values from secure storage.",
            "default": "Apply least-privilege validation and add a regression test for this case.",
        }

        def _redacted_headers(headers: dict[str, Any]) -> dict[str, str]:
            sanitized: dict[str, str] = {}
            for key, value in headers.items():
                key_text = str(key)
                if key_text.lower() in {"authorization", "cookie"}:
                    sanitized[key_text] = REDACTED
                else:
                    sanitized[key_text] = str(value)
            return sanitized

        def _escape_single_quotes(text: str) -> str:
            return text.replace("'", "'\"'\"'")

        report: list[dict[str, Any]] = []
        for finding in findings:
            if not isinstance(finding, dict):
                continue

            metadata = finding.get("metadata") if isinstance(finding.get("metadata"), dict) else {}
            method = str(finding.get("method") or metadata.get("method") or "GET").upper()
            path = str(finding.get("affected_endpoint") or metadata.get("endpoint_url") or metadata.get("path") or "")
            affected_endpoint = f"{method} {path}".strip()

            proof_artifacts = finding.get("proof_artifacts")
            artifact = proof_artifacts[0] if isinstance(proof_artifacts, list) and proof_artifacts else {}
            if not isinstance(artifact, dict):
                artifact = {}
            confidence_score = artifact.get("confidence_score", finding.get("confidence_score"))
            artifact_type = artifact.get("proof_type") or artifact.get("artifact_type") or "unknown"

            request_data = artifact.get("request") if isinstance(artifact.get("request"), dict) else {}
            replay: str | None = None
            if request_data:
                replay_method = str(request_data.get("method") or method).upper()
                replay_url = str(request_data.get("url") or path).strip()
                if replay_url:
                    curl_parts: list[str] = [f"curl -X {replay_method}", f"'{_escape_single_quotes(replay_url)}'"]
                    headers = request_data.get("headers")
                    if isinstance(headers, dict):
                        for key, value in _redacted_headers(headers).items():
                            header_text = f"{key}: {value}"
                            curl_parts.append(f"-H '{_escape_single_quotes(header_text)}'")
                    body = request_data.get("body")
                    if body is not None:
                        if isinstance(body, (dict, list)):
                            body_text = json.dumps(body, ensure_ascii=False)
                        else:
                            body_text = str(body)
                        curl_parts.append(f"--data '{_escape_single_quotes(body_text)}'")
                    replay = " ".join(curl_parts)

            owner = "unassigned"
            owner_annotation = metadata.get("owner")
            if isinstance(owner_annotation, str) and owner_annotation.strip():
                owner = owner_annotation.strip()
            elif isinstance(owner_annotation, dict):
                owner = str(
                    owner_annotation.get("team")
                    or owner_annotation.get("service")
                    or owner_annotation.get("owner")
                    or "unassigned"
                ).strip() or "unassigned"

            attack_class = str(finding.get("attack_class") or "unknown")
            report.append(
                {
                    "finding_id": str(finding.get("id") or finding.get("finding_id") or ""),
                    "attack_class": attack_class,
                    "severity": str(finding.get("severity") or "unknown"),
                    "affected_endpoint": affected_endpoint,
                    "proof": {
                        "confidence_score": confidence_score,
                        "artifact_type": str(artifact_type),
                    },
                    "replay": replay,
                    "owner": owner,
                    "fix_hint": fix_hints.get(attack_class, fix_hints["default"]),
                    "state_diff": metadata.get("state_diff") if isinstance(metadata.get("state_diff"), dict) else None,
                }
            )

        logger.debug("generate_developer_report_completed", scan_id=scan_id, report_count=len(report))
        return report

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

    def _get_provider_id(self, finding: Any) -> str | None:
        try:
            probe = finding.raw_probes[0] if finding.raw_probes else None
            if probe and hasattr(probe, "metadata") and isinstance(probe.metadata, dict):
                return probe.metadata.get("provider_id")
        except (AttributeError, IndexError):
            pass
        return None

    def _get_validator_strategy(self, finding: Any) -> str | None:
        try:
            if finding.proof_artifact and hasattr(finding.proof_artifact, "validator_name"):
                return finding.proof_artifact.validator_name
        except AttributeError:
            pass
        return None

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
            normalized_key = key.strip()
            if normalized_key.lower() in {"raw_secret", "secret_value", "token", "password", "bearer_token"}:
                continue
            parsed[normalized_key] = value.strip()
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
                key_text = str(key)
                if key_text == "evidence_notes":
                    output[key] = self._redact_evidence_notes(str(item))
                elif key_text in _SAFE_SECRET_METADATA_KEYS:
                    output[key] = self._redact_value(item)
                elif _SENSITIVE_KEY_PATTERN.search(key_text):
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

    def _redact_evidence_notes(self, evidence_notes: str) -> str:
        secret_assignment_pattern = (
            r"(?i)\b(raw_secret|secret_value|access[_-]?token|refresh[_-]?token|session[_-]?token|"
            r"api[_-]?key|client[_-]?secret|bearer[_-]?token|password|token)\s*=\s*[^;,\n]+"
        )
        redacted = re.sub(
            secret_assignment_pattern,
            lambda match: f"{match.group(1)}={REDACTED}",
            evidence_notes,
        )
        redacted = re.sub(r"(?i)\bbearer\s+[a-z0-9\-\._~\+/]+=*", REDACTED, redacted)
        redacted = re.sub(r"(?i)\beyJ[a-z0-9\-_]+\.[a-z0-9\-_]+(?:\.[a-z0-9\-_]+)?", REDACTED, redacted)
        return redacted

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

    def _build_attack_chain_timeline_section(self, finding: dict[str, Any]) -> str:
        timeline = finding.get("attack_chain_timeline")
        if not isinstance(timeline, list) or not timeline:
            return ""

        rows: list[str] = []
        for item in timeline:
            if not isinstance(item, dict):
                continue
            step = self._truncate_markdown_cell(str(item.get("step") or "-"), limit=16)
            task_id = self._truncate_markdown_cell(str(item.get("task_id") or "-"), limit=36)
            attack_class = self._truncate_markdown_cell(str(item.get("attack_class") or "-"), limit=32)
            endpoint_id = self._truncate_markdown_cell(str(item.get("endpoint_id") or "-"), limit=36)
            replan_reason = self._truncate_markdown_cell(str(item.get("replan_reason") or "-"), limit=36)
            timestamp = self._truncate_markdown_cell(str(item.get("timestamp") or "-"), limit=40)
            rows.append(f"| {step} | {task_id} | {attack_class} | {endpoint_id} | {replan_reason} | {timestamp} |")

        if not rows:
            return ""
        return "\n".join(
            [
                "### Attack Chain Timeline",
                "| Step | Task ID | Attack Class | Endpoint ID | Replan Reason | Timestamp |",
                "|---|---|---|---|---|---|",
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


def generate_authorization_pack(
    scan_id: str,
    policy: ScanPolicyV2,
    contact_email: str | None = None,
    base_url: str = "",
) -> AuthorizationPackResponse:
    """Generates a compliance artifact for enterprise buyers showing what will be tested."""
    return AuthorizationPackResponse(
        scan_id=scan_id,
        policy_version=policy.version,
        scope_summary={
            "allowed_domains": list(policy.scope.allowed_domains),
            "denied_pattern_count": len(policy.scope.denied_path_patterns),
        },
        contact_email=contact_email,
        maintenance_windows=[
            {"start_hour": tw.start_hour, "end_hour": tw.end_hour, "weekdays": tw.weekdays}
            for tw in policy.time_windows
        ],
        emergency_stop_url=f"{base_url}/scans/{scan_id}/kill",
        generated_at=datetime.now(UTC),
        policy_json=policy.model_dump(),
    )


def authorization_pack_section(scan_id: str, policy: ScanPolicyV2 | None, contact_email: str | None = None) -> dict:
    """Returns authorization pack dict for inclusion in assembled report, or empty dict if no policy."""
    if policy is None:
        return {}
    pack = generate_authorization_pack(scan_id, policy, contact_email)
    return {"authorization_pack": pack.model_dump(mode="json")}


def generate_coverage_report(scan_id: str, endpoint_statuses: list[dict]) -> dict:
    by_status: dict[str, int] = {}
    per_endpoint: dict[str, dict[str, Any]] = {}

    for item in endpoint_statuses:
        status = str(item.get("status", "unknown"))
        by_status[status] = by_status.get(status, 0) + 1

        endpoint_pattern = str(item.get("endpoint_pattern", ""))
        method = str(item.get("method", "")).upper()
        endpoint_key = f"{method} {endpoint_pattern}"
        per_endpoint[endpoint_key] = {
            "status": status,
            "tested_classes": list(item.get("tested_classes", [])),
            "finding_count": int(item.get("finding_count", 0)),
        }

    return {
        "scan_id": scan_id,
        "total_endpoints": len(endpoint_statuses),
        "by_status": by_status,
        "per_endpoint": per_endpoint,
    }


def compute_attack_class_readiness(service_coverage: dict[str, dict]) -> dict[str, dict]:
    readiness: dict[str, dict] = {}

    for service, item in service_coverage.items():
        tested = int(item.get("tested", 0))
        discovered = int(item.get("discovered", 0))
        auth_discovery = (tested / discovered) if discovered > 0 else 0.0
        identity_tests = 1.0 if bool(item.get("identity_tested")) else 0.0
        stateful_proof = 1.0 if bool(item.get("stateful_proof_tested")) else 0.0
        overall = (auth_discovery + identity_tests + stateful_proof) / 3.0

        readiness[service] = {
            "auth_discovery": auth_discovery,
            "identity_tests": identity_tests,
            "stateful_proof": stateful_proof,
            "overall": overall,
        }

    return readiness
