from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel


ReportSchemaVersion = Literal["1.0"]


class ExploitableRiskSummary(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0


class CoverageTruthEntry(BaseModel):
    attack_class: str
    status: Literal["tested", "skipped", "blocked"]
    reason: str | None = None


class ServiceOwnerEntry(BaseModel):
    owner: str
    finding_count: int
    endpoints: list[str]


class ExecutiveSummaryResponse(BaseModel):
    schema_version: ReportSchemaVersion = "1.0"
    scan_id: str
    exploitable_risk: ExploitableRiskSummary
    coverage_truth: list[CoverageTruthEntry]
    top_service_owners: list[ServiceOwnerEntry]
    release_gate_status: Literal["PASS", "BLOCK"]
    generated_at: str


class ProofDetail(BaseModel):
    confidence_score: float | None = None
    artifact_type: str | None = None


class DeveloperFindingEntry(BaseModel):
    finding_id: str | None = None
    attack_class: str | None = None
    severity: str | None = None
    affected_endpoint: str | None = None
    proof: ProofDetail
    replay: str | None = None
    owner: str = "unassigned"
    fix_hint: str | None = None
    state_diff: dict[str, Any] | None = None


class DeveloperReportResponse(BaseModel):
    schema_version: ReportSchemaVersion = "1.0"
    scan_id: str
    findings: list[DeveloperFindingEntry]


class AuthReliabilityDetail(BaseModel):
    sessions_established: int = 0
    auth_failures: int = 0
    re_auth_required: int = 0
    reliability_score: float = 0.0


class EvidenceIntegrityDetail(BaseModel):
    total_findings: int = 0
    findings_with_proof: int = 0
    avg_confidence_score: float = 0.0
    evidence_hashes: dict[str, str] = {}


class AuditorReportResponse(BaseModel):
    schema_version: ReportSchemaVersion = "1.0"
    scan_id: str
    scope: dict[str, Any]
    policy_compliance: dict[str, Any]
    auth_reliability: AuthReliabilityDetail
    evidence_integrity: EvidenceIntegrityDetail
    blocked_classes: list[dict[str, str]]
    skipped_classes: list[dict[str, str]]


class ReportApiContract(BaseModel):
    schema_version: ReportSchemaVersion = "1.0"
    supported_formats: list[str] = ["json", "markdown", "sarif", "html"]
    supported_personas: list[str] = ["technical", "executive", "developer", "auditor"]
    backward_compatible_since: str = "1.0"
