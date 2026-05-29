from __future__ import annotations

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, Field


class ScanResponse(BaseModel):
    id: str
    status: str
    phase: str
    created_at: datetime
    warnings: list[dict[str, object]] = Field(default_factory=list)


class ScanEventResponse(BaseModel):
    timestamp: datetime
    level: str
    source: str
    message: str
    details: dict[str, object] = Field(default_factory=dict)


class ScanReadinessCheck(BaseModel):
    check_name: str
    passed: bool
    blocking: bool
    message: str


class ScanReadinessResponse(BaseModel):
    overall_ready: bool
    checks: list[ScanReadinessCheck] = Field(default_factory=list)
    blocking_issues: list[str] = Field(default_factory=list)


class AuthReadinessResponse(BaseModel):
    readiness_score: float = Field(ge=0.0, le=1.0)
    status: Literal["ok", "degraded", "failed"]
    failing_probes: list[str] = Field(default_factory=list)
    redacted_evidence: dict[str, object] = Field(default_factory=dict)
    recommended_fix: str
    checked_at: datetime


class KillChainStep(BaseModel):
    phase: Literal["entry", "pivot", "exploit", "impact"]
    description: str
    endpoint: str
    evidence_ref: str


class OwnerInfo(BaseModel):
    team: str
    service: str
    confidence: float
    source: str


class FindingResponse(BaseModel):
    id: str
    title: str
    severity: str
    attack_class: str
    affected_endpoint: str
    owner: OwnerInfo | None = None
    kill_chain: list[KillChainStep] = Field(default_factory=list)


class SuppressionResponse(BaseModel):
    id: UUID
    finding_id: UUID
    suppression_type: str
    reason: str
    approved_by: str
    expires_at: datetime | None
    is_active: bool
    created_at: datetime


class ReportResponse(BaseModel):
    scan_id: str
    findings: list[FindingResponse]
    generated_at: datetime


class SecretProperty(BaseModel):
    secret_type: str | None = None
    secret_fingerprint: str | None = None
    ttl_bucket: str | None = None
    active_during_scan: str | None = None


class PrivilegeSummary(BaseModel):
    observed_access_level: str | None = None
    inferred_level: str | None = None
    confidence: float | None = None


class SecretExposureEvidencePack(BaseModel):
    secret_properties: SecretProperty | None = None
    blast_radius: dict[str, object] | None = None
    privilege_fingerprint: PrivilegeSummary | None = None
    lifecycle: dict[str, object] | None = None
    severity_factors: list[dict[str, object]] = Field(default_factory=list)
    leak_source: dict[str, object] | None = None
    remediation_priority: str | None = None


class AttackChainStep(BaseModel):
    phase: Literal["entry", "pivot", "exploit", "impact"]
    description: str
    endpoint: str
    evidence_ref: str
    confidence: float


class AttackChainScoreFactors(BaseModel):
    impact: float
    reachability: float
    privilege: float
    repeatability: float
    blast_radius: float
    safety_confidence: float
    total: float


class AttackChain(BaseModel):
    id: str
    root_cause_id: str
    steps: list[AttackChainStep]
    identities: list[str] = Field(default_factory=list)
    evidence_refs: list[str] = Field(default_factory=list)
    chain_confidence: float
    severity: str
    severity_explanation: str
    score_factors: AttackChainScoreFactors
    remediation: str


class AttackChainReportResponse(BaseModel):
    scan_id: str
    chains: list[AttackChain]
    findings: list[FindingResponse]
    generated_at: datetime


class PolicyPreflightResponse(BaseModel):
    will_test: list[dict]
    will_skip: list[dict]
    will_block: list[dict]
    total_endpoints: int
    blocked_count: int


class AuthorizationPackResponse(BaseModel):
    scan_id: str
    policy_version: str
    scope_summary: dict  # {"allowed_domains": list[str], "denied_pattern_count": int}
    contact_email: str | None
    maintenance_windows: list[dict]  # [{"start_hour": int, "end_hour": int, "weekdays": list[int]}]
    emergency_stop_url: str  # e.g. "/scans/{scan_id}/kill"
    generated_at: datetime
    policy_json: dict  # full serialized ScanPolicyV2


class InventoryEndpointResponse(BaseModel):
    endpoint_id: str
    pattern: str
    method: str
    sources: list[str] = Field(default_factory=list)
    owner_team: str = "unknown"
    owner_confidence: float = 0.0
    finding_count: int = 0
    status: str = "unknown"


class InventoryServiceResponse(BaseModel):
    service: str
    endpoint_count: int = 0
    owner_team: str = "unknown"
    attack_class_readiness: dict[str, float] = Field(default_factory=dict)


class DriftItemResponse(BaseModel):
    endpoint_pattern: str
    drift_type: Literal["runtime_no_owner", "repo_not_deployed", "stale_version"]
    detail: str = ""
