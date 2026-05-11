from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field


class ScanResponse(BaseModel):
    id: str
    status: str
    phase: str
    created_at: datetime


class ScanEventResponse(BaseModel):
    timestamp: datetime
    level: str
    source: str
    message: str
    details: dict[str, object] = Field(default_factory=dict)


class KillChainStep(BaseModel):
    phase: Literal["entry", "pivot", "exploit", "impact"]
    description: str
    endpoint: str
    evidence_ref: str


class FindingResponse(BaseModel):
    id: str
    title: str
    severity: str
    attack_class: str
    affected_endpoint: str
    kill_chain: list[KillChainStep] = Field(default_factory=list)


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
