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
