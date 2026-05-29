from __future__ import annotations

import enum
import json
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import Boolean, DateTime, Enum, Float, ForeignKey, Integer, JSON, LargeBinary, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB, UUID as PGUUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


class Severity(str, enum.Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    info = "info"


class SuppressionType(str, enum.Enum):
    false_positive = "false_positive"
    accepted_risk = "accepted_risk"
    wont_fix = "wont_fix"


class ScanStatus(str, enum.Enum):
    created = "created"
    running = "running"
    paused = "paused"
    complete = "complete"
    failed = "failed"


class AttackTaskStatus(str, enum.Enum):
    pending = "pending"
    running = "running"
    done = "done"
    failed = "failed"


class AuditEventType(enum.StrEnum):
    SCAN_CREATED = "SCAN_CREATED"
    SCAN_STARTED = "SCAN_STARTED"
    SCAN_KILLED = "SCAN_KILLED"
    TASK_DISPATCHED = "TASK_DISPATCHED"
    TASK_SKIPPED = "TASK_SKIPPED"
    FINDING_RECORDED = "FINDING_RECORDED"
    AUTH_FAILED = "AUTH_FAILED"
    POLICY_VIOLATION = "POLICY_VIOLATION"


class Target(Base):
    __tablename__ = "targets"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    url: Mapped[str] = mapped_column(String(2048), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    config: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())

    scans: Mapped[list[Scan]] = relationship(back_populates="target", cascade="all, delete-orphan")


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    target_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), ForeignKey("targets.id"), nullable=False)
    auth_context_id: Mapped[UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("auth_contexts.id"), nullable=True
    )
    status: Mapped[ScanStatus] = mapped_column(
        Enum(ScanStatus, name="scan_status", native_enum=False), nullable=False, default=ScanStatus.created
    )
    phase: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    policy: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)

    target: Mapped[Target] = relationship(back_populates="scans")
    auth_context_ref: Mapped[AuthContext | None] = relationship(
        "AuthContext", foreign_keys=[auth_context_id], uselist=False, post_update=True
    )
    auth_context: Mapped[AuthContext | None] = relationship(
        "AuthContext", foreign_keys="AuthContext.scan_id", back_populates="scan", uselist=False
    )
    asset_map: Mapped[AssetMap | None] = relationship(back_populates="scan", uselist=False, cascade="all, delete-orphan")
    attack_tasks: Mapped[list[AttackTask]] = relationship(back_populates="scan", cascade="all, delete-orphan")
    findings: Mapped[list[Finding]] = relationship(back_populates="scan", cascade="all, delete-orphan")
    attack_paths: Mapped[list[AttackPath]] = relationship(back_populates="scan", cascade="all, delete-orphan")
    auth_bundles: Mapped[list[AuthBundle]] = relationship(back_populates="scan", cascade="all, delete-orphan")


class AuthContext(Base):
    __tablename__ = "auth_contexts"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    scan_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), ForeignKey("scans.id"), nullable=False, unique=True)
    type: Mapped[str] = mapped_column(String(32), nullable=False)
    session_snapshot: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    health: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)

    scan: Mapped[Scan] = relationship("Scan", foreign_keys=[scan_id], back_populates="auth_context")


class AuthBundle(Base):
    __tablename__ = "auth_bundles"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    scan_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), ForeignKey("scans.id"), nullable=False)
    encrypted_payload: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    identity_label: Mapped[str] = mapped_column(String(255), nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    redacted_preview: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)

    scan: Mapped[Scan] = relationship("Scan", foreign_keys=[scan_id], back_populates="auth_bundles")


class AssetMap(Base):
    __tablename__ = "asset_maps"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    scan_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), ForeignKey("scans.id"), nullable=False, unique=True)

    scan: Mapped[Scan] = relationship(back_populates="asset_map")
    endpoints: Mapped[list[Endpoint]] = relationship(back_populates="asset_map", cascade="all, delete-orphan")


class Endpoint(Base):
    __tablename__ = "endpoints"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    asset_map_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), ForeignKey("asset_maps.id"), nullable=False)
    url_pattern: Mapped[str] = mapped_column(String(2048), nullable=False)
    method: Mapped[str] = mapped_column(String(16), nullable=False)
    auth_required: Mapped[bool] = mapped_column(nullable=False, default=False)
    source: Mapped[str] = mapped_column(String(32), nullable=False, default="crawler")
    parameters: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False, default=list)
    observed_content_type: Mapped[str | None] = mapped_column(String(255), nullable=True)
    example_response_code: Mapped[int | None] = mapped_column(Integer, nullable=True)

    asset_map: Mapped[AssetMap] = relationship(back_populates="endpoints")
    attack_tasks: Mapped[list[AttackTask]] = relationship(back_populates="endpoint")
    findings: Mapped[list[Finding]] = relationship(back_populates="affected_endpoint")


class AttackTask(Base):
    __tablename__ = "attack_tasks"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    scan_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), ForeignKey("scans.id"), nullable=False)
    endpoint_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), ForeignKey("endpoints.id"), nullable=False)
    attack_class: Mapped[str] = mapped_column(String(64), nullable=False)
    target_parameter: Mapped[str | None] = mapped_column(String(255), nullable=True)
    hypothesis: Mapped[str] = mapped_column(Text, nullable=False)
    priority_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    prerequisites: Mapped[list[str] | None] = mapped_column(JSON, nullable=True, default=None)
    step_order: Mapped[int | None] = mapped_column(Integer, nullable=True, default=None)
    parent_task_id: Mapped[UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("attack_tasks.id"), nullable=True
    )
    parent_probe_id: Mapped[UUID | None] = mapped_column(PGUUID(as_uuid=True), ForeignKey("raw_probes.id"), nullable=True)
    replan_reason: Mapped[str | None] = mapped_column(String(64), nullable=True)
    status: Mapped[AttackTaskStatus] = mapped_column(
        Enum(AttackTaskStatus, name="attack_task_status", native_enum=False),
        nullable=False,
        default=AttackTaskStatus.pending,
    )

    scan: Mapped[Scan] = relationship(back_populates="attack_tasks")
    endpoint: Mapped[Endpoint] = relationship(back_populates="attack_tasks")
    parent_task: Mapped[AttackTask | None] = relationship(
        "AttackTask",
        remote_side=[id],
        back_populates="follow_up_tasks",
        foreign_keys="AttackTask.parent_task_id",
    )
    follow_up_tasks: Mapped[list[AttackTask]] = relationship(
        "AttackTask",
        back_populates="parent_task",
        foreign_keys="AttackTask.parent_task_id",
    )
    raw_probes: Mapped[list[RawProbe]] = relationship(
        back_populates="attack_task",
        cascade="all, delete-orphan",
        foreign_keys="RawProbe.attack_task_id",
    )
    proof_artifacts: Mapped[list[ProofArtifact]] = relationship(back_populates="attack_task", cascade="all, delete-orphan")


class RawProbe(Base):
    __tablename__ = "raw_probes"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    attack_task_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), ForeignKey("attack_tasks.id"), nullable=False)
    worker_id: Mapped[str] = mapped_column(String(255), nullable=False)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    request_s3_key: Mapped[str] = mapped_column(String(1024), nullable=False)
    request_content_type: Mapped[str] = mapped_column(String(255), nullable=False)
    request_size_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    response_s3_key: Mapped[str] = mapped_column(String(1024), nullable=False)
    response_content_type: Mapped[str] = mapped_column(String(255), nullable=False)
    response_size_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    control_probe_id: Mapped[UUID | None] = mapped_column(PGUUID(as_uuid=True), ForeignKey("raw_probes.id"), nullable=True)

    attack_task: Mapped[AttackTask] = relationship(
        back_populates="raw_probes",
        foreign_keys=[attack_task_id],
    )
    control_probe: Mapped[RawProbe | None] = relationship("RawProbe", remote_side=[id], back_populates="derived_probes")
    derived_probes: Mapped[list[RawProbe]] = relationship("RawProbe", back_populates="control_probe")
    proof_artifacts_as_attack: Mapped[list[ProofArtifact]] = relationship(
        "ProofArtifact", foreign_keys="ProofArtifact.attack_probe_id", back_populates="attack_probe"
    )
    proof_artifacts_as_control: Mapped[list[ProofArtifact]] = relationship(
        "ProofArtifact", foreign_keys="ProofArtifact.control_probe_id", back_populates="control_probe"
    )

    def __init__(self, **kwargs: Any) -> None:
        request_payload = kwargs.pop("request", None)
        response_payload = kwargs.pop("response", None)
        super().__init__(**kwargs)
        if request_payload is not None:
            self.request = request_payload
        if response_payload is not None:
            self.response = response_payload

    @property
    def request(self) -> dict[str, Any]:
        payload = getattr(self, "_request_payload", None)
        if isinstance(payload, dict):
            return payload
        return {
            "s3_key": self.request_s3_key,
            "content_type": self.request_content_type,
            "size_bytes": self.request_size_bytes,
        }

    @request.setter
    def request(self, value: dict[str, Any]) -> None:
        self._request_payload = value
        self.request_s3_key = str(value.get("s3_key") or "")
        self.request_content_type = str(value.get("content_type") or "application/json")
        self.request_size_bytes = int(value.get("size_bytes") or len(json.dumps(value, default=str).encode("utf-8")))

    @property
    def response(self) -> dict[str, Any]:
        payload = getattr(self, "_response_payload", None)
        if isinstance(payload, dict):
            return payload
        return {
            "s3_key": self.response_s3_key,
            "content_type": self.response_content_type,
            "size_bytes": self.response_size_bytes,
        }

    @response.setter
    def response(self, value: dict[str, Any]) -> None:
        self._response_payload = value
        self.response_s3_key = str(value.get("s3_key") or "")
        self.response_content_type = str(value.get("content_type") or "application/json")
        self.response_size_bytes = int(value.get("size_bytes") or len(json.dumps(value, default=str).encode("utf-8")))


class ProofArtifact(Base):
    __tablename__ = "proof_artifacts"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    attack_task_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), ForeignKey("attack_tasks.id"), nullable=False)
    finding_id: Mapped[UUID | None] = mapped_column(PGUUID(as_uuid=True), ForeignKey("findings.id"), nullable=True)
    proof_type: Mapped[str] = mapped_column(String(32), nullable=False)
    confidence_score: Mapped[float] = mapped_column(Float, nullable=False)
    attack_probe_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), ForeignKey("raw_probes.id"), nullable=False)
    control_probe_id: Mapped[UUID | None] = mapped_column(PGUUID(as_uuid=True), ForeignKey("raw_probes.id"), nullable=True)
    identity_role: Mapped[str | None] = mapped_column(String(64), nullable=True)
    state_diff: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    evidence_notes: Mapped[str] = mapped_column(Text, nullable=False)

    attack_task: Mapped[AttackTask] = relationship(back_populates="proof_artifacts")
    finding: Mapped[Finding | None] = relationship(back_populates="proof_artifacts")
    attack_probe: Mapped[RawProbe] = relationship(
        "RawProbe", foreign_keys=[attack_probe_id], back_populates="proof_artifacts_as_attack"
    )
    control_probe: Mapped[RawProbe | None] = relationship(
        "RawProbe", foreign_keys=[control_probe_id], back_populates="proof_artifacts_as_control"
    )


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    scan_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), ForeignKey("scans.id"), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[Severity] = mapped_column(
        Enum(Severity, name="finding_severity", native_enum=False), nullable=False
    )
    attack_class: Mapped[str] = mapped_column(String(64), nullable=False)
    affected_endpoint_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), ForeignKey("endpoints.id"), nullable=False)
    repro_steps: Mapped[str] = mapped_column(Text, nullable=False)
    fix_guidance: Mapped[str] = mapped_column(Text, nullable=False)
    extra_metadata: Mapped[dict[str, Any]] = mapped_column("metadata", JSON, nullable=False, default=dict)
    deduplicated_from: Mapped[UUID | None] = mapped_column(PGUUID(as_uuid=True), ForeignKey("findings.id"), nullable=True)

    scan: Mapped[Scan] = relationship(back_populates="findings")
    affected_endpoint: Mapped[Endpoint] = relationship(back_populates="findings")
    proof_artifacts: Mapped[list[ProofArtifact]] = relationship(back_populates="finding")
    evidence_bundles: Mapped[list[EvidenceBundle]] = relationship(
        back_populates="finding", cascade="all, delete-orphan"
    )
    suppressions: Mapped[list[Suppression]] = relationship(back_populates="finding", cascade="all, delete-orphan")
    deduplicated_parent: Mapped[Finding | None] = relationship(
        "Finding", remote_side=[id], back_populates="deduplicated_children"
    )
    deduplicated_children: Mapped[list[Finding]] = relationship("Finding", back_populates="deduplicated_parent")


class Suppression(Base):
    __tablename__ = "suppressions"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    finding_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), ForeignKey("findings.id"), nullable=False)
    proof_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    suppression_type: Mapped[SuppressionType] = mapped_column(
        Enum(SuppressionType, name="suppression_type", native_enum=False),
        nullable=False,
    )
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    approved_by: Mapped[str] = mapped_column(String(255), nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(UTC)
    )

    finding: Mapped[Finding] = relationship(back_populates="suppressions")

    @property
    def is_active(self) -> bool:
        if self.expires_at is None:
            return True

        expires_at = self.expires_at
        if expires_at.tzinfo is None or expires_at.tzinfo.utcoffset(expires_at) is None:
            expires_at = expires_at.replace(tzinfo=UTC)
        return expires_at > datetime.now(UTC)


class EvidenceBundle(Base):
    __tablename__ = "evidence_bundles"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    finding_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), ForeignKey("findings.id"), nullable=False)
    request_chain: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, nullable=False, default=list)
    control_request: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    attack_request: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    state_diff: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    identity_context: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    redacted_secrets_map: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(UTC)
    )

    finding: Mapped[Finding] = relationship(back_populates="evidence_bundles")


class AttackPath(Base):
    __tablename__ = "attack_paths"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    scan_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), ForeignKey("scans.id"), nullable=False)
    steps: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False, default=list)
    entry_point: Mapped[str] = mapped_column(String(2048), nullable=False)
    impact_description: Mapped[str] = mapped_column(Text, nullable=False)

    scan: Mapped[Scan] = relationship(back_populates="attack_paths")


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    scan_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), ForeignKey("scans.id"), nullable=False, index=True)
    event_type: Mapped[str] = mapped_column(String, nullable=False)
    entity_id: Mapped[str | None] = mapped_column(String, nullable=True)
    policy_decision: Mapped[str | None] = mapped_column(String, nullable=True)
    actor: Mapped[str | None] = mapped_column(String(255), nullable=True)
    details: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(UTC), index=True
    )


class OrgAuditEvent(Base):
    __tablename__ = "org_audit_events"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    org_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False, index=True)
    event_type: Mapped[str] = mapped_column(String(128), nullable=False)
    actor_email: Mapped[str | None] = mapped_column(String(255), nullable=True)
    resource_type: Mapped[str | None] = mapped_column(String(128), nullable=True)
    resource_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    details: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(UTC), index=True
    )


class ScanPolicyRecord(Base):
    __tablename__ = "scan_policy_records"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    scan_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), ForeignKey("scans.id"), nullable=False, unique=True)
    policy_json: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(UTC))


class OrgRole(str, enum.Enum):
    owner = "owner"
    appsec_admin = "appsec_admin"
    developer = "developer"
    auditor = "auditor"
    runner = "runner"


class Organization(Base):
    __tablename__ = "organizations"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    name: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    slug: Mapped[str] = mapped_column(String(128), nullable=False, unique=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())

    projects: Mapped[list["Project"]] = relationship(back_populates="org", cascade="all, delete-orphan")
    members: Mapped[list["OrgMember"]] = relationship(back_populates="org", cascade="all, delete-orphan")


class Project(Base):
    __tablename__ = "projects"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    org_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    slug: Mapped[str] = mapped_column(String(128), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())

    org: Mapped["Organization"] = relationship(back_populates="projects")
    service_groups: Mapped[list["ServiceGroup"]] = relationship(back_populates="project", cascade="all, delete-orphan")


class ServiceGroup(Base):
    __tablename__ = "service_groups"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    project_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), ForeignKey("projects.id"), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())

    project: Mapped["Project"] = relationship(back_populates="service_groups")


class OrgMember(Base):
    __tablename__ = "org_members"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    org_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False)
    user_email: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[OrgRole] = mapped_column(Enum(OrgRole, name="org_role", native_enum=False), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())

    org: Mapped["Organization"] = relationship(back_populates="members")


class APIKey(Base):
    __tablename__ = "api_keys"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    org_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    key_hash: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    key_prefix: Mapped[str] = mapped_column(String(12), nullable=False)
    scopes: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    created_by: Mapped[str] = mapped_column(String(255), nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())

    org: Mapped["Organization"] = relationship()


class ServiceToken(Base):
    __tablename__ = "service_tokens"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    org_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    token_hash: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    token_prefix: Mapped[str] = mapped_column(String(12), nullable=False)
    scopes: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    issued_to: Mapped[str] = mapped_column(String(255), nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())

    org: Mapped["Organization"] = relationship()


class Runner(Base):
    __tablename__ = "runners"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    org_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    token_hash: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    token_prefix: Mapped[str] = mapped_column(String(12), nullable=False)
    capabilities: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    registered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    last_heartbeat_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    is_online: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    current_job_id: Mapped[UUID | None] = mapped_column(PGUUID(as_uuid=True), nullable=True)
    version: Mapped[str] = mapped_column(String(64), nullable=False, default="1.0.0")


class Secret(Base):
    __tablename__ = "secrets"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    org_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    secret_type: Mapped[str] = mapped_column(String(64), nullable=False)
    ciphertext: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="active")
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    rotated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    redacted_preview: Mapped[str | None] = mapped_column(String(64), nullable=True)
    metadata_json: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
