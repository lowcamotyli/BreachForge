"""initial schema

Revision ID: 001_initial
Revises:
Create Date: 2026-04-18 00:00:00
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "001_initial"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "targets",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("url", sa.String(length=2048), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("config", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )

    op.create_table(
        "scans",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("target_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("auth_context_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column(
            "status",
            sa.Enum(
                "pending",
                "crawling",
                "attacking",
                "validating",
                "scoring",
                "done",
                "failed",
                name="scan_status",
                native_enum=False,
            ),
            nullable=False,
        ),
        sa.Column("phase", sa.String(length=32), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["target_id"], ["targets.id"]),
        sa.PrimaryKeyConstraint("id"),
    )

    op.create_table(
        "auth_contexts",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("scan_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("type", sa.String(length=32), nullable=False),
        sa.Column("session_snapshot", sa.JSON(), nullable=False),
        sa.Column("health", sa.JSON(), nullable=False),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("scan_id"),
    )

    op.create_foreign_key(
        "fk_scans_auth_context_id_auth_contexts",
        "scans",
        "auth_contexts",
        ["auth_context_id"],
        ["id"],
    )

    op.create_table(
        "asset_maps",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("scan_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("scan_id"),
    )

    op.create_table(
        "endpoints",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("asset_map_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("url_pattern", sa.String(length=2048), nullable=False),
        sa.Column("method", sa.String(length=16), nullable=False),
        sa.Column("auth_required", sa.Boolean(), nullable=False),
        sa.Column("parameters", sa.JSON(), nullable=False),
        sa.Column("observed_content_type", sa.String(length=255), nullable=True),
        sa.Column("example_response_code", sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(["asset_map_id"], ["asset_maps.id"]),
        sa.PrimaryKeyConstraint("id"),
    )

    op.create_table(
        "attack_tasks",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("scan_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("endpoint_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("attack_class", sa.String(length=64), nullable=False),
        sa.Column("target_parameter", sa.String(length=255), nullable=True),
        sa.Column("hypothesis", sa.Text(), nullable=False),
        sa.Column("priority_score", sa.Float(), nullable=False),
        sa.Column(
            "status",
            sa.Enum("pending", "running", "done", "failed", name="attack_task_status", native_enum=False),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["endpoint_id"], ["endpoints.id"]),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"]),
        sa.PrimaryKeyConstraint("id"),
    )

    op.create_table(
        "raw_probes",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("attack_task_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("worker_id", sa.String(length=255), nullable=False),
        sa.Column("timestamp", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("request", sa.JSON(), nullable=False),
        sa.Column("response", sa.JSON(), nullable=False),
        sa.Column("control_probe_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.ForeignKeyConstraint(["attack_task_id"], ["attack_tasks.id"]),
        sa.ForeignKeyConstraint(["control_probe_id"], ["raw_probes.id"]),
        sa.PrimaryKeyConstraint("id"),
    )

    op.create_table(
        "findings",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("scan_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column(
            "severity",
            sa.Enum("critical", "high", "medium", "info", name="finding_severity", native_enum=False),
            nullable=False,
        ),
        sa.Column("attack_class", sa.String(length=64), nullable=False),
        sa.Column("affected_endpoint_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("repro_steps", sa.Text(), nullable=False),
        sa.Column("fix_guidance", sa.Text(), nullable=False),
        sa.Column("deduplicated_from", postgresql.UUID(as_uuid=True), nullable=True),
        sa.ForeignKeyConstraint(["affected_endpoint_id"], ["endpoints.id"]),
        sa.ForeignKeyConstraint(["deduplicated_from"], ["findings.id"]),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"]),
        sa.PrimaryKeyConstraint("id"),
    )

    op.create_table(
        "proof_artifacts",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("attack_task_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("finding_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("proof_type", sa.String(length=32), nullable=False),
        sa.Column("confidence_score", sa.Float(), nullable=False),
        sa.Column("attack_probe_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("control_probe_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("evidence_notes", sa.Text(), nullable=False),
        sa.ForeignKeyConstraint(["attack_probe_id"], ["raw_probes.id"]),
        sa.ForeignKeyConstraint(["attack_task_id"], ["attack_tasks.id"]),
        sa.ForeignKeyConstraint(["control_probe_id"], ["raw_probes.id"]),
        sa.ForeignKeyConstraint(["finding_id"], ["findings.id"]),
        sa.PrimaryKeyConstraint("id"),
    )

    op.create_table(
        "attack_paths",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("scan_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("steps", sa.JSON(), nullable=False),
        sa.Column("entry_point", sa.String(length=2048), nullable=False),
        sa.Column("impact_description", sa.Text(), nullable=False),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"]),
        sa.PrimaryKeyConstraint("id"),
    )

    op.create_index("ix_scans_target_id", "scans", ["target_id"], unique=False)
    op.create_index("ix_scans_auth_context_id", "scans", ["auth_context_id"], unique=False)
    op.create_index("ix_auth_contexts_scan_id", "auth_contexts", ["scan_id"], unique=True)
    op.create_index("ix_asset_maps_scan_id", "asset_maps", ["scan_id"], unique=True)
    op.create_index("ix_endpoints_asset_map_id", "endpoints", ["asset_map_id"], unique=False)
    op.create_index("ix_attack_tasks_scan_id", "attack_tasks", ["scan_id"], unique=False)
    op.create_index("ix_attack_tasks_endpoint_id", "attack_tasks", ["endpoint_id"], unique=False)
    op.create_index("ix_raw_probes_attack_task_id", "raw_probes", ["attack_task_id"], unique=False)
    op.create_index("ix_raw_probes_control_probe_id", "raw_probes", ["control_probe_id"], unique=False)
    op.create_index("ix_findings_scan_id", "findings", ["scan_id"], unique=False)
    op.create_index("ix_findings_affected_endpoint_id", "findings", ["affected_endpoint_id"], unique=False)
    op.create_index("ix_findings_deduplicated_from", "findings", ["deduplicated_from"], unique=False)
    op.create_index("ix_proof_artifacts_attack_task_id", "proof_artifacts", ["attack_task_id"], unique=False)
    op.create_index("ix_proof_artifacts_finding_id", "proof_artifacts", ["finding_id"], unique=False)
    op.create_index("ix_proof_artifacts_attack_probe_id", "proof_artifacts", ["attack_probe_id"], unique=False)
    op.create_index("ix_proof_artifacts_control_probe_id", "proof_artifacts", ["control_probe_id"], unique=False)
    op.create_index("ix_attack_paths_scan_id", "attack_paths", ["scan_id"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_attack_paths_scan_id", table_name="attack_paths")
    op.drop_index("ix_proof_artifacts_control_probe_id", table_name="proof_artifacts")
    op.drop_index("ix_proof_artifacts_attack_probe_id", table_name="proof_artifacts")
    op.drop_index("ix_proof_artifacts_finding_id", table_name="proof_artifacts")
    op.drop_index("ix_proof_artifacts_attack_task_id", table_name="proof_artifacts")
    op.drop_index("ix_findings_deduplicated_from", table_name="findings")
    op.drop_index("ix_findings_affected_endpoint_id", table_name="findings")
    op.drop_index("ix_findings_scan_id", table_name="findings")
    op.drop_index("ix_raw_probes_control_probe_id", table_name="raw_probes")
    op.drop_index("ix_raw_probes_attack_task_id", table_name="raw_probes")
    op.drop_index("ix_attack_tasks_endpoint_id", table_name="attack_tasks")
    op.drop_index("ix_attack_tasks_scan_id", table_name="attack_tasks")
    op.drop_index("ix_endpoints_asset_map_id", table_name="endpoints")
    op.drop_index("ix_asset_maps_scan_id", table_name="asset_maps")
    op.drop_index("ix_auth_contexts_scan_id", table_name="auth_contexts")
    op.drop_index("ix_scans_auth_context_id", table_name="scans")
    op.drop_index("ix_scans_target_id", table_name="scans")

    op.drop_table("attack_paths")
    op.drop_table("proof_artifacts")
    op.drop_table("findings")
    op.drop_table("raw_probes")
    op.drop_table("attack_tasks")
    op.drop_table("endpoints")
    op.drop_table("asset_maps")
    op.drop_constraint("fk_scans_auth_context_id_auth_contexts", "scans", type_="foreignkey")
    op.drop_table("auth_contexts")
    op.drop_table("scans")
    op.drop_table("targets")

    sa.Enum(name="finding_severity").drop(op.get_bind(), checkfirst=True)
    sa.Enum(name="attack_task_status").drop(op.get_bind(), checkfirst=True)
    sa.Enum(name="scan_status").drop(op.get_bind(), checkfirst=True)
