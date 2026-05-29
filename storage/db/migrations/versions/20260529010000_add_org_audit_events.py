"""add org audit events

Revision ID: 20260529010000
Revises: 20260529000000
Create Date: 2026-05-29 01:00:00
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "20260529010000"
down_revision = "20260529000000"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "org_audit_events",
        sa.Column("id", postgresql.UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("org_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("event_type", sa.String(), nullable=False),
        sa.Column("actor_email", sa.String(length=255), nullable=True),
        sa.Column("resource_type", sa.String(length=128), nullable=True),
        sa.Column("resource_id", sa.String(length=255), nullable=True),
        sa.Column("details", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_org_audit_events_org_id", "org_audit_events", ["org_id"], unique=False)
    op.create_index(
        "ix_org_audit_events_org_id_created_at",
        "org_audit_events",
        ["org_id", "created_at"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_table("org_audit_events")
