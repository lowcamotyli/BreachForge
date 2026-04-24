"""align scan status lifecycle semantics

Revision ID: 20260420160042
Revises: 001_initial
Create Date: 2026-04-20 16:00:42
"""

from __future__ import annotations

from alembic import op


revision = "20260420160042"
down_revision = "001_initial"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("UPDATE scans SET status = 'created' WHERE status = 'pending'")
    op.execute(
        "UPDATE scans SET status = 'running' WHERE status IN ('crawling', 'attacking', 'validating', 'scoring')"
    )
    op.execute("UPDATE scans SET status = 'complete' WHERE status = 'done'")

    op.execute("ALTER TABLE scans DROP CONSTRAINT IF EXISTS scan_status")
    op.execute("ALTER TABLE scans DROP CONSTRAINT IF EXISTS ck_scans_status")
    op.execute(
        "ALTER TABLE scans ADD CONSTRAINT scan_status CHECK (status IN ('created', 'running', 'paused', 'complete', 'failed'))"
    )


def downgrade() -> None:
    raise NotImplementedError("Irreversible migration: lifecycle status normalization is lossy")
