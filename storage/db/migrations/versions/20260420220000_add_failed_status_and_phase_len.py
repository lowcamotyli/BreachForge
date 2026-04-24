"""add failed status and phase length

Revision ID: 20260420220000
Revises: 20260420193000
Create Date: 2026-04-20 22:00:00
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "20260420220000"
down_revision = "20260420193000"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        DO $$
        BEGIN
            IF EXISTS (
                SELECT 1
                FROM pg_type
                WHERE typname = 'scan_status'
            ) THEN
                ALTER TYPE scan_status ADD VALUE IF NOT EXISTS 'failed';
            END IF;
        END
        $$;
        """
    )
    op.alter_column(
        "scans",
        "phase",
        existing_type=sa.String(length=32),
        type_=sa.String(length=64),
        existing_nullable=True,
    )


def downgrade() -> None:
    op.alter_column(
        "scans",
        "phase",
        existing_type=sa.String(length=64),
        type_=sa.String(length=32),
        existing_nullable=True,
    )
