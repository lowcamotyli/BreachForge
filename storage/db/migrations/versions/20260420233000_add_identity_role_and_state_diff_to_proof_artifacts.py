"""add identity role and state diff to proof artifacts

Revision ID: 20260420233000
Revises: 20260420220000
Create Date: 2026-04-20 23:30:00
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "20260420233000"
down_revision = "20260420220000"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("proof_artifacts", sa.Column("identity_role", sa.String(length=64), nullable=True))
    op.add_column("proof_artifacts", sa.Column("state_diff", sa.JSON(), nullable=True))


def downgrade() -> None:
    op.drop_column("proof_artifacts", "state_diff")
    op.drop_column("proof_artifacts", "identity_role")
