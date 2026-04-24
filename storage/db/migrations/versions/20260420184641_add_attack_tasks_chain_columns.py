"""add chain ordering columns to attack_tasks

Revision ID: 20260420184641
Revises: 20260420160042
Create Date: 2026-04-20 18:46:41
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "20260420184641"
down_revision = "20260420160042"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("attack_tasks", sa.Column("prerequisites", sa.JSON(), nullable=True))
    op.add_column("attack_tasks", sa.Column("step_order", sa.Integer(), nullable=True))


def downgrade() -> None:
    op.drop_column("attack_tasks", "step_order")
    op.drop_column("attack_tasks", "prerequisites")
