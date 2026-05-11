"""add metadata column to findings

Revision ID: 20260511000000
Revises: 20260420233000
Create Date: 2026-05-11 00:00:00
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "20260511000000"
down_revision = "20260420233000"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("findings", sa.Column("metadata", sa.JSON(), nullable=False, server_default="{}"))


def downgrade() -> None:
    op.drop_column("findings", "metadata")
