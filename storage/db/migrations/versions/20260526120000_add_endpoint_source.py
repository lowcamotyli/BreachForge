"""add source column to endpoints

Revision ID: 20260526120000
Revises: 20260511000000
Create Date: 2026-05-26 12:00:00
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "20260526120000"
down_revision = "20260511000000"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("endpoints", sa.Column("source", sa.String(length=32), nullable=False, server_default="crawler"))


def downgrade() -> None:
    op.drop_column("endpoints", "source")
