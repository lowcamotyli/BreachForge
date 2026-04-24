"""storage contract: move raw probe payloads to S3 metadata references

Revision ID: 20260420193000
Revises: 20260420184641
Create Date: 2026-04-20 19:30:00
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "20260420193000"
down_revision = "20260420184641"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("raw_probes", sa.Column("request_s3_key", sa.String(length=1024), nullable=True))
    op.add_column("raw_probes", sa.Column("request_content_type", sa.String(length=255), nullable=True))
    op.add_column("raw_probes", sa.Column("request_size_bytes", sa.Integer(), nullable=True))
    op.add_column("raw_probes", sa.Column("response_s3_key", sa.String(length=1024), nullable=True))
    op.add_column("raw_probes", sa.Column("response_content_type", sa.String(length=255), nullable=True))
    op.add_column("raw_probes", sa.Column("response_size_bytes", sa.Integer(), nullable=True))

    op.execute(
        """
        UPDATE raw_probes
        SET
            request_s3_key = 'legacy/raw_probes/' || id::text || '/request.json',
            request_content_type = 'application/json',
            request_size_bytes = GREATEST(octet_length(COALESCE(request::text, '')), 0),
            response_s3_key = 'legacy/raw_probes/' || id::text || '/response.json',
            response_content_type = 'application/json',
            response_size_bytes = GREATEST(octet_length(COALESCE(response::text, '')), 0)
        """
    )

    op.alter_column("raw_probes", "request_s3_key", nullable=False)
    op.alter_column("raw_probes", "request_content_type", nullable=False)
    op.alter_column("raw_probes", "request_size_bytes", nullable=False)
    op.alter_column("raw_probes", "response_s3_key", nullable=False)
    op.alter_column("raw_probes", "response_content_type", nullable=False)
    op.alter_column("raw_probes", "response_size_bytes", nullable=False)

    op.drop_column("raw_probes", "request")
    op.drop_column("raw_probes", "response")


def downgrade() -> None:
    op.add_column("raw_probes", sa.Column("request", sa.JSON(), nullable=True))
    op.add_column("raw_probes", sa.Column("response", sa.JSON(), nullable=True))

    op.execute(
        """
        UPDATE raw_probes
        SET
            request = json_build_object(
                's3_key', request_s3_key,
                'content_type', request_content_type,
                'size_bytes', request_size_bytes
            ),
            response = json_build_object(
                's3_key', response_s3_key,
                'content_type', response_content_type,
                'size_bytes', response_size_bytes
            )
        """
    )

    op.alter_column("raw_probes", "request", nullable=False)
    op.alter_column("raw_probes", "response", nullable=False)

    op.drop_column("raw_probes", "request_size_bytes")
    op.drop_column("raw_probes", "request_content_type")
    op.drop_column("raw_probes", "request_s3_key")
    op.drop_column("raw_probes", "response_size_bytes")
    op.drop_column("raw_probes", "response_content_type")
    op.drop_column("raw_probes", "response_s3_key")
