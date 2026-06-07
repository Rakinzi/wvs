"""add scan_job user created_at index

Revision ID: 20260603_0012
Revises: 20260603_0011
Create Date: 2026-06-03 10:05:00.000000
"""

from alembic import op
import sqlalchemy as sa


revision = "20260603_0012"
down_revision = "20260603_0011"
branch_labels = None
depends_on = None


def _index_exists(name: str) -> bool:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    return any(index["name"] == name for index in inspector.get_indexes("scan_job"))


def upgrade():
    if not _index_exists("ix_scan_job_user_created_at"):
        op.create_index(
            "ix_scan_job_user_created_at",
            "scan_job",
            ["user_id", "created_at"],
            unique=False,
        )


def downgrade():
    if _index_exists("ix_scan_job_user_created_at"):
        op.drop_index("ix_scan_job_user_created_at", table_name="scan_job")
