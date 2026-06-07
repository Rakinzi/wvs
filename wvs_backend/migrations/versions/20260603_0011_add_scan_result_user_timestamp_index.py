"""add scan_result user timestamp index

Revision ID: 20260603_0011
Revises: 121b8e2a79a5
Create Date: 2026-06-03 09:35:00.000000
"""

from alembic import op
import sqlalchemy as sa


revision = "20260603_0011"
down_revision = "121b8e2a79a5"
branch_labels = None
depends_on = None


def _index_exists(name: str) -> bool:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    return any(index["name"] == name for index in inspector.get_indexes("scan_result"))


def upgrade():
    if not _index_exists("ix_scan_result_user_timestamp"):
        op.create_index(
            "ix_scan_result_user_timestamp",
            "scan_result",
            ["user_id", "timestamp"],
            unique=False,
        )


def downgrade():
    if _index_exists("ix_scan_result_user_timestamp"):
        op.drop_index("ix_scan_result_user_timestamp", table_name="scan_result")
