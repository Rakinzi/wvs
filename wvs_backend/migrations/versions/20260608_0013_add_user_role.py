"""add user role column

Revision ID: 20260608_0013
Revises: 20260603_0012
Create Date: 2026-06-08 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa


revision = "20260608_0013"
down_revision = "20260603_0012"
branch_labels = None
depends_on = None


def _column_exists(table: str, column: str) -> bool:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    return any(c["name"] == column for c in inspector.get_columns(table))


def upgrade():
    bind = op.get_bind()
    if not _column_exists("user", "role"):
        op.add_column(
            "user",
            sa.Column("role", sa.String(20), nullable=False, server_default="free"),
        )
        op.create_index("ix_user_role", "user", ["role"], unique=False)

    table_name = "`user`" if bind.dialect.name == "mysql" else '"user"'
    try:
        bind.execute(sa.text(f"UPDATE {table_name} SET role = 'admin' WHERE is_admin = TRUE AND role = 'free'"))
    except Exception:
        # is_admin column may not exist if dropped; skip gracefully
        pass


def downgrade():
    if _column_exists("user", "role"):
        op.drop_index("ix_user_role", table_name="user")
        op.drop_column("user", "role")
