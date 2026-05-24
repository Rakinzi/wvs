"""add password reset fields

Revision ID: 20260521_0002
Revises: 20260521_0001
Create Date: 2026-05-21 12:55:00
"""

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "20260521_0002"
down_revision = "20260521_0001"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("user", sa.Column("reset_token_hash", sa.String(length=64), nullable=True))
    op.add_column("user", sa.Column("reset_token_expires_at", sa.DateTime(), nullable=True))
    op.add_column("user", sa.Column("reset_requested_at", sa.DateTime(), nullable=True))
    op.create_index(op.f("ix_user_reset_token_hash"), "user", ["reset_token_hash"], unique=False)


def downgrade():
    op.drop_index(op.f("ix_user_reset_token_hash"), table_name="user")
    op.drop_column("user", "reset_requested_at")
    op.drop_column("user", "reset_token_expires_at")
    op.drop_column("user", "reset_token_hash")
