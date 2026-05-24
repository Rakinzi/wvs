"""add email verification fields

Revision ID: 20260522_0003
Revises: 20260521_0002
Create Date: 2026-05-22 00:00:00
"""

from alembic import op
import sqlalchemy as sa


revision = "20260522_0003"
down_revision = "20260521_0002"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("user", sa.Column("email_verified", sa.Boolean(), nullable=False, server_default=sa.false()))
    op.add_column("user", sa.Column("verification_token_hash", sa.String(length=64), nullable=True))
    op.create_index(op.f("ix_user_verification_token_hash"), "user", ["verification_token_hash"], unique=False)


def downgrade():
    op.drop_index(op.f("ix_user_verification_token_hash"), table_name="user")
    op.drop_column("user", "verification_token_hash")
    op.drop_column("user", "email_verified")
