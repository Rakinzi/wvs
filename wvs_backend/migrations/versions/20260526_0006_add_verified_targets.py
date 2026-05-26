"""add verified targets

Revision ID: 20260526_0006
Revises: 20260522_0005
Create Date: 2026-05-26 10:30:00
"""

from alembic import op
import sqlalchemy as sa


revision = "20260526_0006"
down_revision = "20260522_0005"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "verified_target",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("public_id", sa.String(length=36), nullable=False),
        sa.Column("target_url", sa.String(length=500), nullable=False),
        sa.Column("normalized_domain", sa.String(length=255), nullable=False),
        sa.Column("verification_method", sa.String(length=50), nullable=False),
        sa.Column("verification_token_hash", sa.String(length=64), nullable=False),
        sa.Column("verification_status", sa.String(length=30), nullable=False),
        sa.Column("verified_at", sa.DateTime(), nullable=True),
        sa.Column("token_expires_at", sa.DateTime(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["user.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("public_id"),
    )
    op.create_index(op.f("ix_verified_target_normalized_domain"), "verified_target", ["normalized_domain"], unique=False)
    op.create_index(op.f("ix_verified_target_public_id"), "verified_target", ["public_id"], unique=True)
    op.create_index(op.f("ix_verified_target_verification_status"), "verified_target", ["verification_status"], unique=False)
    op.create_index(op.f("ix_verified_target_verification_token_hash"), "verified_target", ["verification_token_hash"], unique=False)


def downgrade():
    op.drop_index(op.f("ix_verified_target_verification_token_hash"), table_name="verified_target")
    op.drop_index(op.f("ix_verified_target_verification_status"), table_name="verified_target")
    op.drop_index(op.f("ix_verified_target_public_id"), table_name="verified_target")
    op.drop_index(op.f("ix_verified_target_normalized_domain"), table_name="verified_target")
    op.drop_table("verified_target")
