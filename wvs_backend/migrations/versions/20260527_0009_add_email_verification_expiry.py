"""add verification_token_expires_at to user

Revision ID: 20260527_0009
Revises: 20260527_0008
Create Date: 2026-05-27 00:00:00
"""

from alembic import op
import sqlalchemy as sa


revision = "20260527_0009"
down_revision = "20260527_0008"
branch_labels = None
depends_on = None


def upgrade():
    conn = op.get_bind()
    cols = [row[0] for row in conn.execute(sa.text("SHOW COLUMNS FROM user")).fetchall()]
    if 'verification_token_expires_at' not in cols:
        op.add_column("user", sa.Column("verification_token_expires_at", sa.DateTime(), nullable=True))


def downgrade():
    op.drop_column("user", "verification_token_expires_at")
