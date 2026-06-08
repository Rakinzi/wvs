"""add verification_token plain column to verified_target

Revision ID: 20260527_0008
Revises: 20260526_0007_add_uptime_monitors
Create Date: 2026-05-27
"""
from alembic import op
import sqlalchemy as sa

revision = '20260527_0008'
down_revision = '20260526_0007'
branch_labels = None
depends_on = None


def upgrade():
    conn = op.get_bind()
    cols = [column["name"] for column in sa.inspect(conn).get_columns("verified_target")]
    if 'verification_token' not in cols:
        op.add_column('verified_target', sa.Column('verification_token', sa.String(128), nullable=True))


def downgrade():
    op.drop_column('verified_target', 'verification_token')
