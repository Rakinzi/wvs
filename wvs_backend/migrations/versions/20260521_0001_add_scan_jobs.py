"""add scan jobs

Revision ID: 20260521_0001
Revises:
Create Date: 2026-05-21 11:35:00
"""

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '20260521_0001'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'scan_job',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('url', sa.String(length=500), nullable=False),
        sa.Column('scan_type', sa.String(length=50), nullable=False),
        sa.Column('status', sa.String(length=30), nullable=False),
        sa.Column('task_id', sa.String(length=100), nullable=True),
        sa.Column('findings', sa.JSON(), nullable=True),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.Column('started_at', sa.DateTime(), nullable=True),
        sa.Column('completed_at', sa.DateTime(), nullable=True),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('result_id', sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(['result_id'], ['scan_result.id']),
        sa.ForeignKeyConstraint(['user_id'], ['user.id']),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('task_id'),
    )
    op.create_index(op.f('ix_scan_job_status'), 'scan_job', ['status'], unique=False)


def downgrade():
    op.drop_index(op.f('ix_scan_job_status'), table_name='scan_job')
    op.drop_table('scan_job')
