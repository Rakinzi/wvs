"""add uptime monitors

Revision ID: 20260526_0007
Revises: 20260526_0006
Create Date: 2026-05-26 14:25:00.000000
"""

from alembic import op
import sqlalchemy as sa


revision = "20260526_0007"
down_revision = "20260526_0006"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "uptime_monitor",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("public_id", sa.String(length=36), nullable=False),
        sa.Column("name", sa.String(length=120), nullable=False),
        sa.Column("target_url", sa.String(length=500), nullable=False),
        sa.Column("status", sa.String(length=30), nullable=False),
        sa.Column("check_interval_minutes", sa.Integer(), nullable=False),
        sa.Column("is_enabled", sa.Boolean(), nullable=False),
        sa.Column("last_checked_at", sa.DateTime(), nullable=True),
        sa.Column("last_up_at", sa.DateTime(), nullable=True),
        sa.Column("last_response_time_ms", sa.Integer(), nullable=True),
        sa.Column("consecutive_failures", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["user.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_uptime_monitor_public_id"), "uptime_monitor", ["public_id"], unique=True)
    op.create_index(op.f("ix_uptime_monitor_status"), "uptime_monitor", ["status"], unique=False)
    op.create_index(op.f("ix_uptime_monitor_is_enabled"), "uptime_monitor", ["is_enabled"], unique=False)

    op.create_table(
        "uptime_check",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("public_id", sa.String(length=36), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("status_code", sa.Integer(), nullable=True),
        sa.Column("response_time_ms", sa.Integer(), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("checked_at", sa.DateTime(), nullable=False),
        sa.Column("monitor_id", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(["monitor_id"], ["uptime_monitor.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_uptime_check_public_id"), "uptime_check", ["public_id"], unique=True)
    op.create_index(op.f("ix_uptime_check_status"), "uptime_check", ["status"], unique=False)
    op.create_index(op.f("ix_uptime_check_checked_at"), "uptime_check", ["checked_at"], unique=False)
    op.create_index(op.f("ix_uptime_check_monitor_id"), "uptime_check", ["monitor_id"], unique=False)


def downgrade():
    op.drop_index(op.f("ix_uptime_check_monitor_id"), table_name="uptime_check")
    op.drop_index(op.f("ix_uptime_check_checked_at"), table_name="uptime_check")
    op.drop_index(op.f("ix_uptime_check_status"), table_name="uptime_check")
    op.drop_index(op.f("ix_uptime_check_public_id"), table_name="uptime_check")
    op.drop_table("uptime_check")

    op.drop_index(op.f("ix_uptime_monitor_is_enabled"), table_name="uptime_monitor")
    op.drop_index(op.f("ix_uptime_monitor_status"), table_name="uptime_monitor")
    op.drop_index(op.f("ix_uptime_monitor_public_id"), table_name="uptime_monitor")
    op.drop_table("uptime_monitor")

