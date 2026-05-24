"""add public ids for scan resources

Revision ID: 20260522_0005
Revises: 20260522_0004
Create Date: 2026-05-22 01:00:00
"""

from __future__ import annotations

import uuid

from alembic import op
import sqlalchemy as sa


revision = "20260522_0005"
down_revision = "20260522_0004"
branch_labels = None
depends_on = None


scan_result_table = sa.table(
    "scan_result",
    sa.column("id", sa.Integer()),
    sa.column("public_id", sa.String(length=36)),
)

scan_job_table = sa.table(
    "scan_job",
    sa.column("id", sa.Integer()),
    sa.column("public_id", sa.String(length=36)),
)


def _populate_public_ids(bind, table) -> None:
    rows = bind.execute(sa.select(table.c.id, table.c.public_id)).fetchall()
    for row in rows:
        if not row.public_id:
            bind.execute(
                table.update().where(table.c.id == row.id).values(public_id=str(uuid.uuid4()))
            )


def upgrade():
    with op.batch_alter_table("scan_result") as batch_op:
        batch_op.add_column(sa.Column("public_id", sa.String(length=36), nullable=True))
    with op.batch_alter_table("scan_job") as batch_op:
        batch_op.add_column(sa.Column("public_id", sa.String(length=36), nullable=True))

    bind = op.get_bind()
    _populate_public_ids(bind, scan_result_table)
    _populate_public_ids(bind, scan_job_table)

    with op.batch_alter_table("scan_result") as batch_op:
        batch_op.alter_column("public_id", existing_type=sa.String(length=36), nullable=False)
        batch_op.create_index(op.f("ix_scan_result_public_id"), ["public_id"], unique=True)
    with op.batch_alter_table("scan_job") as batch_op:
        batch_op.alter_column("public_id", existing_type=sa.String(length=36), nullable=False)
        batch_op.create_index(op.f("ix_scan_job_public_id"), ["public_id"], unique=True)


def downgrade():
    with op.batch_alter_table("scan_job") as batch_op:
        batch_op.drop_index(op.f("ix_scan_job_public_id"))
        batch_op.drop_column("public_id")
    with op.batch_alter_table("scan_result") as batch_op:
        batch_op.drop_index(op.f("ix_scan_result_public_id"))
        batch_op.drop_column("public_id")
