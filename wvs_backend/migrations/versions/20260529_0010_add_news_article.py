"""add_news_article

Revision ID: 121b8e2a79a5
Revises: 20260527_0009
Create Date: 2026-05-29 10:02:58.382645

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mysql

# revision identifiers, used by Alembic.
revision = '121b8e2a79a5'
down_revision = '20260527_0009'
branch_labels = None
depends_on = None


def upgrade():
    conn = op.get_bind()
    op.create_table('news_article',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('public_id', sa.String(length=36), nullable=False),
    sa.Column('title', sa.String(length=300), nullable=False),
    sa.Column('slug', sa.String(length=320), nullable=False),
    sa.Column('summary', sa.Text(), nullable=False),
    sa.Column('body', sa.Text(), nullable=False),
    sa.Column('category', sa.String(length=60), nullable=False),
    sa.Column('tags', sa.JSON(), nullable=False),
    sa.Column('severity', sa.String(length=20), nullable=True),
    sa.Column('cve_ids', sa.JSON(), nullable=False),
    sa.Column('source_url', sa.String(length=500), nullable=True),
    sa.Column('published', sa.Boolean(), nullable=False),
    sa.Column('published_at', sa.DateTime(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.Column('author_id', sa.Integer(), nullable=False),
    sa.ForeignKeyConstraint(['author_id'], ['user.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('news_article', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_news_article_public_id'), ['public_id'], unique=True)
        batch_op.create_index(batch_op.f('ix_news_article_published'), ['published'], unique=False)
        batch_op.create_index(batch_op.f('ix_news_article_published_at'), ['published_at'], unique=False)
        batch_op.create_index(batch_op.f('ix_news_article_slug'), ['slug'], unique=True)

    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.alter_column('username',
               existing_type=mysql.VARCHAR(length=50),
               nullable=False)
        batch_op.alter_column('password',
               existing_type=mysql.VARCHAR(length=255),
               nullable=False)
        batch_op.alter_column('email',
               existing_type=mysql.VARCHAR(length=100),
               nullable=False)

    verified_target_indexes = {
        index["name"] for index in sa.inspect(conn).get_indexes("verified_target")
    }
    if "public_id" in verified_target_indexes:
        with op.batch_alter_table('verified_target', schema=None) as batch_op:
            batch_op.drop_index(batch_op.f('public_id'))


def downgrade():
    with op.batch_alter_table('verified_target', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('public_id'), ['public_id'], unique=True)

    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.alter_column('email',
               existing_type=mysql.VARCHAR(length=100),
               nullable=True)
        batch_op.alter_column('password',
               existing_type=mysql.VARCHAR(length=255),
               nullable=True)
        batch_op.alter_column('username',
               existing_type=mysql.VARCHAR(length=50),
               nullable=True)

    with op.batch_alter_table('news_article', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_news_article_slug'))
        batch_op.drop_index(batch_op.f('ix_news_article_published_at'))
        batch_op.drop_index(batch_op.f('ix_news_article_published'))
        batch_op.drop_index(batch_op.f('ix_news_article_public_id'))

    op.drop_table('news_article')
