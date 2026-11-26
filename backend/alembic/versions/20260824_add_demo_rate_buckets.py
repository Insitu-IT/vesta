"""Add bounded public-demo rate counters.

Revision ID: add_demo_rate_buckets
Revises: add_demo_sessions
"""

import sqlalchemy as sa
from alembic import op

revision = "add_demo_rate_buckets"
down_revision = "add_demo_sessions"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "demo_rate_buckets",
        sa.Column("key_hash", sa.String(length=64), nullable=False),
        sa.Column("window_started_at", sa.DateTime(), nullable=False),
        sa.Column("request_count", sa.Integer(), nullable=False),
        sa.PrimaryKeyConstraint("key_hash"),
    )


def downgrade():
    op.drop_table("demo_rate_buckets")
