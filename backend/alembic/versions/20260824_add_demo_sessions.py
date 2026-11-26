"""Add isolated public-demo sessions.

Revision ID: add_demo_sessions
Revises: add_notification_read
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "add_demo_sessions"
down_revision = "add_notification_read"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "demo_sessions",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("fixture_version", sa.String(length=32), nullable=False),
        sa.Column("state", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.Column("absolute_expires_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("token_hash"),
    )
    op.create_index("ix_demo_sessions_token_hash", "demo_sessions", ["token_hash"])
    op.create_index("ix_demo_sessions_expires_at", "demo_sessions", ["expires_at"])
    op.create_index(
        "ix_demo_sessions_absolute_expires_at",
        "demo_sessions",
        ["absolute_expires_at"],
    )


def downgrade():
    op.drop_index("ix_demo_sessions_absolute_expires_at", table_name="demo_sessions")
    op.drop_index("ix_demo_sessions_expires_at", table_name="demo_sessions")
    op.drop_index("ix_demo_sessions_token_hash", table_name="demo_sessions")
    op.drop_table("demo_sessions")
