"""Add activity logs

Revision ID: 005_activity_logs
Revises: 004_backup_tags
Create Date: 2025-11-05 17:00:00.000000

This migration adds the activity_logs table for user activity audit trail.
Tracks all significant user actions with JSONB details field.
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = "005_activity_logs"
down_revision = "004_backup_tags"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create activity_logs table"""
    op.create_table(
        "activity_logs",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("user_id", sa.String(), nullable=False),
        sa.Column("action", sa.String(length=100), nullable=False),
        sa.Column("resource_type", sa.String(length=50), nullable=True),
        sa.Column("resource_id", sa.String(), nullable=True),
        sa.Column("details", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
    )

    # Create index on user_id for faster queries
    op.create_index("ix_activity_logs_user_id", "activity_logs", ["user_id"])
    # Create index on created_at for time-based queries
    op.create_index("ix_activity_logs_created_at", "activity_logs", ["created_at"])
    # Create index on action for filtering by action type
    op.create_index("ix_activity_logs_action", "activity_logs", ["action"])


def downgrade() -> None:
    """Drop activity_logs table and indices"""
    op.drop_index("ix_activity_logs_action", table_name="activity_logs")
    op.drop_index("ix_activity_logs_created_at", table_name="activity_logs")
    op.drop_index("ix_activity_logs_user_id", table_name="activity_logs")
    op.drop_table("activity_logs")
