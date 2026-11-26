"""Add read column to notification_logs

Revision ID: add_notification_read
Revises: add_backup_chain_tracking
Create Date: 2026-03-11
"""

from alembic import op
import sqlalchemy as sa

revision = "add_notification_read"
down_revision = "add_backup_chain_tracking"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        "notification_logs",
        sa.Column("read", sa.Boolean(), nullable=True, server_default="false"),
    )
    op.execute("UPDATE notification_logs SET read = false WHERE read IS NULL")
    op.alter_column("notification_logs", "read", nullable=False)


def downgrade():
    op.drop_column("notification_logs", "read")
