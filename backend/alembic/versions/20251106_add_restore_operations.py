"""add restore operations

Revision ID: 009_restore_operations
Revises: 008_agent_heartbeat
Create Date: 2025-11-06 12:00:00

"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

# revision identifiers, used by Alembic.
revision = "009_restore_operations"
down_revision = "008_agent_heartbeat"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add restores table for tracking backup restore operations"""
    op.create_table(
        "restores",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("backup_id", sa.String(), nullable=False),
        sa.Column("target_vm_id", sa.String(), nullable=True),
        sa.Column(
            "restore_to_original", sa.Boolean(), nullable=True, server_default="true"
        ),
        sa.Column("target_vm_name", sa.String(length=255), nullable=True),
        sa.Column(
            "status", sa.String(length=20), nullable=True, server_default="pending"
        ),
        sa.Column("progress", sa.Integer(), nullable=True, server_default="0"),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("created_by", sa.String(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.Column("started_at", sa.DateTime(), nullable=True),
        sa.Column("completed_at", sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(
            ["backup_id"],
            ["backups.id"],
        ),
        sa.ForeignKeyConstraint(
            ["target_vm_id"],
            ["vms.id"],
        ),
        sa.ForeignKeyConstraint(
            ["created_by"],
            ["users.id"],
        ),
    )

    # Create indexes for common queries
    op.create_index("ix_restores_backup_id", "restores", ["backup_id"])
    op.create_index("ix_restores_status", "restores", ["status"])
    op.create_index("ix_restores_created_at", "restores", ["created_at"])


def downgrade() -> None:
    """Remove restores table"""
    op.drop_index("ix_restores_created_at", table_name="restores")
    op.drop_index("ix_restores_status", table_name="restores")
    op.drop_index("ix_restores_backup_id", table_name="restores")
    op.drop_table("restores")
