"""Add backup_queue table for queue-based backup scheduling

Revision ID: add_backup_queue
Revises: add_vmgroup_tags
Create Date: 2026-01-11
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

# revision identifiers
revision = "add_backup_queue"
down_revision = "add_vmgroup_tags"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "backup_queue",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("vm_id", sa.String(), sa.ForeignKey("vms.id"), nullable=False),
        sa.Column("priority", sa.Integer(), default=0),
        sa.Column("retention_days", sa.Integer(), default=30),
        sa.Column("backup_type", sa.String(20), default="full"),
        sa.Column("tags", JSONB, default=dict),
        sa.Column("exclude_disks", JSONB, default=list),
        sa.Column("workers", sa.Integer(), nullable=True),
        sa.Column("status", sa.String(20), default="queued"),
        sa.Column("position", sa.Integer(), nullable=True),
        sa.Column("queued_at", sa.DateTime(), default=sa.func.now()),
        sa.Column("started_at", sa.DateTime(), nullable=True),
        sa.Column("created_by", sa.String(), sa.ForeignKey("users.id"), nullable=True),
        sa.Column(
            "schedule_id", sa.String(), sa.ForeignKey("schedules.id"), nullable=True
        ),
        sa.Column("is_bulk_operation", sa.Boolean(), default=False),
    )

    # Index for efficient queue processing
    op.create_index(
        "ix_backup_queue_status_priority", "backup_queue", ["status", "priority"]
    )


def downgrade():
    op.drop_index("ix_backup_queue_status_priority")
    op.drop_table("backup_queue")
