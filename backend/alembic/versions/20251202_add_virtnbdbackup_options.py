"""Add virtnbdbackup/restore advanced options

Revision ID: 20251202_virtnbdbackup_options
Revises: 20251129_agent_vm_details
Create Date: 2025-12-02

Adds support for:
- Backup: exclude_disks, workers, checkpoints
- Restore: until_checkpoint, auto_define, adjust_config, selected_disks
- Schedule: exclude_disks, workers
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = "20251202_virtnbdbackup_options"
down_revision = "20251129_agent_vm_details"
branch_labels = None
depends_on = None


def upgrade():
    # Add new columns to backups table
    op.add_column(
        "backups",
        sa.Column(
            "exclude_disks", postgresql.JSONB(), nullable=True, server_default="[]"
        ),
    )
    op.add_column("backups", sa.Column("workers", sa.Integer(), nullable=True))
    op.add_column(
        "backups",
        sa.Column(
            "checkpoints", postgresql.JSONB(), nullable=True, server_default="[]"
        ),
    )

    # Add new columns to restores table
    op.add_column(
        "restores", sa.Column("until_checkpoint", sa.String(255), nullable=True)
    )
    op.add_column(
        "restores",
        sa.Column("auto_define", sa.Boolean(), nullable=True, server_default="false"),
    )
    op.add_column(
        "restores",
        sa.Column("adjust_config", sa.Boolean(), nullable=True, server_default="false"),
    )
    op.add_column(
        "restores",
        sa.Column(
            "selected_disks", postgresql.JSONB(), nullable=True, server_default="[]"
        ),
    )

    # Add new columns to schedules table
    op.add_column(
        "schedules",
        sa.Column(
            "exclude_disks", postgresql.JSONB(), nullable=True, server_default="[]"
        ),
    )
    op.add_column("schedules", sa.Column("workers", sa.Integer(), nullable=True))
    op.add_column(
        "schedules",
        sa.Column("backup_type", sa.String(20), nullable=True, server_default="full"),
    )


def downgrade():
    # Remove columns from schedules table
    op.drop_column("schedules", "backup_type")
    op.drop_column("schedules", "workers")
    op.drop_column("schedules", "exclude_disks")

    # Remove columns from restores table
    op.drop_column("restores", "selected_disks")
    op.drop_column("restores", "adjust_config")
    op.drop_column("restores", "auto_define")
    op.drop_column("restores", "until_checkpoint")

    # Remove columns from backups table
    op.drop_column("backups", "checkpoints")
    op.drop_column("backups", "workers")
    op.drop_column("backups", "exclude_disks")
