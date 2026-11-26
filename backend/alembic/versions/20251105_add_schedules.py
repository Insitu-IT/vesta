"""add schedules table

Revision ID: 007_schedules
Revises: 006_user_roles
Create Date: 2025-11-05 16:00:00

"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

# revision identifiers, used by Alembic.
revision = "007_schedules"
down_revision = "006_user_roles"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create schedules table"""
    op.create_table(
        "schedules",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("vm_id", sa.String(), nullable=True),
        sa.Column("vm_group_id", sa.String(), nullable=True),
        sa.Column("cron_expression", sa.String(length=100), nullable=False),
        sa.Column("retention_days", sa.Integer(), nullable=True, server_default="30"),
        sa.Column("tags", JSONB, nullable=True, server_default="{}"),
        sa.Column("enabled", sa.Boolean(), nullable=True, server_default="true"),
        sa.Column("last_run_at", sa.DateTime(), nullable=True),
        sa.Column("next_run_at", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(
            ["vm_id"],
            ["vms.id"],
        ),
        sa.ForeignKeyConstraint(
            ["vm_group_id"],
            ["vm_groups.id"],
        ),
    )

    # Create index on enabled for faster queries
    op.create_index("ix_schedules_enabled", "schedules", ["enabled"])

    # Create index on next_run_at for scheduler
    op.create_index("ix_schedules_next_run_at", "schedules", ["next_run_at"])


def downgrade() -> None:
    """Drop schedules table"""
    op.drop_index("ix_schedules_next_run_at", table_name="schedules")
    op.drop_index("ix_schedules_enabled", table_name="schedules")
    op.drop_table("schedules")
