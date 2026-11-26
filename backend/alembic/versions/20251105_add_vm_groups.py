"""Add VM groups

Revision ID: 003_vm_groups
Revises: 002_retention_days
Create Date: 2025-11-05 15:00:00.000000

This migration adds VM groups with many-to-many relationship support.
VMs can belong to multiple groups, and groups can contain multiple VMs.
"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = "003_vm_groups"
down_revision = "002_retention_days"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create vm_groups table and vm_group_members association table"""

    # Create vm_groups table
    op.create_table(
        "vm_groups",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("name"),
    )

    # Create vm_group_members association table
    op.create_table(
        "vm_group_members",
        sa.Column("vm_id", sa.String(), nullable=False),
        sa.Column("group_id", sa.String(), nullable=False),
        sa.Column("added_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(
            ["group_id"],
            ["vm_groups.id"],
        ),
        sa.ForeignKeyConstraint(
            ["vm_id"],
            ["vms.id"],
        ),
        sa.PrimaryKeyConstraint("vm_id", "group_id"),
    )


def downgrade() -> None:
    """Drop vm_group_members and vm_groups tables"""
    op.drop_table("vm_group_members")
    op.drop_table("vm_groups")
