"""Initial schema from MVP

Revision ID: 001_initial
Revises:
Create Date: 2025-11-05 12:00:00.000000

This migration represents the initial database schema from the Minimal MVP.
It includes: users, agents, vms, and backups tables.
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = "001_initial"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create initial database schema"""

    # Create users table
    op.create_table(
        "users",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("username", sa.String(length=100), nullable=False),
        sa.Column("password_hash", sa.String(length=255), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("username"),
    )
    op.create_index(op.f("ix_users_username"), "users", ["username"], unique=True)

    # Create agents table
    op.create_table(
        "agents",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("hostname", sa.String(length=255), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("hostname"),
    )

    # Create vms table
    op.create_table(
        "vms",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("agent_id", sa.String(), nullable=False),
        sa.Column("state", sa.String(length=20), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(
            ["agent_id"],
            ["agents.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
    )

    # Create backups table
    op.create_table(
        "backups",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("vm_id", sa.String(), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=True),
        sa.Column("progress", sa.Integer(), nullable=True),
        sa.Column("size_bytes", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.Column("completed_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(
            ["vm_id"],
            ["vms.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
    )


def downgrade() -> None:
    """Drop all tables"""
    op.drop_table("backups")
    op.drop_table("vms")
    op.drop_table("agents")
    op.drop_index(op.f("ix_users_username"), table_name="users")
    op.drop_table("users")
