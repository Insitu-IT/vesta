"""Add tags to backups

Revision ID: 004_backup_tags
Revises: 003_vm_groups
Create Date: 2025-11-05 16:00:00.000000

This migration adds a JSONB tags field to backups for custom metadata.
Tags are stored as key-value pairs (e.g., {"environment": "production", "app": "web"}).
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = "004_backup_tags"
down_revision = "003_vm_groups"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add tags JSONB column to backups table"""
    op.add_column(
        "backups",
        sa.Column("tags", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    )

    # Set default empty object for existing records
    op.execute("UPDATE backups SET tags = '{}' WHERE tags IS NULL")

    # Make the column non-nullable after setting defaults
    op.alter_column("backups", "tags", nullable=False)


def downgrade() -> None:
    """Remove tags column from backups table"""
    op.drop_column("backups", "tags")
