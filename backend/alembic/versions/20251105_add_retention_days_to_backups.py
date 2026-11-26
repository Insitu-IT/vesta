"""Add retention_days to backups

Revision ID: 002_retention_days
Revises: 001_initial
Create Date: 2025-11-05 14:00:00.000000

This migration adds a retention_days field to the backups table to support
automated backup retention policies.
"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = "002_retention_days"
down_revision = "001_initial"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add retention_days column to backups table"""
    op.add_column("backups", sa.Column("retention_days", sa.Integer(), nullable=True))

    # Set default value for existing records
    op.execute("UPDATE backups SET retention_days = 30 WHERE retention_days IS NULL")

    # Make the column non-nullable after setting defaults
    op.alter_column("backups", "retention_days", nullable=False)


def downgrade() -> None:
    """Remove retention_days column from backups table"""
    op.drop_column("backups", "retention_days")
