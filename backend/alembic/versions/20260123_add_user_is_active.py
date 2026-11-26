"""Add is_active column to users

Revision ID: add_user_is_active
Revises: add_backup_queue
Create Date: 2026-01-23
"""

from alembic import op
import sqlalchemy as sa

# revision identifiers
revision = "add_user_is_active"
down_revision = "add_backup_queue"
branch_labels = None
depends_on = None


def upgrade():
    # Add is_active column with default True for existing users
    op.add_column(
        "users",
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default="true"),
    )


def downgrade():
    op.drop_column("users", "is_active")
