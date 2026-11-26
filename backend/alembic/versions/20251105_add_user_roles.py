"""Add user roles

Revision ID: 006_user_roles
Revises: 005_activity_logs
Create Date: 2025-11-05 18:00:00.000000

This migration adds role-based access control (RBAC) to users.
Roles: admin, operator, viewer
"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = "006_user_roles"
down_revision = "005_activity_logs"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add role column to users table"""
    # Add role column as nullable first
    op.add_column("users", sa.Column("role", sa.String(length=20), nullable=True))

    # Set default role for existing users (admin user gets admin role)
    op.execute("UPDATE users SET role = 'admin' WHERE username = 'admin'")
    op.execute("UPDATE users SET role = 'viewer' WHERE role IS NULL")

    # Make role non-nullable
    op.alter_column("users", "role", nullable=False)


def downgrade() -> None:
    """Remove role column from users table"""
    op.drop_column("users", "role")
