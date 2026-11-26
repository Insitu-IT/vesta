"""Add missing model fields: is_public, template

Revision ID: add_missing_model_fields
Revises: add_user_is_active
Create Date: 2026-01-23

Adds columns that were used in routers but missing from models:
- saved_searches.is_public (Boolean) - share searches with all users
- notification_rules.template (Text) - custom email template
"""

from alembic import op
import sqlalchemy as sa

revision = "add_missing_model_fields"
down_revision = "add_user_is_active"
branch_labels = None
depends_on = None


def upgrade():
    # Add is_public to saved_searches
    op.add_column(
        "saved_searches",
        sa.Column("is_public", sa.Boolean(), nullable=False, server_default="false"),
    )

    # Add template to notification_rules
    op.add_column("notification_rules", sa.Column("template", sa.Text(), nullable=True))


def downgrade():
    op.drop_column("notification_rules", "template")
    op.drop_column("saved_searches", "is_public")
