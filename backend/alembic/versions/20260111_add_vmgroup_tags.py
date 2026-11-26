"""Add tags column to VMGroup

Revision ID: add_vmgroup_tags
Revises: 20260110_v3_settings
Create Date: 2026-01-11
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSON

# revision identifiers
revision = "add_vmgroup_tags"
down_revision = "20260110_v3_settings"
branch_labels = None
depends_on = None


def upgrade():
    # Add tags column to vm_groups table
    op.add_column("vm_groups", sa.Column("tags", JSON, nullable=True))


def downgrade():
    op.drop_column("vm_groups", "tags")
