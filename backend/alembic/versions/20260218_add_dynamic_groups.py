"""Add dynamic group support: group_type, rules, rules_match columns

Revision ID: add_dynamic_groups
Revises: add_mtls_support
Create Date: 2026-02-18
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = "add_dynamic_groups"
down_revision = "add_mtls_support"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        "vm_groups",
        sa.Column("group_type", sa.String(20), server_default="static", nullable=False),
    )
    op.add_column("vm_groups", sa.Column("rules", JSONB, nullable=True))
    op.add_column(
        "vm_groups",
        sa.Column("rules_match", sa.String(10), server_default="all", nullable=False),
    )


def downgrade():
    op.drop_column("vm_groups", "rules_match")
    op.drop_column("vm_groups", "rules")
    op.drop_column("vm_groups", "group_type")
