"""Add agent API key authentication

Revision ID: 20251109_agent_auth
Revises: 20251106_add_tier_c_features
Create Date: 2025-11-09

"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

# revision identifiers, used by Alembic.
revision = "20251109_agent_auth"
down_revision = "011_tier_c_features"
branch_labels = None
depends_on = None


def upgrade():
    """Add API key authentication fields to agents table"""
    # Add API key authentication fields
    op.add_column("agents", sa.Column("api_key_hash", sa.String(64), nullable=True))
    op.add_column("agents", sa.Column("key_created_at", sa.DateTime(), nullable=True))
    op.add_column("agents", sa.Column("key_last_used_at", sa.DateTime(), nullable=True))

    # Add capabilities and metrics JSON fields
    op.add_column(
        "agents", sa.Column("capabilities", JSONB, server_default="{}", nullable=False)
    )
    op.add_column(
        "agents", sa.Column("metrics", JSONB, server_default="{}", nullable=False)
    )


def downgrade():
    """Remove API key authentication fields from agents table"""
    op.drop_column("agents", "metrics")
    op.drop_column("agents", "capabilities")
    op.drop_column("agents", "key_last_used_at")
    op.drop_column("agents", "key_created_at")
    op.drop_column("agents", "api_key_hash")
