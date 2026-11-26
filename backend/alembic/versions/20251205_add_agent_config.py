"""Add config column to agents for UI-configurable settings

Revision ID: 20251205_agent_config
Revises: 20251205_report_content
Create Date: 2025-12-05
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

# revision identifiers
revision = "20251205_agent_config"
down_revision = "20251205_report_content"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Add config column to agents table for UI-managed settings
    # Settings delivered via heartbeat, overridable by local agent.env
    op.add_column(
        "agents", sa.Column("config", JSONB, server_default="{}", nullable=False)
    )


def downgrade() -> None:
    op.drop_column("agents", "config")
