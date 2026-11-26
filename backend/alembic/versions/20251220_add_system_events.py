"""Add system_events table for agent/scheduler events

Revision ID: 20251220_system_events
Revises: 20251205_agent_config
Create Date: 2025-12-20
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

# revision identifiers
revision = "20251220_system_events"
down_revision = "20251205_agent_config"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Create system_events table for agent/scheduler generated events
    # Unlike activity_logs which require user_id, these are system events
    op.create_table(
        "system_events",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("event_type", sa.String(100), nullable=False, index=True),
        sa.Column("source", sa.String(50), nullable=False),
        sa.Column("source_id", sa.String(), nullable=True),
        sa.Column("resource_type", sa.String(50), nullable=True),
        sa.Column("resource_id", sa.String(), nullable=True),
        sa.Column("details", JSONB, server_default="{}", nullable=False),
        sa.Column(
            "created_at", sa.DateTime(), nullable=False, server_default=sa.text("now()")
        ),
        sa.PrimaryKeyConstraint("id"),
    )

    # Create index on created_at for time-based queries
    op.create_index("ix_system_events_created_at", "system_events", ["created_at"])


def downgrade() -> None:
    op.drop_index("ix_system_events_created_at", table_name="system_events")
    op.drop_table("system_events")
