"""add agent heartbeat

Revision ID: 008_agent_heartbeat
Revises: 007_schedules
Create Date: 2025-11-05 18:00:00

"""

from alembic import op
import sqlalchemy as sa
from datetime import datetime

# revision identifiers, used by Alembic.
revision = "008_agent_heartbeat"
down_revision = "007_schedules"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add last_heartbeat column to agents table"""
    op.add_column("agents", sa.Column("last_heartbeat", sa.DateTime(), nullable=True))

    # Set default value for existing agents to current timestamp
    op.execute(
        "UPDATE agents SET last_heartbeat = created_at WHERE last_heartbeat IS NULL"
    )


def downgrade() -> None:
    """Remove last_heartbeat column from agents table"""
    op.drop_column("agents", "last_heartbeat")
