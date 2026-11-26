"""Add agent and VM detail columns

Revision ID: 20251129_agent_vm_details
Revises: 20251116_add_multi_tenancy_foundation
Create Date: 2025-11-29

"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = "20251129_agent_vm_details"
down_revision = "20251116_multi_tenancy"
branch_labels = None
depends_on = None


def upgrade():
    # Add new columns to agents table
    op.add_column("agents", sa.Column("ip_address", sa.String(45), nullable=True))
    op.add_column("agents", sa.Column("port", sa.Integer(), nullable=True))
    op.add_column("agents", sa.Column("version", sa.String(32), nullable=True))
    op.add_column("agents", sa.Column("platform", sa.String(64), nullable=True))

    # Add new columns to vms table
    op.add_column("vms", sa.Column("uuid", sa.String(36), nullable=True))
    op.add_column("vms", sa.Column("memory_kb", sa.BigInteger(), nullable=True))
    op.add_column("vms", sa.Column("vcpu_count", sa.Integer(), nullable=True))
    op.add_column(
        "vms",
        sa.Column("disks", postgresql.JSONB(), nullable=True, server_default="[]"),
    )
    op.add_column(
        "vms",
        sa.Column(
            "vm_metadata", postgresql.JSONB(), nullable=True, server_default="{}"
        ),
    )


def downgrade():
    # Remove columns from vms table
    op.drop_column("vms", "vm_metadata")
    op.drop_column("vms", "disks")
    op.drop_column("vms", "vcpu_count")
    op.drop_column("vms", "memory_kb")
    op.drop_column("vms", "uuid")

    # Remove columns from agents table
    op.drop_column("agents", "platform")
    op.drop_column("agents", "version")
    op.drop_column("agents", "port")
    op.drop_column("agents", "ip_address")
