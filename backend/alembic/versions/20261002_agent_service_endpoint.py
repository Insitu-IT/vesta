"""Allow the agent endpoint to be a Kubernetes service DNS name."""

from alembic import op
import sqlalchemy as sa

revision = "agent_service_endpoint"
down_revision = "modern_capacity_review"
branch_labels = None
depends_on = None


def upgrade():
    op.alter_column(
        "agents",
        "ip_address",
        existing_type=sa.String(length=45),
        type_=sa.String(length=255),
        existing_nullable=True,
    )


def downgrade():
    has_long_endpoint = op.get_bind().scalar(
        sa.text("SELECT EXISTS (SELECT 1 FROM agents WHERE length(ip_address) > 45)")
    )
    if has_long_endpoint:
        raise RuntimeError("Cannot narrow a persisted agent service DNS endpoint")
    op.alter_column(
        "agents",
        "ip_address",
        existing_type=sa.String(length=255),
        type_=sa.String(length=45),
        existing_nullable=True,
    )
