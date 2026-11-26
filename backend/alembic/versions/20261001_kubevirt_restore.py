"""Durable fresh restore plans and destination resource identities."""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "kubevirt_restore"
down_revision = "scheduler_activation"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        "restores", sa.Column("kubevirt_plan", postgresql.JSONB(), nullable=True)
    )
    op.add_column(
        "restores", sa.Column("kubevirt_result", postgresql.JSONB(), nullable=True)
    )
    op.add_column(
        "restores", sa.Column("native_plan", postgresql.JSONB(), nullable=True)
    )
    op.add_column(
        "restores", sa.Column("native_result", postgresql.JSONB(), nullable=True)
    )


def downgrade():
    op.drop_column("restores", "native_result")
    op.drop_column("restores", "native_plan")
    op.drop_column("restores", "kubevirt_result")
    op.drop_column("restores", "kubevirt_plan")
