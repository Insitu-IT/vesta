"""Keep upload observations outside immutable backup options and tags."""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "storage_upload_progress"
down_revision = "backup_verification"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        "backups", sa.Column("storage_progress", postgresql.JSONB(), nullable=True)
    )


def downgrade():
    # Only presentation telemetry is discarded; custody is in existing columns.
    op.drop_column("backups", "storage_progress")
