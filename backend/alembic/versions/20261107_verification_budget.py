"""Pin the original verification admission window across busy retries."""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "verification_budget"
down_revision = "storage_upload_progress"
branch_labels = None
depends_on = None


def upgrade():
    # The existing verification trigger compares all columns except its
    # explicit mutable list, so this new field is immutable after enrollment.
    # Old attempts are observed but receive no invented admission window.
    op.add_column(
        "backup_verifications",
        sa.Column("verification_admission_budget", postgresql.JSONB(), nullable=True),
    )


def downgrade():
    op.drop_column("backup_verifications", "verification_admission_budget")
