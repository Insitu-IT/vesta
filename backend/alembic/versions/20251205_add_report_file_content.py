"""Add file_content column to report_executions for database storage

Revision ID: 20251205_report_content
Revises: 20251202_virtnbdbackup_options
Create Date: 2025-12-05
"""

from alembic import op
import sqlalchemy as sa

# revision identifiers
revision = "20251205_report_content"
down_revision = "20251202_virtnbdbackup_options"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Add file_content column to store report data in database
    # Using LargeBinary for binary data (PDF, etc.)
    op.add_column(
        "report_executions", sa.Column("file_content", sa.LargeBinary(), nullable=True)
    )
    # Add filename column to preserve original filename
    op.add_column(
        "report_executions", sa.Column("file_name", sa.String(255), nullable=True)
    )
    # Add content_type for proper download headers
    op.add_column(
        "report_executions", sa.Column("content_type", sa.String(100), nullable=True)
    )


def downgrade() -> None:
    op.drop_column("report_executions", "content_type")
    op.drop_column("report_executions", "file_name")
    op.drop_column("report_executions", "file_content")
