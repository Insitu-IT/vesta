"""add tier c features

Revision ID: 011_tier_c_features
Revises: 010_settings_notifications
Create Date: 2025-11-06 16:00:00

"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

# revision identifiers, used by Alembic.
revision = "011_tier_c_features"
down_revision = "010_settings_notifications"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add tables for Tier C features: verification, saved searches, and reports"""

    # Backup Verifications table
    op.create_table(
        "backup_verifications",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("backup_id", sa.String(), nullable=False),
        sa.Column(
            "status", sa.String(length=20), nullable=True, server_default="pending"
        ),
        sa.Column(
            "verification_type",
            sa.String(length=50),
            nullable=True,
            server_default="checksum",
        ),
        sa.Column("result_message", sa.Text(), nullable=True),
        sa.Column("started_at", sa.DateTime(), nullable=True),
        sa.Column("completed_at", sa.DateTime(), nullable=True),
        sa.Column("created_by", sa.String(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(
            ["backup_id"],
            ["backups.id"],
        ),
        sa.ForeignKeyConstraint(
            ["created_by"],
            ["users.id"],
        ),
    )
    op.create_index(
        "ix_backup_verifications_backup_id", "backup_verifications", ["backup_id"]
    )
    op.create_index(
        "ix_backup_verifications_status", "backup_verifications", ["status"]
    )

    # Saved Searches table
    op.create_table(
        "saved_searches",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("search_type", sa.String(length=20), nullable=False),
        sa.Column("filters", JSONB, nullable=True),
        sa.Column("created_by", sa.String(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(
            ["created_by"],
            ["users.id"],
        ),
    )
    op.create_index("ix_saved_searches_created_by", "saved_searches", ["created_by"])
    op.create_index("ix_saved_searches_search_type", "saved_searches", ["search_type"])

    # Reports table
    op.create_table(
        "reports",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("report_type", sa.String(length=50), nullable=False),
        sa.Column("schedule", sa.String(length=50), nullable=True),
        sa.Column("enabled", sa.Boolean(), nullable=True, server_default="true"),
        sa.Column("format", sa.String(length=20), nullable=True, server_default="pdf"),
        sa.Column("recipients", JSONB, nullable=True),
        sa.Column("filters", JSONB, nullable=True),
        sa.Column("last_run_at", sa.DateTime(), nullable=True),
        sa.Column("next_run_at", sa.DateTime(), nullable=True),
        sa.Column("created_by", sa.String(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(
            ["created_by"],
            ["users.id"],
        ),
    )
    op.create_index("ix_reports_report_type", "reports", ["report_type"])
    op.create_index("ix_reports_enabled", "reports", ["enabled"])

    # Report Executions table
    op.create_table(
        "report_executions",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("report_id", sa.String(), nullable=True),
        sa.Column(
            "status", sa.String(length=20), nullable=True, server_default="pending"
        ),
        sa.Column("file_path", sa.String(length=500), nullable=True),
        sa.Column("file_size_bytes", sa.Integer(), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("started_at", sa.DateTime(), nullable=True),
        sa.Column("completed_at", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(
            ["report_id"],
            ["reports.id"],
        ),
    )
    op.create_index(
        "ix_report_executions_report_id", "report_executions", ["report_id"]
    )
    op.create_index(
        "ix_report_executions_created_at", "report_executions", ["created_at"]
    )


def downgrade() -> None:
    """Remove Tier C tables"""
    op.drop_index("ix_report_executions_created_at", table_name="report_executions")
    op.drop_index("ix_report_executions_report_id", table_name="report_executions")
    op.drop_table("report_executions")

    op.drop_index("ix_reports_enabled", table_name="reports")
    op.drop_index("ix_reports_report_type", table_name="reports")
    op.drop_table("reports")

    op.drop_index("ix_saved_searches_search_type", table_name="saved_searches")
    op.drop_index("ix_saved_searches_created_by", table_name="saved_searches")
    op.drop_table("saved_searches")

    op.drop_index("ix_backup_verifications_status", table_name="backup_verifications")
    op.drop_index(
        "ix_backup_verifications_backup_id", table_name="backup_verifications"
    )
    op.drop_table("backup_verifications")
