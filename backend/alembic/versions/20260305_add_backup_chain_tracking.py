"""Add backup chain tracking columns: chain_id, parent_backup_id, chain_position

Revision ID: add_backup_chain_tracking
Revises: add_dynamic_groups
Create Date: 2026-03-05
"""

from alembic import op
import sqlalchemy as sa

revision = "add_backup_chain_tracking"
down_revision = "add_dynamic_groups"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        "backups",
        sa.Column(
            "chain_id",
            sa.String(),
            sa.ForeignKey("backups.id"),
            nullable=True,
            index=True,
        ),
    )
    op.add_column(
        "backups",
        sa.Column(
            "parent_backup_id", sa.String(), sa.ForeignKey("backups.id"), nullable=True
        ),
    )
    op.add_column("backups", sa.Column("chain_position", sa.Integer(), nullable=True))

    # Ensure backup_type column exists (may be missing on fresh DBs)
    conn = op.get_bind()
    inspector = sa.inspect(conn)
    columns = [c["name"] for c in inspector.get_columns("backups")]
    if "backup_type" not in columns:
        op.add_column(
            "backups",
            sa.Column("backup_type", sa.String(20), server_default="full"),
        )

    # Backfill: existing full backups start their own chain
    op.execute(
        "UPDATE backups SET chain_id = id, chain_position = 0 "
        "WHERE backup_type = 'full' AND chain_id IS NULL"
    )


def downgrade():
    op.drop_column("backups", "chain_position")
    op.drop_column("backups", "parent_backup_id")
    op.drop_column("backups", "chain_id")
