"""Add mTLS support: agent_certificates table and agent mTLS columns

Revision ID: add_mtls_support
Revises: add_encryption_keys
Create Date: 2026-02-17

Adds:
- agent_certificates table for tracking issued TLS certificates
- agents.cert_fingerprint, cert_expires_at, mtls_enabled columns
"""

from alembic import op
import sqlalchemy as sa

revision = "add_mtls_support"
down_revision = "add_encryption_keys"
branch_labels = None
depends_on = None


def upgrade():
    # Create agent_certificates table
    op.create_table(
        "agent_certificates",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("agent_id", sa.String(), sa.ForeignKey("agents.id"), nullable=False),
        sa.Column("serial_number", sa.String(64), unique=True, index=True),
        sa.Column("fingerprint", sa.String(64), nullable=False),
        sa.Column("common_name", sa.String(255)),
        sa.Column("issued_at", sa.DateTime(), server_default=sa.func.now()),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.Column("status", sa.String(20), server_default="active"),
        sa.Column("revoked_at", sa.DateTime(), nullable=True),
    )

    # Add mTLS columns to agents
    op.add_column("agents", sa.Column("cert_fingerprint", sa.String(64), nullable=True))
    op.add_column("agents", sa.Column("cert_expires_at", sa.DateTime(), nullable=True))
    op.add_column(
        "agents", sa.Column("mtls_enabled", sa.Boolean(), server_default="false")
    )


def downgrade():
    op.drop_column("agents", "mtls_enabled")
    op.drop_column("agents", "cert_expires_at")
    op.drop_column("agents", "cert_fingerprint")
    op.drop_table("agent_certificates")
