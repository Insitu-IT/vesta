"""Add v3 settings schema for S3 storage and OIDC authentication

Revision ID: 20260110_v3_settings
Revises: 20251220_system_events
Create Date: 2026-01-10

This migration adds:
- settings_v3: Non-secret settings with source tracking
- secrets_v3: Encrypted credentials for UI-entered secrets
- User OIDC columns: auth_source, role_source, oidc_subject, oidc_issuer
"""

from alembic import op
import sqlalchemy as sa

# revision identifiers
revision = "20260110_v3_settings"
down_revision = "20251220_system_events"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Settings table for non-secret config
    op.create_table(
        "settings_v3",
        sa.Column("key", sa.String(100), primary_key=True),
        sa.Column("value", sa.Text, nullable=True),
        sa.Column(
            "value_type", sa.String(20), server_default="string"
        ),  # string, int, bool, json
        sa.Column(
            "source", sa.String(20), server_default="default"
        ),  # default, ui, env, vault
        sa.Column("updated_at", sa.DateTime(), server_default=sa.text("now()")),
        sa.Column("updated_by", sa.String(100), nullable=True),
    )

    # Secrets table - encrypted values for UI-entered credentials
    # Vault-sourced secrets are NOT stored here (read at runtime via ESO)
    op.create_table(
        "secrets_v3",
        sa.Column("key", sa.String(100), primary_key=True),
        sa.Column("encrypted_value", sa.Text, nullable=True),  # Fernet encrypted
        sa.Column("source", sa.String(20), server_default="ui"),  # ui, vault
        sa.Column("vault_path", sa.String(255), nullable=True),  # If source=vault
        sa.Column("updated_at", sa.DateTime(), server_default=sa.text("now()")),
    )

    # OIDC columns on users table
    op.add_column(
        "users", sa.Column("auth_source", sa.String(20), server_default="local")
    )
    op.add_column(
        "users", sa.Column("role_source", sa.String(20), server_default="local")
    )
    op.add_column("users", sa.Column("oidc_subject", sa.String(255), nullable=True))
    op.add_column("users", sa.Column("oidc_issuer", sa.String(255), nullable=True))

    # Unique index for OIDC subject+issuer lookup
    op.create_index(
        "ix_users_oidc_subject",
        "users",
        ["oidc_subject", "oidc_issuer"],
        unique=True,
        postgresql_where=sa.text("oidc_subject IS NOT NULL"),
    )


def downgrade() -> None:
    op.drop_index("ix_users_oidc_subject", table_name="users")
    op.drop_column("users", "oidc_issuer")
    op.drop_column("users", "oidc_subject")
    op.drop_column("users", "role_source")
    op.drop_column("users", "auth_source")
    op.drop_table("secrets_v3")
    op.drop_table("settings_v3")
