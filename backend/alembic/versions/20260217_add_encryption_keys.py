"""Add encryption_keys table and backup envelope encryption columns

Revision ID: add_encryption_keys
Revises: add_missing_model_fields
Create Date: 2026-02-17

Adds:
- encryption_keys table for KEK (Key Encryption Key) storage
- backups.encryption_key_id FK to encryption_keys
- backups.wrapped_dek for AES-wrapped DEK storage
- Data migration: creates legacy key record for existing encrypted backups
"""

import hashlib
import os
import uuid
from datetime import datetime

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = "add_encryption_keys"
down_revision = "add_missing_model_fields"
branch_labels = None
depends_on = None


def upgrade():
    # Create encryption_keys table
    op.create_table(
        "encryption_keys",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("algorithm", sa.String(50), server_default="aes-256-gcm"),
        sa.Column("key_hash", sa.String(64), nullable=False),
        sa.Column("encrypted_material", sa.Text(), nullable=True),
        sa.Column("status", sa.String(20), server_default="active"),
        sa.Column("provider", sa.String(50), server_default="local"),
        sa.Column("provider_key_ref", sa.String(255), nullable=True),
        sa.Column("created_at", sa.DateTime(), server_default=sa.func.now()),
        sa.Column("created_by", sa.String(), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("rotated_at", sa.DateTime(), nullable=True),
        sa.Column(
            "replaced_by_id",
            sa.String(),
            sa.ForeignKey("encryption_keys.id"),
            nullable=True,
        ),
        sa.Column("backed_up", sa.Boolean(), server_default="false"),
        sa.Column("backed_up_at", sa.DateTime(), nullable=True),
        sa.Column("backed_up_locations", JSONB, server_default="[]"),
    )

    op.create_index("ix_encryption_keys_status", "encryption_keys", ["status"])

    # Add envelope encryption columns to backups
    op.add_column(
        "backups",
        sa.Column(
            "encryption_key_id",
            sa.String(),
            sa.ForeignKey("encryption_keys.id"),
            nullable=True,
        ),
    )
    op.add_column("backups", sa.Column("wrapped_dek", sa.Text(), nullable=True))

    # Data migration: if ENCRYPTION_KEY env var is set and encrypted backups exist,
    # create a legacy EncryptionKey record and link existing backups.
    # This runs in Python so we can read the env var.
    _migrate_legacy_encryption()


def _migrate_legacy_encryption():
    """Create legacy key record for pre-envelope encrypted backups."""
    encryption_key = os.getenv("ENCRYPTION_KEY", "")
    if not encryption_key:
        return

    conn = op.get_bind()

    # Check if any encrypted backups exist (tags->>'encrypted' = 'true')
    result = conn.execute(
        sa.text("SELECT COUNT(*) FROM backups WHERE tags->>'encrypted' = 'true'")
    )
    count = result.scalar()
    if count == 0:
        return

    key_hash = hashlib.sha256(encryption_key.encode()).hexdigest()[:16]
    key_id = str(uuid.uuid4())

    # Try to encrypt the key material with Fernet if VNBUI_ENCRYPTION_KEY is available
    encrypted_material = None
    vnbui_key = os.getenv("VNBUI_ENCRYPTION_KEY")
    if vnbui_key:
        try:
            from cryptography.fernet import Fernet

            f = Fernet(vnbui_key.encode())
            encrypted_material = f.encrypt(encryption_key.encode()).decode()
        except Exception:
            pass  # Will be None — key can still be used for hash validation

    conn.execute(
        sa.text("""
            INSERT INTO encryption_keys (id, name, algorithm, key_hash, encrypted_material,
                                         status, provider, created_at, backed_up, backed_up_locations)
            VALUES (:id, :name, :algorithm, :key_hash, :encrypted_material,
                    :status, :provider, :created_at, :backed_up, :backed_up_locations)
        """),
        {
            "id": key_id,
            "name": "Legacy Key (migrated from ENCRYPTION_KEY env var)",
            "algorithm": "aes-256-gcm",
            "key_hash": key_hash,
            "encrypted_material": encrypted_material,
            "status": "rotated",  # Not active — new backups should use new keys
            "provider": "local",
            "created_at": datetime.utcnow(),
            "backed_up": False,
            "backed_up_locations": "[]",
        },
    )

    # Link existing encrypted backups to this key
    conn.execute(
        sa.text("""
            UPDATE backups SET encryption_key_id = :key_id
            WHERE tags->>'encrypted' = 'true' AND encryption_key_id IS NULL
        """),
        {"key_id": key_id},
    )


def downgrade():
    op.drop_column("backups", "wrapped_dek")
    op.drop_column("backups", "encryption_key_id")
    op.drop_index("ix_encryption_keys_status")
    op.drop_table("encryption_keys")
