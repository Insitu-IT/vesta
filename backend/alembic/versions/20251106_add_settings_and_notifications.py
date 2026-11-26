"""add settings and notifications

Revision ID: 010_settings_notifications
Revises: 009_restore_operations
Create Date: 2025-11-06 14:00:00

"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

# revision identifiers, used by Alembic.
revision = "010_settings_notifications"
down_revision = "009_restore_operations"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add system_settings, notification_rules, and notification_logs tables"""

    # System Settings table
    op.create_table(
        "system_settings",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("category", sa.String(length=50), nullable=False),
        sa.Column("key", sa.String(length=100), nullable=False),
        sa.Column("value", sa.Text(), nullable=True),
        sa.Column(
            "value_type", sa.String(length=20), nullable=True, server_default="string"
        ),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=True),
        sa.Column("updated_by", sa.String(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(
            ["updated_by"],
            ["users.id"],
        ),
        sa.UniqueConstraint("category", "key", name="uq_settings_category_key"),
    )
    op.create_index("ix_system_settings_category", "system_settings", ["category"])

    # Notification Rules table
    op.create_table(
        "notification_rules",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("event_type", sa.String(length=50), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=True, server_default="true"),
        sa.Column(
            "notification_type",
            sa.String(length=20),
            nullable=True,
            server_default="email",
        ),
        sa.Column("recipients", JSONB, nullable=True),
        sa.Column("conditions", JSONB, nullable=True),
        sa.Column("created_by", sa.String(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(
            ["created_by"],
            ["users.id"],
        ),
    )
    op.create_index(
        "ix_notification_rules_event_type", "notification_rules", ["event_type"]
    )
    op.create_index("ix_notification_rules_enabled", "notification_rules", ["enabled"])

    # Notification Logs table
    op.create_table(
        "notification_logs",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("rule_id", sa.String(), nullable=True),
        sa.Column("event_type", sa.String(length=50), nullable=False),
        sa.Column("recipient", sa.String(length=255), nullable=False),
        sa.Column("subject", sa.String(length=500), nullable=True),
        sa.Column("body", sa.Text(), nullable=True),
        sa.Column("status", sa.String(length=20), nullable=True, server_default="sent"),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("sent_at", sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(
            ["rule_id"],
            ["notification_rules.id"],
        ),
    )
    op.create_index(
        "ix_notification_logs_event_type", "notification_logs", ["event_type"]
    )
    op.create_index("ix_notification_logs_sent_at", "notification_logs", ["sent_at"])

    # Insert default email settings
    op.execute("""
        INSERT INTO system_settings (id, category, key, value, value_type, description)
        VALUES
            (gen_random_uuid()::text, 'email', 'smtp_host', 'smtp.gmail.com', 'string', 'SMTP server hostname'),
            (gen_random_uuid()::text, 'email', 'smtp_port', '587', 'integer', 'SMTP server port'),
            (gen_random_uuid()::text, 'email', 'smtp_use_tls', 'true', 'boolean', 'Use TLS for SMTP connection'),
            (gen_random_uuid()::text, 'email', 'smtp_username', '', 'string', 'SMTP username for authentication'),
            (gen_random_uuid()::text, 'email', 'smtp_password', '', 'string', 'SMTP password (encrypted)'),
            (gen_random_uuid()::text, 'email', 'from_email', 'vnbui@example.com', 'string', 'From email address'),
            (gen_random_uuid()::text, 'email', 'from_name', 'vnbui Backup System', 'string', 'From name'),
            (gen_random_uuid()::text, 'backup', 'default_retention_days', '30', 'integer', 'Default retention period for backups'),
            (gen_random_uuid()::text, 'backup', 'auto_cleanup_enabled', 'true', 'boolean', 'Automatically cleanup old backups'),
            (gen_random_uuid()::text, 'storage', 'backup_storage_path', '/var/lib/vnbui/backups', 'string', 'Path to store backup files'),
            (gen_random_uuid()::text, 'storage', 'max_storage_gb', '1000', 'integer', 'Maximum storage in GB (0 = unlimited)'),
            (gen_random_uuid()::text, 'agent', 'heartbeat_interval_seconds', '300', 'integer', 'Agent heartbeat interval in seconds')
    """)


def downgrade() -> None:
    """Remove system_settings, notification_rules, and notification_logs tables"""
    op.drop_index("ix_notification_logs_sent_at", table_name="notification_logs")
    op.drop_index("ix_notification_logs_event_type", table_name="notification_logs")
    op.drop_table("notification_logs")

    op.drop_index("ix_notification_rules_enabled", table_name="notification_rules")
    op.drop_index("ix_notification_rules_event_type", table_name="notification_rules")
    op.drop_table("notification_rules")

    op.drop_index("ix_system_settings_category", table_name="system_settings")
    op.drop_table("system_settings")
