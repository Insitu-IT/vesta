"""Bind registration keys to an administrator-authorized agent identity.

Previously issued, unscoped keys cannot be safely inferred from their display
name, so migration disables them. Administrators must issue new scoped keys.
"""

from alembic import op
import sqlalchemy as sa

revision = "agent_registration_scope"
down_revision = "restore_cleanup_review"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        "agent_registration_keys", sa.Column("agent_hostname", sa.String(255))
    )
    # Both the key table and its parent users table have FORCE RLS. Without an
    # explicit migration-owner scope, the UPDATE sees no old keys, then the
    # constraint rejects their still-enabled rows. Keep the scope transaction-local.
    op.execute("SELECT set_config('app.platform_admin', 'true', true)")
    op.execute("UPDATE agent_registration_keys SET enabled = false")
    op.execute("SELECT set_config('app.platform_admin', '', true)")
    op.create_check_constraint(
        "ck_registration_key_enabled_scope",
        "agent_registration_keys",
        "enabled = false OR (agent_hostname IS NOT NULL AND length(agent_hostname) > 0)",
    )


def downgrade():
    op.drop_constraint(
        "ck_registration_key_enabled_scope", "agent_registration_keys", type_="check"
    )
    op.drop_column("agent_registration_keys", "agent_hostname")
