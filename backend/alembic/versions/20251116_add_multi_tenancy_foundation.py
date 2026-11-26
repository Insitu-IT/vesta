"""
Add multi-tenancy foundation (org_id and RLS)

Revision ID: 20251116_multi_tenancy
Revises: previous
Create Date: 2025-11-16

This migration prepares the database for multi-tenancy:
1. Adds org_id to all tenant-scoped tables
2. Creates default organization
3. Sets up PostgreSQL Row-Level Security (RLS)
4. Adds organization table

For OSS: Always uses 'default' org_id
For MSP/Enterprise: Enables proper tenant isolation
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql
import uuid

# revision identifiers, used by Alembic.
revision = "20251116_multi_tenancy"
down_revision = "20251109_agent_auth"
branch_labels = None
depends_on = None

# Default organization ID (used by OSS)
DEFAULT_ORG_ID = str(uuid.uuid4())


def upgrade():
    """
    Add multi-tenancy support
    """
    print("Adding multi-tenancy foundation...")

    # Create organizations table (Commercial feature)
    op.create_table(
        "organizations",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column(
            "parent_id", sa.String(), sa.ForeignKey("organizations.id"), nullable=True
        ),
        sa.Column("settings", postgresql.JSONB(), default={}),
        sa.Column("branding", postgresql.JSONB(), default={}),
        sa.Column("limits", postgresql.JSONB(), default={}),
        sa.Column("enabled", sa.Boolean(), default=True),
        sa.Column("created_at", sa.DateTime(), server_default=sa.func.now()),
        sa.Column(
            "updated_at",
            sa.DateTime(),
            server_default=sa.func.now(),
            onupdate=sa.func.now(),
        ),
    )

    # Insert default organization (for OSS and migration)
    op.execute(f"""
        INSERT INTO organizations (id, name, settings, enabled)
        VALUES ('{DEFAULT_ORG_ID}', 'Default Organization', '{{}}', true)
    """)

    # Add org_id to all tenant-scoped tables
    tables_to_update = [
        "backups",
        "agents",
        "vms",
        "vm_groups",
        "schedules",
        "restores",
        "backup_verifications",
        "reports",
        "report_executions",
        "saved_searches",
        "notification_rules",
        "users",  # Users belong to organizations in MSP mode
    ]

    for table in tables_to_update:
        print(f"  Adding org_id to {table}...")

        # Add column (nullable first)
        op.add_column(table, sa.Column("org_id", sa.String(), nullable=True))

        # Set all existing rows to default org
        op.execute(f"""
            UPDATE {table}
            SET org_id = '{DEFAULT_ORG_ID}'
            WHERE org_id IS NULL
        """)

        # Make non-nullable
        op.alter_column(table, "org_id", nullable=False)

        # Add foreign key
        op.create_foreign_key(
            f"fk_{table}_org_id", table, "organizations", ["org_id"], ["id"]
        )

        # Add index for performance
        op.create_index(f"idx_{table}_org_id", table, ["org_id"])

    # Enable Row-Level Security (RLS) on tenant tables
    # Note: RLS is only enforced when license has multi_tenancy feature
    print("  Setting up Row-Level Security...")

    for table in tables_to_update:
        # Enable RLS
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")

        # Create policy for normal users (tenant-scoped)
        op.execute(f"""
            CREATE POLICY tenant_isolation_{table}
            ON {table}
            FOR ALL
            USING (
                org_id = COALESCE(
                    current_setting('app.current_org', true),
                    '{DEFAULT_ORG_ID}'
                )::text
            )
        """)

        # Create policy for superusers (bypass RLS)
        op.execute(f"""
            CREATE POLICY admin_bypass_{table}
            ON {table}
            FOR ALL
            USING (
                COALESCE(
                    current_setting('app.is_superuser', true),
                    'false'
                )::boolean = true
            )
        """)

    # Create audit trigger for tenant access
    print("  Creating audit triggers...")

    op.execute("""
        CREATE TABLE IF NOT EXISTS access_audit (
            id SERIAL PRIMARY KEY,
            table_name TEXT NOT NULL,
            operation TEXT NOT NULL,
            org_id TEXT,
            user_id TEXT,
            accessed_at TIMESTAMP DEFAULT NOW(),
            row_id TEXT
        )
    """)

    op.execute("""
        CREATE OR REPLACE FUNCTION audit_access()
        RETURNS TRIGGER AS $$
        BEGIN
            INSERT INTO access_audit (
                table_name,
                operation,
                org_id,
                user_id,
                row_id
            ) VALUES (
                TG_TABLE_NAME,
                TG_OP,
                COALESCE(current_setting('app.current_org', true), NULL),
                COALESCE(current_setting('app.user_id', true), NULL),
                COALESCE(NEW.id, OLD.id)
            );
            RETURN COALESCE(NEW, OLD);
        END;
        $$ LANGUAGE plpgsql;
    """)

    # Add audit triggers to critical tables
    critical_tables = ["backups", "agents", "users"]
    for table in critical_tables:
        op.execute(f"""
            CREATE TRIGGER audit_{table}_access
                AFTER INSERT OR UPDATE OR DELETE ON {table}
                FOR EACH ROW
                EXECUTE FUNCTION audit_access()
        """)

    print("Organization isolation foundation complete")
    print(f"   Default org ID: {DEFAULT_ORG_ID}")
    print("   RLS enabled on all tenant tables")
    print("   Community installation: one default organization")


def downgrade():
    """
    Remove multi-tenancy support (rollback)
    """
    print("Rolling back multi-tenancy foundation...")

    # Drop audit triggers
    critical_tables = ["backups", "agents", "users"]
    for table in critical_tables:
        op.execute(f"DROP TRIGGER IF EXISTS audit_{table}_access ON {table}")

    op.execute("DROP FUNCTION IF EXISTS audit_access()")
    op.execute("DROP TABLE IF EXISTS access_audit")

    # Disable RLS and drop policies
    tables = [
        "backups",
        "agents",
        "vms",
        "vm_groups",
        "schedules",
        "restores",
        "backup_verifications",
        "reports",
        "report_executions",
        "saved_searches",
        "notification_rules",
        "users",
    ]

    for table in tables:
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation_{table} ON {table}")
        op.execute(f"DROP POLICY IF EXISTS admin_bypass_{table} ON {table}")
        op.execute(f"ALTER TABLE {table} DISABLE ROW LEVEL SECURITY")

    # Drop org_id columns
    for table in tables:
        op.drop_index(f"idx_{table}_org_id")
        op.drop_constraint(f"fk_{table}_org_id", table)
        op.drop_column(table, "org_id")

    # Drop organizations table
    op.drop_table("organizations")

    print("✅ Multi-tenancy foundation removed")
