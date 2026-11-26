"""Durable one-time OIDC login bindings, independent of user provisioning."""

from alembic import op
import sqlalchemy as sa

revision = "oidc_login_states"
down_revision = "vm_inventory_identity"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "oidc_login_states",
        sa.Column("digest", sa.String(64), primary_key=True),
        sa.Column("org_id", sa.String(), nullable=False),
        sa.Column("issuer", sa.Text(), nullable=False),
        sa.Column("client_id", sa.Text(), nullable=False),
        sa.Column("purpose", sa.String(32), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True)),
        sa.ForeignKeyConstraint(
            ["org_id"], ["organizations.id"], name="fk_oidc_login_states_org_id"
        ),
    )
    op.create_index("idx_oidc_login_states_org_id", "oidc_login_states", ["org_id"])
    op.create_index(
        "ix_oidc_login_states_expiry_batch",
        "oidc_login_states",
        ["org_id", "expires_at", "digest"],
    )
    op.execute("ALTER TABLE oidc_login_states ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE oidc_login_states FORCE ROW LEVEL SECURITY")
    predicate = """(org_id = NULLIF(current_setting('app.current_org', true), '')
        OR current_setting('app.platform_admin', true) = 'true')"""
    op.execute(f"""CREATE POLICY tenant_isolation_oidc_login_states
        ON oidc_login_states USING ({predicate}) WITH CHECK ({predicate})""")
    op.execute("""CREATE FUNCTION vnbui_oidc_state_transition() RETURNS trigger
        LANGUAGE plpgsql AS $$ BEGIN
        IF TG_OP='INSERT' THEN
            IF NEW.consumed_at IS NOT NULL THEN
                RAISE EXCEPTION 'OIDC state must begin unconsumed' USING ERRCODE='23514';
            END IF;
            RETURN NEW;
        END IF;
        IF TG_OP='DELETE' THEN
            IF OLD.expires_at > now()
                AND current_setting('app.platform_admin', true) IS DISTINCT FROM 'true' THEN
                RAISE EXCEPTION 'Live replay custody cannot be removed' USING ERRCODE='23514';
            END IF;
            RETURN OLD;
        END IF;
        IF ROW(NEW.digest, NEW.org_id, NEW.issuer, NEW.client_id, NEW.purpose, NEW.expires_at)
            IS DISTINCT FROM
            ROW(OLD.digest, OLD.org_id, OLD.issuer, OLD.client_id, OLD.purpose, OLD.expires_at)
            OR OLD.consumed_at IS NOT NULL OR NEW.consumed_at IS NULL THEN
            RAISE EXCEPTION 'OIDC binding is immutable and consumption is one-time'
                USING ERRCODE='23514';
        END IF;
        RETURN NEW;
        END $$""")
    op.execute(
        """CREATE TRIGGER oidc_state_transition BEFORE INSERT OR UPDATE OR DELETE ON oidc_login_states
        FOR EACH ROW EXECUTE FUNCTION vnbui_oidc_state_transition()"""
    )


def downgrade():
    op.drop_table("oidc_login_states")
    op.execute("DROP FUNCTION vnbui_oidc_state_transition()")
