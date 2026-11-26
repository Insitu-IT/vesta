"""Enforce replay retention for previously versioned and fresh databases."""

from alembic import op

revision = "oidc_state_retention"
down_revision = "oidc_login_states"
branch_labels = None
depends_on = None


def upgrade():
    # Early draft applications of the predecessor omitted these indexes. Keep
    # this successor usable without assuming that every application was ephemeral.
    op.execute("""CREATE INDEX IF NOT EXISTS idx_oidc_login_states_org_id
        ON oidc_login_states (org_id)""")
    op.execute("""CREATE INDEX IF NOT EXISTS ix_oidc_login_states_expiry_batch
        ON oidc_login_states (org_id, expires_at, digest)""")
    op.execute(
        """CREATE OR REPLACE FUNCTION vnbui_oidc_state_transition() RETURNS trigger
        LANGUAGE plpgsql AS $$ BEGIN
        IF TG_OP='INSERT' THEN
            IF NEW.consumed_at IS NOT NULL THEN
                RAISE EXCEPTION 'OIDC state must begin unconsumed' USING ERRCODE='23514';
            END IF;
            RETURN NEW;
        END IF;
        IF TG_OP='DELETE' THEN
            IF OLD.expires_at > now() - interval '24 hours'
                AND current_setting('app.platform_admin', true) IS DISTINCT FROM 'true' THEN
                RAISE EXCEPTION 'Replay custody retention has not elapsed' USING ERRCODE='23514';
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
        END $$"""
    )


def downgrade():
    raise RuntimeError(
        "Replay retention cannot be weakened; restore the reviewed database/image backup"
    )
