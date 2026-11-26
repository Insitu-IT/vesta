"""One-time producer custody after a separately committed immutable plan."""

from alembic import op
import sqlalchemy as sa

revision = "storage_dispatch_custody"
down_revision = "oidc_state_retention"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("s3_publications", sa.Column("plan_transaction_id", sa.BigInteger()))
    op.add_column("s3_publications", sa.Column("dispatch_token", sa.String()))
    op.add_column(
        "s3_publications", sa.Column("dispatch_transaction_id", sa.BigInteger())
    )
    # Existing plans predate this migration. This records a durability boundary,
    # not adoption of schema-1/2 plans into transaction/1 dispatch authority.
    op.execute("""UPDATE s3_publications SET plan_transaction_id=txid_current()
        WHERE expected_plan IS NOT NULL""")
    op.execute("""CREATE FUNCTION vnbui_storage_dispatch_custody() RETURNS trigger
        LANGUAGE plpgsql AS $$ BEGIN
        IF TG_OP='INSERT' THEN
            IF NEW.dispatch_token IS NOT NULL OR NEW.dispatch_transaction_id IS NOT NULL THEN
                RAISE EXCEPTION 'Dispatch requires a committed plan' USING ERRCODE='23514';
            END IF;
            NEW.plan_transaction_id := CASE WHEN NEW.expected_plan IS NOT NULL
                THEN txid_current() ELSE NULL END;
            RETURN NEW;
        END IF;
        IF OLD.expected_plan IS NULL AND NEW.expected_plan IS NOT NULL THEN
            NEW.plan_transaction_id := txid_current();
        ELSIF NEW.plan_transaction_id IS DISTINCT FROM OLD.plan_transaction_id THEN
            RAISE EXCEPTION 'Plan transaction is immutable' USING ERRCODE='23514';
        END IF;
        IF OLD.dispatch_token IS NOT NULL THEN
            IF ROW(NEW.dispatch_token, NEW.dispatch_transaction_id) IS DISTINCT FROM
               ROW(OLD.dispatch_token, OLD.dispatch_transaction_id) THEN
                RAISE EXCEPTION 'Producer custody cannot be transferred or reset' USING ERRCODE='23514';
            END IF;
        ELSIF NEW.dispatch_token IS NOT NULL THEN
            IF OLD.expected_plan IS NULL OR OLD.plan_transaction_id IS NULL
               OR OLD.plan_transaction_id=txid_current()
               OR OLD.state <> 'reserved' OR NEW.state <> 'reserved'
               OR NEW.kind <> 'payload' OR OLD.prepared_receipt IS NOT NULL
               OR OLD.expected_plan->>'schema' IS DISTINCT FROM '3'
               OR NEW.dispatch_token !~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$' THEN
                RAISE EXCEPTION 'Dispatch requires a committed transaction plan' USING ERRCODE='23514';
            END IF;
            NEW.dispatch_transaction_id := txid_current();
        ELSIF NEW.dispatch_transaction_id IS DISTINCT FROM OLD.dispatch_transaction_id THEN
            RAISE EXCEPTION 'Dispatch transaction has no authority' USING ERRCODE='23514';
        END IF;
        RETURN NEW;
        END $$""")
    op.execute("""CREATE TRIGGER storage_dispatch_custody
        BEFORE INSERT OR UPDATE ON s3_publications
        FOR EACH ROW EXECUTE FUNCTION vnbui_storage_dispatch_custody()""")


def downgrade():
    raise RuntimeError("Producer custody requires reviewed database/image rollback")
