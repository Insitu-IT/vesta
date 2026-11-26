"""Immutable native job and closed inventory admission; no upload authority."""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "native_inventory"
down_revision = "storage_finalize"
branch_labels = None
depends_on = None


def upgrade():
    for name in ("native_job_intent", "native_inventory"):
        op.add_column("backups", sa.Column(name, postgresql.JSONB(), nullable=True))
    for name in ("native_job_transaction_id", "native_inventory_transaction_id"):
        op.add_column("backups", sa.Column(name, sa.BigInteger(), nullable=True))
    op.execute("""CREATE FUNCTION vnbui_native_inventory() RETURNS trigger
    LANGUAGE plpgsql AS $$ BEGIN
      IF TG_OP='INSERT' THEN
        IF NEW.native_job_intent IS NOT NULL OR NEW.native_inventory IS NOT NULL
          OR NEW.native_job_transaction_id IS NOT NULL OR NEW.native_inventory_transaction_id IS NOT NULL THEN
          RAISE EXCEPTION 'Native authority requires persisted backup' USING ERRCODE='23514';
        END IF;
        RETURN NEW;
      END IF;
      IF NEW.native_job_transaction_id IS DISTINCT FROM OLD.native_job_transaction_id
        OR NEW.native_inventory_transaction_id IS DISTINCT FROM OLD.native_inventory_transaction_id THEN
        RAISE EXCEPTION 'Native transaction identity is database owned' USING ERRCODE='23514';
      END IF;
      IF NEW.native_job_intent IS DISTINCT FROM OLD.native_job_intent THEN
        IF OLD.native_job_intent IS NOT NULL OR NEW.native_job_intent IS NULL
          OR jsonb_typeof(NEW.native_job_intent) IS DISTINCT FROM 'object'
          OR octet_length(NEW.native_job_intent::text)>65536
          OR NEW.native_job_intent->>'schema' IS DISTINCT FROM '1'
          OR NEW.native_job_intent->>'backup_id' IS DISTINCT FROM OLD.id
          OR NEW.native_job_intent->>'org_id' IS DISTINCT FROM OLD.org_id
          OR NEW.native_job_intent->>'actor_id' IS DISTINCT FROM OLD.initiating_user_id
          OR OLD.initiating_user_id IS NULL OR NEW.status NOT IN ('pending','running') THEN
          RAISE EXCEPTION 'Invalid native job intent' USING ERRCODE='23514';
        END IF;
        NEW.native_job_transaction_id := txid_current();
      END IF;
      IF NEW.native_inventory IS DISTINCT FROM OLD.native_inventory THEN
        IF OLD.native_inventory IS NOT NULL OR NEW.native_inventory IS NULL
          OR OLD.native_job_intent IS NULL OR OLD.native_job_transaction_id IS NULL
          OR OLD.native_job_transaction_id=txid_current()
          OR jsonb_typeof(NEW.native_inventory) IS DISTINCT FROM 'object'
          OR octet_length(NEW.native_inventory::text)>2097152
          OR NEW.native_inventory->'inventory'->>'backup_id' IS DISTINCT FROM OLD.id
          OR NEW.native_inventory->'inventory'->>'attempt_id' IS DISTINCT FROM OLD.native_job_intent->>'attempt_id'
          OR NEW.native_inventory->'inventory'->>'job_id' IS DISTINCT FROM OLD.native_job_intent->>'job_id'
          OR NEW.native_inventory->'inventory'->>'checkpoint' IS DISTINCT FROM OLD.native_job_intent->>'checkpoint'
          OR NEW.status NOT IN ('pending','running') THEN
          RAISE EXCEPTION 'Native inventory requires durable job intent' USING ERRCODE='23514';
        END IF;
        NEW.native_inventory_transaction_id := txid_current();
      END IF;
      IF NEW.status='completed' AND NEW.status IS DISTINCT FROM OLD.status
        AND OLD.native_job_intent IS NOT NULL THEN
        RAISE EXCEPTION 'Native transaction completion awaits publication' USING ERRCODE='23514';
      END IF;
      RETURN NEW;
    END $$""")
    op.execute("""CREATE TRIGGER native_inventory BEFORE INSERT OR UPDATE ON backups
      FOR EACH ROW EXECUTE FUNCTION vnbui_native_inventory()""")


def downgrade():
    raise RuntimeError("Native custody requires reviewed database/image rollback")
