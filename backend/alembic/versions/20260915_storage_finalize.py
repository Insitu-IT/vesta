"""Durable finalize and checkpoint facts; neither publishes a backup."""

from alembic import op
import sqlalchemy as sa

revision = "storage_finalize"
down_revision = "storage_control"
branch_labels = None
depends_on = None


def upgrade():
    for name in ("finalize_intent", "checkpoint_proof"):
        op.add_column("s3_publications", sa.Column(name, sa.JSON()))
    for name in ("finalize_transaction_id", "checkpoint_transaction_id"):
        op.add_column("s3_publications", sa.Column(name, sa.BigInteger()))
    op.execute("""CREATE FUNCTION vnbui_storage_finalize() RETURNS trigger
    LANGUAGE plpgsql AS $$
    BEGIN
      IF TG_OP='INSERT' THEN
        IF NEW.finalize_intent IS NOT NULL OR NEW.checkpoint_proof IS NOT NULL
          OR NEW.finalize_transaction_id IS NOT NULL OR NEW.checkpoint_transaction_id IS NOT NULL THEN
          RAISE EXCEPTION 'Finalize requires prior durable acceptance' USING ERRCODE='23514';
        END IF;
        RETURN NEW;
      END IF;
      IF NEW.finalize_transaction_id IS DISTINCT FROM OLD.finalize_transaction_id
        OR NEW.checkpoint_transaction_id IS DISTINCT FROM OLD.checkpoint_transaction_id THEN
        RAISE EXCEPTION 'Finalize transaction identity is database owned' USING ERRCODE='23514';
      END IF;
      IF NEW.finalize_intent::jsonb IS DISTINCT FROM OLD.finalize_intent::jsonb THEN
        IF OLD.finalize_intent IS NOT NULL OR NEW.finalize_intent IS NULL
          OR jsonb_typeof(NEW.finalize_intent::jsonb) IS DISTINCT FROM 'object'
          OR octet_length(NEW.finalize_intent::text)>65536
          OR OLD.expected_plan->>'schema' IS DISTINCT FROM '3'
          OR OLD.kind IS DISTINCT FROM 'payload' OR OLD.dispatch_token IS NULL
          OR OLD.prepared_receipt IS NULL OR OLD.receipt_transaction_id IS NULL
          OR OLD.prepared_receipt->'receipt'->>'schema' IS DISTINCT FROM '2'
          OR OLD.prepared_receipt->'response'->>'accepted' IS DISTINCT FROM 'true'
          OR OLD.prepared_receipt->'response'->>'acceptance_id' IS NULL
          OR OLD.prepared_receipt->>'receipt_sha256' IS NULL
          OR NEW.finalize_intent->>'intent_id' IS NULL
          OR OLD.receipt_transaction_id=txid_current()
          OR OLD.state<>'reserved' OR NEW.state<>'reserved'
          OR NEW.finalize_intent->'binding'->>'receipt_sha256' IS DISTINCT FROM OLD.prepared_receipt->>'receipt_sha256'
          OR NEW.finalize_intent->'binding'->>'acceptance_id' IS DISTINCT FROM OLD.prepared_receipt->'response'->>'acceptance_id'
          OR NEW.finalize_intent->'binding'->>'plan_sha256' IS DISTINCT FROM OLD.expected_plan->'transaction'->>'plan_sha256'
          OR NEW.finalize_intent->'binding'->>'attempt_id' IS DISTINCT FROM OLD.expected_plan->'transaction'->'plan'->>'attempt_id' THEN
          RAISE EXCEPTION 'Invalid finalize transition' USING ERRCODE='23514';
        END IF;
        NEW.finalize_transaction_id := txid_current();
      END IF;
      IF NEW.checkpoint_proof::jsonb IS DISTINCT FROM OLD.checkpoint_proof::jsonb THEN
        IF OLD.checkpoint_proof IS NOT NULL OR NEW.checkpoint_proof IS NULL
          OR jsonb_typeof(NEW.checkpoint_proof::jsonb) IS DISTINCT FROM 'object'
          OR octet_length(NEW.checkpoint_proof::text)>65536
          OR OLD.finalize_intent IS NULL OR OLD.finalize_transaction_id IS NULL
          OR OLD.finalize_transaction_id=txid_current()
          OR OLD.state<>'reserved' OR NEW.state<>'reserved'
          OR NEW.checkpoint_proof->>'vmb_absent' IS DISTINCT FROM 'true'
          OR NEW.checkpoint_proof->>'tracker_resource_version' IS NULL
          OR NEW.checkpoint_proof->>'terminal_resource_version' IS NULL
          OR NEW.checkpoint_proof->>'checkpoint_creation_time' IS DISTINCT FROM OLD.finalize_intent->'binding'->>'started_at'
          OR NEW.checkpoint_proof->>'guest_consistency' IS DISTINCT FROM OLD.finalize_intent->'binding'->>'guest_consistency'
          OR NEW.checkpoint_proof->>'intent_id' IS DISTINCT FROM OLD.finalize_intent->>'intent_id'
          OR NEW.checkpoint_proof->>'checkpoint' IS DISTINCT FROM OLD.finalize_intent->'binding'->>'checkpoint' THEN
          RAISE EXCEPTION 'Checkpoint requires prior durable finalize intent' USING ERRCODE='23514';
        END IF;
        NEW.checkpoint_transaction_id := txid_current();
      END IF;
      IF NEW.state='published' AND OLD.state<>'published'
        AND OLD.expected_plan->>'schema'='3'
        AND (OLD.checkpoint_proof IS NULL OR OLD.checkpoint_transaction_id IS NULL
          OR OLD.checkpoint_transaction_id=txid_current()) THEN
        RAISE EXCEPTION 'Publication requires prior durable checkpoint proof' USING ERRCODE='23514';
      END IF;
      RETURN NEW;
    END $$""")
    op.execute(
        """CREATE TRIGGER storage_finalize BEFORE INSERT OR UPDATE ON s3_publications
        FOR EACH ROW EXECUTE FUNCTION vnbui_storage_finalize()"""
    )

    op.execute("""CREATE FUNCTION vnbui_storage_completion_hold() RETURNS trigger
    LANGUAGE plpgsql AS $$ BEGIN
      IF NEW.status='completed' AND OLD.status IS DISTINCT FROM NEW.status
        AND EXISTS (SELECT 1 FROM s3_publications p WHERE p.backup_id=NEW.id
          AND p.expected_plan->>'schema'='3' AND p.dispatch_token IS NOT NULL) THEN
        RAISE EXCEPTION 'Transaction completion awaits generation publication acceptance' USING ERRCODE='23514';
      END IF;
      RETURN NEW;
    END $$""")
    op.execute(
        """CREATE TRIGGER storage_completion_hold BEFORE UPDATE OF status ON backups
        FOR EACH ROW EXECUTE FUNCTION vnbui_storage_completion_hold()"""
    )


def downgrade():
    raise RuntimeError("Finalize custody requires reviewed database/image rollback")
