"""Receipt-complete pre-finalize abort; native capacity is never released."""

from alembic import op
import sqlalchemy as sa

revision = "storage_compensation"
down_revision = "scheduled_full_policy"
branch_labels = None
depends_on = None


def upgrade():
    for name in ("cleanup_intent", "cleanup_result"):
        op.add_column("s3_publications", sa.Column(name, sa.JSON()))
    op.add_column(
        "s3_publications", sa.Column("cleanup_transaction_id", sa.BigInteger())
    )
    op.execute("""CREATE FUNCTION vnbui_storage_compensation() RETURNS trigger
    LANGUAGE plpgsql AS $$
    DECLARE b public.backups; r jsonb; i jsonb;
    BEGIN
      IF TG_OP='INSERT' THEN
        IF NEW.cleanup_intent IS NOT NULL OR NEW.cleanup_result IS NOT NULL
          OR NEW.cleanup_transaction_id IS NOT NULL THEN
          RAISE EXCEPTION 'Cleanup requires prior durable custody' USING ERRCODE='23514';
        END IF;
        RETURN NEW;
      END IF;
      IF NEW.cleanup_transaction_id IS DISTINCT FROM OLD.cleanup_transaction_id THEN
        RAISE EXCEPTION 'Cleanup transaction identity is database owned' USING ERRCODE='23514';
      END IF;
      IF OLD.cleanup_intent IS NOT NULL THEN
        IF NEW.cleanup_intent::jsonb IS DISTINCT FROM OLD.cleanup_intent::jsonb
          OR NEW.state IS DISTINCT FROM 'cleanup_required'
          OR NEW.finalize_intent IS NOT NULL OR NEW.checkpoint_proof IS NOT NULL THEN
          RAISE EXCEPTION 'Abort custody cannot reopen or finalize' USING ERRCODE='23514';
        END IF;
      END IF;
      IF NEW.cleanup_intent::jsonb IS DISTINCT FROM OLD.cleanup_intent::jsonb THEN
        SELECT * INTO b FROM public.backups WHERE id=OLD.backup_id AND org_id=OLD.org_id FOR UPDATE;
        r:=OLD.expected_plan::jsonb->'transaction'; i:=NEW.cleanup_intent::jsonb;
        IF OLD.cleanup_intent IS NOT NULL OR i IS NULL
          OR OLD.state IS DISTINCT FROM 'reserved' OR NEW.state IS DISTINCT FROM 'cleanup_required'
          OR OLD.expected_plan->>'schema' IS DISTINCT FROM '3'
          OR OLD.kind IS DISTINCT FROM 'payload' OR OLD.dispatch_token IS NULL
          OR OLD.dispatch_transaction_id IS NULL OR OLD.receipt_transaction_id IS NULL
          OR OLD.receipt_transaction_id=txid_current()
          OR OLD.prepared_receipt->'response'->>'accepted' IS DISTINCT FROM 'true'
          OR OLD.finalize_intent IS NOT NULL OR NEW.finalize_intent IS NOT NULL
          OR OLD.checkpoint_proof IS NOT NULL OR NEW.checkpoint_proof IS NOT NULL
          OR r->'plan'->>'provider' IS DISTINCT FROM 'kubevirt'
          OR r->'plan'->>'capability_profile' IS DISTINCT FROM 'db-rooted-consumer-verified/1'
          OR r->'plan' ? 'capability_evidence'
          OR b.capacity_state IS DISTINCT FROM 'reserved' OR b.capacity_id IS NULL
          OR b.status IS DISTINCT FROM 'cleanup_required'
          OR jsonb_typeof(i) IS DISTINCT FROM 'object'
          OR NOT i ?& ARRAY['schema','intent_id','backup_id','org_id','agent_id','reservation_id','attempt_id','plan_sha256','receipt_sha256','acceptance_id','capacity_id','reason']
          OR i-ARRAY['schema','intent_id','backup_id','org_id','agent_id','reservation_id','attempt_id','plan_sha256','receipt_sha256','acceptance_id','capacity_id','reason']<>'{}'::jsonb
          OR i->'schema' IS DISTINCT FROM '1'::jsonb
          OR i->>'intent_id' IS DISTINCT FROM 'abort:' || OLD.id
          OR i->>'backup_id' IS DISTINCT FROM OLD.backup_id
          OR i->>'org_id' IS DISTINCT FROM OLD.org_id
          OR i->>'agent_id' IS DISTINCT FROM r->>'agent_id'
          OR i->>'reservation_id' IS DISTINCT FROM OLD.id
          OR i->>'attempt_id' IS DISTINCT FROM r->'plan'->>'attempt_id'
          OR i->>'plan_sha256' IS DISTINCT FROM r->>'plan_sha256'
          OR i->>'receipt_sha256' IS DISTINCT FROM OLD.prepared_receipt->>'receipt_sha256'
          OR i->>'acceptance_id' IS DISTINCT FROM OLD.prepared_receipt->'response'->>'acceptance_id'
          OR i->>'capacity_id' IS DISTINCT FROM b.capacity_id::text
          OR i->>'reason' IS DISTINCT FROM 'original_native_identity_lost'
          OR EXISTS(SELECT 1 FROM jsonb_array_elements(OLD.prepared_receipt::jsonb->'receipt'->'objects') o
            WHERE jsonb_typeof(o->'version_id') IS DISTINCT FROM 'string'
              OR o->>'version_id' IN ('','null'))
          OR EXISTS(SELECT 1 FROM public.s3_publications p WHERE p.backup_id=b.id AND p.org_id=b.org_id AND p.kind='chain_manifest')
          OR EXISTS(SELECT 1 FROM public.storage_lineage_generations g WHERE g.backup_id=b.id AND g.org_id=b.org_id) THEN
          RAISE EXCEPTION 'Invalid pre-finalize abort' USING ERRCODE='23514';
        END IF;
        NEW.cleanup_transaction_id:=txid_current();
      END IF;
      IF NEW.cleanup_result::jsonb IS DISTINCT FROM OLD.cleanup_result::jsonb THEN
        SELECT * INTO b FROM public.backups WHERE id=OLD.backup_id AND org_id=OLD.org_id FOR UPDATE;
        IF OLD.cleanup_result IS NOT NULL OR OLD.cleanup_intent IS NULL
          OR OLD.cleanup_transaction_id IS NULL OR OLD.cleanup_transaction_id=txid_current()
          OR NEW.cleanup_result::jsonb IS DISTINCT FROM jsonb_build_object('schema',1,'s3_absent',true)
          OR b.capacity_state IS DISTINCT FROM 'reserved'
          OR b.capacity_id::text IS DISTINCT FROM OLD.cleanup_intent->>'capacity_id'
          OR b.status IS DISTINCT FROM 'cleanup_required' THEN
          RAISE EXCEPTION 'Invalid cleanup result' USING ERRCODE='23514';
        END IF;
      END IF;
      RETURN NEW;
    END $$""")
    op.execute(
        """CREATE TRIGGER storage_compensation BEFORE INSERT OR UPDATE ON s3_publications
      FOR EACH ROW EXECUTE FUNCTION vnbui_storage_compensation()"""
    )
    _extend_scheduler_cleanup_tags()


def _extend_scheduler_cleanup_tags():
    # Preserve the entire deferred construction/claim check. Only exact
    # server-owned hold presentation may differ from original queue tags.
    definition = op.get_bind().scalar(
        sa.text(
            "SELECT pg_get_functiondef('public.vnbui_scheduler_complete()'::regprocedure)"
        )
    )
    old = "b.tags IS DISTINCT FROM q.tags"
    if definition.count(old) != 1:
        raise RuntimeError(
            "Scheduler completion tag guard changed; review cleanup integration"
        )
    held = """
      b.status='cleanup_required' AND b.capacity_state='reserved'
      AND b.capacity_id IS NOT NULL AND b.capacity_release IS NULL
      AND b.capacity_terminal_evidence IS NULL AND q.claim_id IS NOT NULL
      AND b.tags->'cleanup_required'='true'::jsonb
      AND (coalesce(b.tags,'{}'::jsonb)-ARRAY['cleanup_required','storage_hold','error']::text[])
        IS NOT DISTINCT FROM
          (coalesce(q.tags,'{}'::jsonb)-ARRAY['cleanup_required','storage_hold','error']::text[])
      AND (b.tags->'error' IS NOT DISTINCT FROM q.tags->'error'
        OR b.tags->>'error'='Agent retained this storage transaction for reconciliation')
      AND EXISTS(SELECT 1 FROM public.s3_publications cleanup
        WHERE cleanup.backup_id=b.id AND cleanup.org_id=b.org_id AND cleanup.kind='payload'
          AND cleanup.state='cleanup_required' AND cleanup.cleanup_transaction_id IS NOT NULL
          AND cleanup.finalize_intent IS NULL AND cleanup.checkpoint_proof IS NULL
          AND cleanup.cleanup_intent->>'reason'='original_native_identity_lost'
          AND cleanup.cleanup_intent->>'backup_id'=b.id
          AND cleanup.cleanup_intent->>'org_id'=c.org_id
          AND cleanup.cleanup_intent->>'reservation_id'=cleanup.id
          AND cleanup.cleanup_intent->>'capacity_id'=b.capacity_id::text
          AND cleanup.cleanup_intent->>'agent_id'=cleanup.expected_plan->'transaction'->>'agent_id'
          AND cleanup.cleanup_intent->>'attempt_id'=cleanup.expected_plan->'transaction'->'plan'->>'attempt_id'
          AND cleanup.cleanup_intent->>'plan_sha256'=cleanup.expected_plan->'transaction'->>'plan_sha256'
          AND cleanup.cleanup_intent->>'receipt_sha256'=cleanup.prepared_receipt->>'receipt_sha256'
          AND cleanup.cleanup_intent->>'acceptance_id'=cleanup.prepared_receipt->'response'->>'acceptance_id'
          AND (b.tags->'storage_hold' IS NOT DISTINCT FROM q.tags->'storage_hold'
            OR b.tags->'storage_hold'=jsonb_build_object('schema',1,'reservation_id',cleanup.id,
              'plan_sha256',cleanup.cleanup_intent->>'plan_sha256','reason','storage_transaction_retained'))
          AND NOT EXISTS(SELECT 1 FROM public.s3_publications manifest
            WHERE manifest.backup_id=b.id AND manifest.org_id=b.org_id AND manifest.kind='chain_manifest')
          AND NOT EXISTS(SELECT 1 FROM public.storage_lineage_generations generation
            WHERE generation.backup_id=b.id AND generation.org_id=b.org_id))
    """
    op.execute(definition.replace(old, f"({old} AND NOT (({held}) IS TRUE))"))


def downgrade():
    raise RuntimeError("Compensation custody requires reviewed database/image rollback")
