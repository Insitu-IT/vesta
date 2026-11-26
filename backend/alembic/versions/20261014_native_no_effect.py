"""Atomically settle original native attempts with positive pre-begin refusal."""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = "native_no_effect"
down_revision = "native_capacity_review"
branch_labels = None
depends_on = None

GUARD = r"""
 IF TG_OP='INSERT' AND NEW.native_no_effect IS NOT NULL THEN
   RAISE EXCEPTION 'Native no-effect needs original custody' USING ERRCODE='23514';
 END IF;
 IF TG_OP='UPDATE' AND OLD.native_no_effect IS NOT NULL THEN
   IF NEW.native_no_effect IS DISTINCT FROM OLD.native_no_effect
     OR NEW.status IS DISTINCT FROM 'failed' OR NEW.capacity_state IS DISTINCT FROM 'released'
     OR (to_jsonb(NEW)-ARRAY['tags','progress'])
        IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['tags','progress']) THEN
     RAISE EXCEPTION 'Native no-effect settlement is immutable' USING ERRCODE='23514';
   END IF;
   RETURN NEW;
 END IF;
 IF TG_OP='UPDATE' AND NEW.native_no_effect IS NOT NULL THEN
   PERFORM pg_advisory_xact_lock(1447977557,1);
   IF current_setting('transaction_isolation')<>'read committed'
     OR current_setting('app.platform_admin',true)='true'
     OR current_setting('app.demo',true)='true'
     OR NULLIF(current_setting('app.user_id',true),'') IS NOT NULL
     OR current_setting('app.current_org',true) IS DISTINCT FROM OLD.org_id
     OR EXISTS(SELECT 1 FROM pg_roles WHERE rolname=current_user AND (rolsuper OR rolbypassrls))
     OR OLD.capacity_state IS DISTINCT FROM 'reserved'
     OR (OLD.status IN ('pending','running','cleanup_required','failed')) IS NOT TRUE
     OR OLD.native_job_intent IS NULL OR OLD.native_job_transaction_id IS NULL
     OR OLD.native_job_transaction_id=txid_current()
     OR OLD.native_inventory IS NOT NULL OR OLD.wrapped_dek IS NOT NULL
     OR EXISTS(SELECT 1 FROM public.s3_publications WHERE backup_id=OLD.id)
     OR EXISTS(SELECT 1 FROM public.storage_lineage_generations WHERE backup_id=OLD.id)
     OR OLD.native_job_intent->>'producer' IS DISTINCT FROM 'libvirt-push-qcow2/1'
     OR OLD.native_job_intent->>'backup_id' IS DISTINCT FROM OLD.id
     OR OLD.native_job_intent->>'org_id' IS DISTINCT FROM OLD.org_id
     OR NOT EXISTS(SELECT 1 FROM public.vms WHERE id=OLD.vm_id AND org_id=OLD.org_id
       AND provider='libvirt' AND agent_id=OLD.native_job_intent->>'agent_id')
     OR (to_jsonb(NEW)-ARRAY['native_no_effect'])
        IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['native_no_effect'])
     OR jsonb_typeof(NEW.native_no_effect) IS DISTINCT FROM 'object'
     OR NOT NEW.native_no_effect ?& ARRAY['intent_canonical','intent_sha256','refusal_canonical','refusal_sha256']
     OR NEW.native_no_effect-ARRAY['intent_canonical','intent_sha256','refusal_canonical','refusal_sha256']<>'{}'::jsonb
     OR octet_length(NEW.native_no_effect::text)>262144
     OR EXISTS(SELECT 1 FROM jsonb_each(NEW.native_no_effect) f WHERE jsonb_typeof(f.value)<>'string')
     OR (NEW.native_no_effect->>'intent_canonical')::jsonb IS DISTINCT FROM OLD.native_job_intent
     OR NEW.native_no_effect->>'intent_sha256' IS DISTINCT FROM
        encode(sha256(convert_to(NEW.native_no_effect->>'intent_canonical','UTF8')),'hex')
     OR NEW.native_no_effect->>'refusal_sha256' IS DISTINCT FROM
        encode(sha256(convert_to(NEW.native_no_effect->>'refusal_canonical','UTF8')),'hex')
     OR ((NEW.native_no_effect->>'refusal_canonical')::jsonb->>'schema') IS DISTINCT FROM 'libvirt-prebegin-refusal/1'
     OR ((NEW.native_no_effect->>'refusal_canonical')::jsonb->>'backup_id') IS DISTINCT FROM OLD.id
     OR ((NEW.native_no_effect->>'refusal_canonical')::jsonb->>'attempt_id') IS DISTINCT FROM OLD.native_job_intent->>'attempt_id'
     OR ((NEW.native_no_effect->>'refusal_canonical')::jsonb->>'domain_uuid') IS DISTINCT FROM OLD.native_job_intent->'source'->>'domain_uuid'
     OR (((NEW.native_no_effect->>'refusal_canonical')::jsonb->>'request_sha256') ~ '^[0-9a-f]{64}$') IS NOT TRUE
     OR (length((NEW.native_no_effect->>'refusal_canonical')::jsonb->>'reason') BETWEEN 1 AND 2048) IS NOT TRUE
     OR NOT (NEW.native_no_effect->>'refusal_canonical')::jsonb ?& ARRAY['schema','request_sha256','backup_id','attempt_id','domain_uuid','reason']
     OR (NEW.native_no_effect->>'refusal_canonical')::jsonb-ARRAY['schema','request_sha256','backup_id','attempt_id','domain_uuid','reason']<>'{}'::jsonb
     OR EXISTS(SELECT 1 FROM jsonb_each((NEW.native_no_effect->>'refusal_canonical')::jsonb) f WHERE jsonb_typeof(f.value)<>'string') THEN
     RAISE EXCEPTION 'Native no-effect binding unavailable' USING ERRCODE='23514';
   END IF;
   NEW.capacity_state:='released'; NEW.status:='failed';
   NEW.completed_at:=clock_timestamp() AT TIME ZONE 'UTC';
   NEW.tags:=COALESCE(NEW.tags,'{}'::jsonb)||jsonb_build_object('error',
     'Native backup refused before backupBegin: '||((NEW.native_no_effect->>'refusal_canonical')::jsonb->>'reason'));
   NEW.capacity_release:=jsonb_build_object('schema',1,'reason','native_prebegin_refused',
     'capacity_id',OLD.capacity_id,'attempt_id',OLD.native_job_intent->>'attempt_id',
     'refusal_sha256',NEW.native_no_effect->>'refusal_sha256',
     'released_at',to_char(clock_timestamp() AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'));
   RETURN NEW;
 END IF;
"""


def owner_sql(original):
    # Run before earlier owner-review branches, whose early returns must not
    # permit inserting or changing this terminal evidence as a side effect.
    marker = "\nBEGIN\n"
    if original.count(marker) != 1:
        raise RuntimeError("Capacity guard changed; inspect no-effect integration")
    return original.replace(marker, marker + GUARD, 1)


def upgrade():
    # Earlier steps may backfill populated backups in this same transaction.
    # Validate their deferred events before changing the table's row shape.
    # This fires checks (and fails on invalid data); it never disables triggers
    # or introduces an intermediate commit.
    op.execute("SET CONSTRAINTS ALL IMMEDIATE")
    op.add_column("backups", sa.Column("native_no_effect", JSONB(), nullable=True))
    connection = op.get_bind()
    original = connection.scalar(
        sa.text(
            "SELECT pg_get_functiondef('public.vnbui_capacity_owner()'::regprocedure)"
        )
    )
    op.execute(owner_sql(original))


def downgrade():
    raise RuntimeError("Native settlements require reviewed database/image rollback")
