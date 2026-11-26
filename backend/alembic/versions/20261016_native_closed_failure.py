"""Settle positively closed failed native writers without publishing output."""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = "native_closed_failure"
down_revision = "native_seal_publication"
branch_labels = None
depends_on = None

DECLARATIONS = """cf_record jsonb; cf_states jsonb; cf_event jsonb; cf_paths jsonb;
 cf_expected_paths jsonb; cf_job text; cf_prior text;
 """

GUARD = r"""
 IF TG_OP='INSERT' AND NEW.native_closed_failure IS NOT NULL THEN
   RAISE EXCEPTION 'Native failure closure needs original custody' USING ERRCODE='23514';
 END IF;
 IF TG_OP='UPDATE' AND OLD.native_closed_failure IS NOT NULL THEN
   IF NEW.native_closed_failure IS DISTINCT FROM OLD.native_closed_failure
     OR NEW.status IS DISTINCT FROM 'failed' OR NEW.capacity_state IS DISTINCT FROM 'released'
     OR (to_jsonb(NEW)-ARRAY['tags','progress']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['tags','progress']) THEN
     RAISE EXCEPTION 'Native failure closure is immutable' USING ERRCODE='23514';
   END IF;
   RETURN NEW;
 END IF;
 IF TG_OP='UPDATE' AND NEW.native_closed_failure IS NOT NULL THEN
   PERFORM pg_advisory_xact_lock(1447977557,1);
   IF current_setting('transaction_isolation')<>'read committed'
     OR current_setting('app.platform_admin',true)='true' OR current_setting('app.demo',true)='true'
     OR NULLIF(current_setting('app.user_id',true),'') IS NOT NULL
     OR current_setting('app.current_org',true) IS DISTINCT FROM OLD.org_id
     OR EXISTS(SELECT 1 FROM pg_roles WHERE rolname=current_user AND (rolsuper OR rolbypassrls))
     OR OLD.capacity_state IS DISTINCT FROM 'reserved'
     OR (OLD.status IN ('pending','running','cleanup_required','failed')) IS NOT TRUE
     OR OLD.native_no_effect IS NOT NULL
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
     OR (to_jsonb(NEW)-ARRAY['native_closed_failure']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['native_closed_failure'])
     OR jsonb_typeof(NEW.native_closed_failure) IS DISTINCT FROM 'object'
     OR NOT NEW.native_closed_failure ?& ARRAY['intent_canonical','intent_sha256','closure_canonical','closure_sha256']
     OR NEW.native_closed_failure-ARRAY['intent_canonical','intent_sha256','closure_canonical','closure_sha256']<>'{}'::jsonb
     OR octet_length(NEW.native_closed_failure::text)>4194304
     OR EXISTS(SELECT 1 FROM jsonb_each(NEW.native_closed_failure) f WHERE jsonb_typeof(f.value)<>'string')
     OR (NEW.native_closed_failure->>'intent_canonical')::jsonb IS DISTINCT FROM OLD.native_job_intent
     OR NEW.native_closed_failure->>'intent_sha256' IS DISTINCT FROM encode(sha256(convert_to(NEW.native_closed_failure->>'intent_canonical','UTF8')),'hex')
     OR NEW.native_closed_failure->>'closure_sha256' IS DISTINCT FROM encode(sha256(convert_to(NEW.native_closed_failure->>'closure_canonical','UTF8')),'hex') THEN
     RAISE EXCEPTION 'Native failure custody unavailable' USING ERRCODE='23514';
   END IF;
   cf_record:=(NEW.native_closed_failure->>'closure_canonical')::jsonb;
   IF jsonb_typeof(cf_record) IS DISTINCT FROM 'object'
     OR NOT cf_record ?& ARRAY['schema','request_sha256','backup_id','attempt_id','domain_uuid','invocation_id','begin_ack_sha256','job_ids','terminal_events','artifacts']
     OR cf_record-ARRAY['schema','request_sha256','backup_id','attempt_id','domain_uuid','invocation_id','begin_ack_sha256','job_ids','terminal_events','artifacts']<>'{}'::jsonb
     OR cf_record->>'schema' IS DISTINCT FROM 'libvirt-closed-failure/1'
     OR cf_record->>'backup_id' IS DISTINCT FROM OLD.id
     OR cf_record->>'attempt_id' IS DISTINCT FROM OLD.native_job_intent->>'attempt_id'
     OR cf_record->>'domain_uuid' IS DISTINCT FROM OLD.native_job_intent->'source'->>'domain_uuid'
     OR (cf_record->>'request_sha256' ~ '^[0-9a-f]{64}$') IS NOT TRUE
     OR (cf_record->>'begin_ack_sha256' ~ '^[0-9a-f]{64}$') IS NOT TRUE
     OR (cf_record->>'invocation_id' ~ '^[0-9a-f]{32}$') IS NOT TRUE
     OR octet_length(NEW.native_closed_failure->>'closure_canonical')>4194304
     OR EXISTS(SELECT 1 FROM jsonb_each(cf_record-ARRAY['job_ids','terminal_events','artifacts']) f WHERE jsonb_typeof(f.value)<>'string')
     OR jsonb_typeof(cf_record->'job_ids') IS DISTINCT FROM 'array'
     OR jsonb_typeof(cf_record->'terminal_events') IS DISTINCT FROM 'array'
     OR jsonb_typeof(cf_record->'artifacts') IS DISTINCT FROM 'array' THEN
     RAISE EXCEPTION 'Native closure record unavailable' USING ERRCODE='23514';
   END IF;
   SELECT jsonb_agg((value->>'target')||'.qcow2' ORDER BY value->>'target') INTO cf_expected_paths
     FROM jsonb_array_elements(OLD.native_job_intent->'source'->'disks')
     WHERE NOT (OLD.native_job_intent->'source'->'exclusions' ? (value->>'target'));
   IF cf_expected_paths IS NULL OR (jsonb_array_length(cf_expected_paths) BETWEEN 1 AND 128) IS NOT TRUE
     OR jsonb_array_length(cf_record->'job_ids')<>jsonb_array_length(cf_expected_paths)
     OR jsonb_array_length(cf_record->'artifacts')<>jsonb_array_length(cf_expected_paths)
     OR (jsonb_array_length(cf_record->'terminal_events') BETWEEN 1 AND 8192) IS NOT TRUE
     OR EXISTS(SELECT 1 FROM jsonb_array_elements(cf_record->'job_ids') j WHERE jsonb_typeof(j)<>'string' OR length(j#>>'{}')>512 OR (j#>>'{}') !~ '^[A-Za-z0-9][A-Za-z0-9._-]*$')
     OR cf_record->'job_ids' IS DISTINCT FROM (SELECT jsonb_agg(DISTINCT value ORDER BY value) FROM jsonb_array_elements(cf_record->'job_ids')) THEN
     RAISE EXCEPTION 'Native closure membership unavailable' USING ERRCODE='23514';
   END IF;
   cf_states:='{}'::jsonb;
   FOR cf_job IN SELECT jsonb_array_elements_text(cf_record->'job_ids') LOOP
     cf_states:=cf_states||jsonb_build_object(cf_job,null);
   END LOOP;
   FOR cf_event IN SELECT value FROM jsonb_array_elements(cf_record->'terminal_events') LOOP
     IF jsonb_typeof(cf_event) IS DISTINCT FROM 'object' OR NOT cf_event ?& ARRAY['id','status']
       OR cf_event-ARRAY['id','status']<>'{}'::jsonb
       OR jsonb_typeof(cf_event->'id') IS DISTINCT FROM 'string'
       OR jsonb_typeof(cf_event->'status') IS DISTINCT FROM 'string'
       OR NOT cf_states ? (cf_event->>'id') THEN
       RAISE EXCEPTION 'Native closure event unavailable' USING ERRCODE='23514';
     END IF;
     cf_prior:=cf_states->>(cf_event->>'id');
     IF (CASE cf_prior
       WHEN 'created' THEN cf_event->>'status' IN ('running','aborting')
       WHEN 'running' THEN cf_event->>'status' IN ('paused','waiting','pending','aborting','concluded')
       WHEN 'paused' THEN cf_event->>'status' IN ('running','aborting')
       WHEN 'waiting' THEN cf_event->>'status' IN ('pending','aborting','concluded')
       WHEN 'pending' THEN cf_event->>'status' IN ('aborting','concluded')
       WHEN 'aborting' THEN cf_event->>'status'='concluded'
       WHEN 'concluded' THEN cf_event->>'status'='null'
       ELSE cf_prior IS NULL AND cf_event->>'status'='created' END) IS NOT TRUE THEN
       RAISE EXCEPTION 'Native closure cycle unavailable' USING ERRCODE='23514';
     END IF;
     cf_states:=cf_states||jsonb_build_object(cf_event->>'id',cf_event->>'status');
   END LOOP;
   IF EXISTS(SELECT 1 FROM jsonb_each(cf_states) f WHERE f.value IS DISTINCT FROM '"null"'::jsonb) THEN
     RAISE EXCEPTION 'Native writer remains unclosed' USING ERRCODE='23514';
   END IF;
   cf_paths:='[]'::jsonb;
   FOR cf_event IN SELECT value FROM jsonb_array_elements(cf_record->'artifacts') LOOP
     IF jsonb_typeof(cf_event) IS DISTINCT FROM 'object'
       OR NOT cf_event ?& ARRAY['path','device','inode','size','mtime_ns','ctime_ns']
       OR cf_event-ARRAY['path','device','inode','size','mtime_ns','ctime_ns']<>'{}'::jsonb
       OR jsonb_typeof(cf_event->'path') IS DISTINCT FROM 'string'
       OR NOT cf_expected_paths ? (cf_event->>'path') OR cf_paths ? (cf_event->>'path') THEN
       RAISE EXCEPTION 'Native failed target unavailable' USING ERRCODE='23514';
     END IF;
     FOR cf_job IN SELECT unnest(ARRAY['device','inode','size','mtime_ns','ctime_ns']) LOOP
       IF jsonb_typeof(cf_event->cf_job) IS DISTINCT FROM 'number'
         OR ((cf_event->>cf_job) ~ '^[0-9]+$') IS NOT TRUE THEN
         RAISE EXCEPTION 'Native failed target identity unavailable' USING ERRCODE='23514';
       END IF;
       IF (cf_event->>cf_job)::numeric>(CASE WHEN cf_job IN ('device','inode') THEN 18446744073709551615::numeric ELSE 9223372036854775807::numeric END)
         OR (cf_job='inode' AND (cf_event->>cf_job)::numeric=0) THEN
         RAISE EXCEPTION 'Native failed target range unavailable' USING ERRCODE='23514';
       END IF;
     END LOOP;
     cf_paths:=cf_paths||jsonb_build_array(cf_event->>'path');
   END LOOP;
   NEW.capacity_state:='released'; NEW.status:='failed';
   NEW.completed_at:=clock_timestamp() AT TIME ZONE 'UTC';
   NEW.tags:=COALESCE(NEW.tags,'{}'::jsonb)||jsonb_build_object('error','Native backup failed after begin; writer closure verified, partial output retained; fresh full recommended');
   NEW.capacity_release:=jsonb_build_object('schema',1,'reason','native_failed_closed',
     'capacity_id',OLD.capacity_id,'attempt_id',OLD.native_job_intent->>'attempt_id',
     'closure_sha256',NEW.native_closed_failure->>'closure_sha256',
     'released_at',to_char(clock_timestamp() AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'));
   RETURN NEW;
 END IF;
"""


def owner_sql(original):
    marker, declaration = "\nBEGIN\n", "\nDECLARE "
    if original.count(marker) != 1 or original.count(declaration) != 1:
        raise RuntimeError("Capacity guard changed; inspect failed closure integration")
    return original.replace(declaration, declaration + DECLARATIONS, 1).replace(
        marker, marker + GUARD, 1
    )


def upgrade():
    op.execute("SET CONSTRAINTS ALL IMMEDIATE")
    op.add_column("backups", sa.Column("native_closed_failure", JSONB(), nullable=True))
    original = op.get_bind().scalar(
        sa.text(
            "SELECT pg_get_functiondef('public.vnbui_capacity_owner()'::regprocedure)"
        )
    )
    op.execute(owner_sql(original))


def downgrade():
    raise RuntimeError(
        "Native failed closure requires reviewed database/image rollback"
    )
