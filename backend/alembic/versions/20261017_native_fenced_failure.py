"""Settle original fenced failed output, preserving custody and forcing full."""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = "native_fenced_failure"
down_revision = "native_execution_binding"
branch_labels = None
depends_on = None

DECLARATIONS = "ff_record jsonb; ff_item jsonb; ff_field text; ff_targets jsonb; ff_seen jsonb; ff_identity jsonb; "

GUARD = r"""
 IF TG_OP='INSERT' AND (NEW.native_fenced_failure IS NOT NULL OR NEW.native_fenced_failure_xid IS NOT NULL) THEN
   RAISE EXCEPTION 'Fenced failure requires original custody' USING ERRCODE='23514';
 END IF;
 IF TG_OP='UPDATE' AND OLD.native_fenced_failure IS NOT NULL THEN
   IF (to_jsonb(NEW)-ARRAY['tags','progress']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['tags','progress']) THEN
     RAISE EXCEPTION 'Fenced failure is immutable' USING ERRCODE='23514';
   END IF;
   RETURN NEW;
 END IF;
 IF TG_OP='UPDATE' AND NEW.native_fenced_failure_xid IS DISTINCT FROM OLD.native_fenced_failure_xid THEN
   RAISE EXCEPTION 'Fenced failure transaction is server owned' USING ERRCODE='23514';
 END IF;
 IF TG_OP='UPDATE' AND NEW.native_fenced_failure IS NOT NULL THEN
   PERFORM pg_advisory_xact_lock(1447977557,1);
   IF current_setting('transaction_isolation')<>'read committed'
     OR current_setting('app.platform_admin',true)='true' OR current_setting('app.demo',true)='true'
     OR NULLIF(current_setting('app.user_id',true),'') IS NOT NULL
     OR current_setting('app.current_org',true) IS DISTINCT FROM OLD.org_id
     OR EXISTS(SELECT 1 FROM pg_roles WHERE rolname=current_user AND (rolsuper OR rolbypassrls))
     OR OLD.capacity_state IS DISTINCT FROM 'reserved'
     OR (OLD.status IN ('pending','running','cleanup_required','failed')) IS NOT TRUE
     OR OLD.native_no_effect IS NOT NULL OR OLD.native_closed_failure IS NOT NULL
     OR OLD.native_job_intent IS NULL OR OLD.native_job_transaction_id IS NULL
     OR OLD.native_job_transaction_id>=txid_current()
     OR OLD.native_execution->>'state' IS DISTINCT FROM 'bound'
     OR jsonb_typeof(OLD.native_execution->'bound_xid') IS DISTINCT FROM 'number'
     OR (OLD.native_execution->>'bound_xid')::bigint>=txid_current()
     OR OLD.native_inventory IS NOT NULL OR OLD.wrapped_dek IS NOT NULL
     OR EXISTS(SELECT 1 FROM public.s3_publications WHERE backup_id=OLD.id)
     OR EXISTS(SELECT 1 FROM public.storage_lineage_generations WHERE backup_id=OLD.id)
     OR OLD.native_job_intent->>'producer' IS DISTINCT FROM 'libvirt-push-qcow2/1'
     OR OLD.native_job_intent->>'backup_id' IS DISTINCT FROM OLD.id
     OR OLD.native_job_intent->>'org_id' IS DISTINCT FROM OLD.org_id
     OR NOT EXISTS(SELECT 1 FROM public.vms WHERE id=OLD.vm_id AND org_id=OLD.org_id
          AND provider='libvirt' AND agent_id=OLD.native_job_intent->>'agent_id')
     OR (to_jsonb(NEW)-'native_fenced_failure') IS DISTINCT FROM (to_jsonb(OLD)-'native_fenced_failure')
     OR jsonb_typeof(NEW.native_fenced_failure) IS DISTINCT FROM 'object'
     OR NOT NEW.native_fenced_failure ?& ARRAY['intent_canonical','intent_sha256','fence_canonical','fence_sha256']
     OR NEW.native_fenced_failure-ARRAY['intent_canonical','intent_sha256','fence_canonical','fence_sha256']<>'{}'::jsonb
     OR octet_length(NEW.native_fenced_failure::text)>524288
     OR EXISTS(SELECT 1 FROM jsonb_each(NEW.native_fenced_failure) f WHERE jsonb_typeof(f.value)<>'string')
     OR NEW.native_fenced_failure->>'intent_canonical' IS DISTINCT FROM OLD.native_execution->>'intent_canonical'
     OR NEW.native_fenced_failure->>'intent_sha256' IS DISTINCT FROM OLD.native_execution->>'intent_sha256'
     OR NEW.native_fenced_failure->>'fence_sha256' IS DISTINCT FROM
        encode(sha256(convert_to(NEW.native_fenced_failure->>'fence_canonical','UTF8')),'hex')
     OR octet_length(NEW.native_fenced_failure->>'fence_canonical')>131072 THEN
     RAISE EXCEPTION 'Fenced failure custody unavailable' USING ERRCODE='23514';
   END IF;
   ff_record:=(NEW.native_fenced_failure->>'fence_canonical')::jsonb;
   IF jsonb_typeof(ff_record) IS DISTINCT FROM 'object'
     OR NOT ff_record ?& ARRAY['schema','request_sha256','target_binding_sha256','directory','data_directory','artifacts']
     OR ff_record-ARRAY['schema','request_sha256','target_binding_sha256','directory','data_directory','artifacts']<>'{}'::jsonb
     OR ff_record->>'schema' IS DISTINCT FROM 'libvirt-failed-output-fence/1'
     OR ff_record->'request_sha256' IS DISTINCT FROM OLD.native_execution->'request_sha256'
     OR jsonb_typeof(ff_record->'schema') IS DISTINCT FROM 'string'
     OR jsonb_typeof(ff_record->'target_binding_sha256') IS DISTINCT FROM 'string'
     OR (ff_record->>'target_binding_sha256' ~ '^[0-9a-f]{64}$') IS NOT TRUE
     OR jsonb_typeof(ff_record->'artifacts') IS DISTINCT FROM 'array' THEN
     RAISE EXCEPTION 'Fenced output record unavailable' USING ERRCODE='23514';
   END IF;
   ff_seen:='[]'::jsonb;
   FOREACH ff_field IN ARRAY ARRAY['directory','data_directory'] LOOP
     ff_identity:=ff_record->ff_field;
     IF jsonb_typeof(ff_identity) IS DISTINCT FROM 'array' OR jsonb_array_length(ff_identity)<>2 THEN
       RAISE EXCEPTION 'Fenced directory identity unavailable' USING ERRCODE='23514';
     END IF;
     FOR ff_item IN SELECT value FROM jsonb_array_elements(ff_identity) LOOP
       IF jsonb_typeof(ff_item) IS DISTINCT FROM 'number' OR (ff_item::text ~ '^[0-9]+$') IS NOT TRUE
         OR ff_item::text::numeric>18446744073709551615::numeric THEN
         RAISE EXCEPTION 'Fenced directory range unavailable' USING ERRCODE='23514';
       END IF;
     END LOOP;
     IF (ff_identity->>1)::numeric=0 OR EXISTS(SELECT 1 FROM jsonb_array_elements(ff_seen) x WHERE x=ff_identity)
       OR ff_identity->0 IS DISTINCT FROM ff_record->'directory'->0 THEN
       RAISE EXCEPTION 'Fenced directory membership unavailable' USING ERRCODE='23514';
     END IF;
     ff_seen:=ff_seen||jsonb_build_array(ff_identity);
   END LOOP;
   SELECT jsonb_agg(value->>'target' ORDER BY value->>'target') INTO ff_targets
     FROM jsonb_array_elements(OLD.native_job_intent->'source'->'disks')
     WHERE NOT (OLD.native_job_intent->'source'->'exclusions' ? (value->>'target'));
   IF ff_targets IS NULL OR (jsonb_array_length(ff_targets) BETWEEN 1 AND 128) IS NOT TRUE
     OR ff_targets IS DISTINCT FROM (SELECT jsonb_agg(value->'target' ORDER BY ordinal)
       FROM jsonb_array_elements(ff_record->'artifacts') WITH ORDINALITY a(value,ordinal)) THEN
     RAISE EXCEPTION 'Fenced target membership unavailable' USING ERRCODE='23514';
   END IF;
   FOR ff_item IN SELECT value FROM jsonb_array_elements(ff_record->'artifacts') LOOP
     IF jsonb_typeof(ff_item) IS DISTINCT FROM 'object'
       OR NOT ff_item ?& ARRAY['target','device','inode','size','verity_sha256']
       OR ff_item-ARRAY['target','device','inode','size','verity_sha256']<>'{}'::jsonb
       OR jsonb_typeof(ff_item->'verity_sha256') IS DISTINCT FROM 'string'
       OR (ff_item->>'verity_sha256' ~ '^[0-9a-f]{64}$') IS NOT TRUE THEN
       RAISE EXCEPTION 'Fenced target unavailable' USING ERRCODE='23514';
     END IF;
     FOREACH ff_field IN ARRAY ARRAY['device','inode','size'] LOOP
       IF jsonb_typeof(ff_item->ff_field) IS DISTINCT FROM 'number'
         OR ((ff_item->>ff_field) ~ '^[0-9]+$') IS NOT TRUE
         OR (ff_item->>ff_field)::numeric>(CASE WHEN ff_field='size' THEN 9223372036854775807::numeric ELSE 18446744073709551615::numeric END) THEN
         RAISE EXCEPTION 'Fenced target range unavailable' USING ERRCODE='23514';
       END IF;
     END LOOP;
     ff_identity:=jsonb_build_array(ff_item->'device',ff_item->'inode');
     IF (ff_item->>'inode')::numeric=0 OR ff_item->'device' IS DISTINCT FROM ff_record->'directory'->0
       OR EXISTS(SELECT 1 FROM jsonb_array_elements(ff_seen) x WHERE x=ff_identity) THEN
       RAISE EXCEPTION 'Fenced target identity unavailable' USING ERRCODE='23514';
     END IF;
     ff_seen:=ff_seen||jsonb_build_array(ff_identity);
   END LOOP;
   NEW.native_fenced_failure_xid:=txid_current();
   NEW.capacity_state:='released'; NEW.status:='failed';
   NEW.completed_at:=clock_timestamp() AT TIME ZONE 'UTC';
   NEW.tags:=COALESCE(NEW.tags,'{}'::jsonb)||jsonb_build_object('error','Native output fenced; partial output retained; fresh full required');
   NEW.capacity_release:=jsonb_build_object('schema',1,'reason','native_failed_fenced',
     'capacity_id',OLD.capacity_id,'attempt_id',OLD.native_job_intent->>'attempt_id',
     'fence_sha256',NEW.native_fenced_failure->>'fence_sha256',
     'released_at',to_char(clock_timestamp() AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'));
   RETURN NEW;
 END IF;
"""


def owner_sql(original):
    marker, declaration = "\nBEGIN\n", "\nDECLARE "
    if original.count(marker) != 1 or original.count(declaration) != 1:
        raise RuntimeError("Capacity guard changed; inspect fenced failure integration")
    return original.replace(declaration, declaration + DECLARATIONS, 1).replace(
        marker, marker + GUARD, 1
    )


def upgrade():
    op.execute("SET CONSTRAINTS ALL IMMEDIATE")
    op.add_column("backups", sa.Column("native_fenced_failure", JSONB(), nullable=True))
    op.add_column(
        "backups",
        sa.Column("native_fenced_failure_xid", sa.BigInteger(), nullable=True),
    )
    original = op.get_bind().scalar(
        sa.text(
            "SELECT pg_get_functiondef('public.vnbui_capacity_owner()'::regprocedure)"
        )
    )
    op.execute(owner_sql(original))


def downgrade():
    raise RuntimeError("Fenced failure requires reviewed database/image rollback")
