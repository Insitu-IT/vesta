"""Owner-only, evidence-recorded disposition of historical capacity holds.

This does not classify predecessor rows or release any hold during migration.
Only an explicit migration-owner call can append a review. Uncertain and
occupied decisions remain held; a reviewed safe-release frees capacity while
retaining the backup, lineage, review and audit records.
"""

import hashlib

from alembic import op
from alembic.script import ScriptDirectory
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = "legacy_capacity_review"
down_revision = "native_publication"
branch_labels = None
depends_on = None

PREVIOUS_OWNER_SHA256 = (
    "6f313ee0aaaea32f161e5b8b59d0478498d2600e3b6814ecad54d74d5931a474"
)

REVIEW_GUARD = """
 IF OLD.capacity_state='unreserved' AND NEW.capacity_state='legacy_held'
   AND current_user=pg_get_userbyid(
     (SELECT relowner FROM pg_class WHERE oid='public.backups'::regclass))
   AND current_setting('app.legacy_capacity_backfill',true)='true'
   AND current_setting('app.platform_admin',true)='true'
   AND NEW.capacity_id IS NOT NULL AND NEW.capacity_reserved_at IS NOT NULL
   AND NEW.capacity_policy_revision IS NULL AND NEW.capacity_release IS NULL
   AND NEW.capacity_legacy_reviews IS NOT DISTINCT FROM OLD.capacity_legacy_reviews
   AND ROW(NEW.id,NEW.org_id,NEW.vm_id,NEW.authority_kind,
       NEW.initiating_user_id,NEW.scheduler_occurrence_id)
     IS NOT DISTINCT FROM
     ROW(OLD.id,OLD.org_id,OLD.vm_id,OLD.authority_kind,
       OLD.initiating_user_id,OLD.scheduler_occurrence_id) THEN
   RETURN NEW;
 END IF;
 IF NEW.capacity_legacy_reviews IS DISTINCT FROM OLD.capacity_legacy_reviews THEN
   IF current_user <> pg_get_userbyid(
       (SELECT relowner FROM pg_class WHERE oid='public.backups'::regclass))
     OR current_setting('app.legacy_capacity_review',true) IS DISTINCT FROM
       NEW.capacity_legacy_reviews->-1->>'operation_id'
     OR OLD.capacity_state <> 'legacy_held'
     OR jsonb_typeof(OLD.capacity_legacy_reviews) <> 'array'
     OR jsonb_typeof(NEW.capacity_legacy_reviews) <> 'array'
     OR NEW.capacity_legacy_reviews IS DISTINCT FROM
       OLD.capacity_legacy_reviews || jsonb_build_array(NEW.capacity_legacy_reviews->-1)
     OR ROW(NEW.id,NEW.org_id,NEW.vm_id,NEW.capacity_id,NEW.capacity_reserved_at,
            NEW.authority_kind,NEW.initiating_user_id,NEW.scheduler_occurrence_id,
            NEW.native_job_intent,NEW.native_inventory,NEW.wrapped_dek)
        IS DISTINCT FROM
        ROW(OLD.id,OLD.org_id,OLD.vm_id,OLD.capacity_id,OLD.capacity_reserved_at,
            OLD.authority_kind,OLD.initiating_user_id,OLD.scheduler_occurrence_id,
            OLD.native_job_intent,OLD.native_inventory,OLD.wrapped_dek) THEN
     RAISE EXCEPTION 'Historical review is migration-owner-only and append-only'
       USING ERRCODE='23514';
   END IF;
   IF NEW.capacity_state='legacy_held' THEN
     IF ROW(NEW.capacity_policy_revision,NEW.capacity_release) IS DISTINCT FROM
       ROW(OLD.capacity_policy_revision,OLD.capacity_release)
       OR NEW.capacity_legacy_reviews->-1->>'classification' NOT IN ('uncertain','occupied') THEN
       RAISE EXCEPTION 'Held historical review cannot free capacity' USING ERRCODE='23514';
     END IF;
   ELSIF NEW.capacity_state='released' THEN
     IF NEW.capacity_policy_revision IS NULL OR NEW.capacity_policy_revision<=0
       OR NEW.capacity_release->>'reason' <> 'reviewed_historical_quiescence'
       OR NEW.capacity_release->>'capacity_id' IS DISTINCT FROM OLD.capacity_id::text
       OR NEW.capacity_release->>'operation_id' IS DISTINCT FROM
         NEW.capacity_legacy_reviews->-1->>'operation_id'
       OR NEW.capacity_legacy_reviews->-1->>'classification' <> 'released' THEN
       RAISE EXCEPTION 'Historical release lacks bound review' USING ERRCODE='23514';
     END IF;
   ELSE
     RAISE EXCEPTION 'Unsupported historical capacity transition' USING ERRCODE='23514';
   END IF;
   RETURN NEW;
 END IF;
"""

REVIEW_FUNCTION = """
CREATE FUNCTION vnbui_review_legacy_capacity(review jsonb) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SET search_path=pg_catalog,public AS $$
DECLARE b public.backups; prior jsonb; entry jsonb; policy jsonb;
  previous_org text; previous_platform text; decision text; revision_number bigint;
  field_name text;
  common_keys text[]:=ARRAY['schema','operation_id','backup_id','org_id','vm_id',
    'capacity_id','classification','evidence_sha256','approved_by','ticket'];
  release_keys text[]:=ARRAY['producer_quiescence_sha256','chain_custody_sha256',
    'object_custody_sha256'];
BEGIN
 IF current_user <> pg_get_userbyid(
     (SELECT relowner FROM pg_class WHERE oid='public.backups'::regclass))
   OR (SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname=current_user) THEN
   RAISE EXCEPTION 'Migration-owner review required' USING ERRCODE='42501';
 END IF;
 IF current_setting('transaction_isolation') <> 'read committed'
   OR jsonb_typeof(review) <> 'object'
   OR review->'schema' IS DISTINCT FROM '1'::jsonb
   OR NOT review ?& common_keys
   OR review->>'classification' NOT IN ('uncertain','occupied','released')
   OR review->>'operation_id' !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
   OR review->>'capacity_id' !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
   OR review->>'evidence_sha256' !~ '^[0-9a-f]{64}$'
   OR length(review->>'approved_by') NOT BETWEEN 1 AND 200
   OR length(review->>'ticket') NOT BETWEEN 1 AND 200
   OR length(review->>'backup_id') NOT BETWEEN 1 AND 200
   OR length(review->>'org_id') NOT BETWEEN 1 AND 200
   OR length(review->>'vm_id') NOT BETWEEN 1 AND 200 THEN
   RAISE EXCEPTION 'Invalid historical review envelope' USING ERRCODE='23514';
 END IF;
 FOR field_name IN SELECT unnest(common_keys) LOOP
   IF field_name<>'schema' AND jsonb_typeof(review->field_name) IS DISTINCT FROM 'string' THEN
     RAISE EXCEPTION 'Historical review identity/evidence must be text' USING ERRCODE='23514';
   END IF;
 END LOOP;
 decision:=review->>'classification';
 IF decision='released' THEN
   IF review-common_keys-release_keys <> '{}'::jsonb
     OR NOT review ?& release_keys
     OR review->>'producer_quiescence_sha256' !~ '^[0-9a-f]{64}$'
     OR review->>'chain_custody_sha256' !~ '^[0-9a-f]{64}$'
     OR review->>'object_custody_sha256' !~ '^[0-9a-f]{64}$' THEN
     RAISE EXCEPTION 'Release needs exact producer, chain and object reviews'
       USING ERRCODE='23514';
   END IF;
   FOR field_name IN SELECT unnest(release_keys) LOOP
     IF jsonb_typeof(review->field_name) IS DISTINCT FROM 'string' THEN
       RAISE EXCEPTION 'Release evidence must be text' USING ERRCODE='23514';
     END IF;
   END LOOP;
 ELSIF review-common_keys <> '{}'::jsonb THEN
   RAISE EXCEPTION 'Held review has unknown fields' USING ERRCODE='23514';
 END IF;
 previous_org:=current_setting('app.current_org',true);
 previous_platform:=current_setting('app.platform_admin',true);
 BEGIN
   PERFORM set_config('app.current_org',review->>'org_id',true);
   PERFORM set_config('app.platform_admin','',true);
   PERFORM id FROM public.organizations WHERE id=review->>'org_id' FOR UPDATE;
   IF NOT FOUND THEN RAISE EXCEPTION 'Historical organization unavailable' USING ERRCODE='23514'; END IF;
   SELECT * INTO b FROM public.backups WHERE id=review->>'backup_id'
     AND org_id=review->>'org_id' AND vm_id=review->>'vm_id' FOR UPDATE;
   IF NOT FOUND OR b.capacity_id::text IS DISTINCT FROM review->>'capacity_id'
     OR b.capacity_state NOT IN ('legacy_held','released') THEN
     RAISE EXCEPTION 'Historical capacity identity changed' USING ERRCODE='23514';
   END IF;
   FOR prior IN SELECT value FROM jsonb_array_elements(b.capacity_legacy_reviews) LOOP
     IF prior->>'operation_id'=review->>'operation_id' THEN
       IF prior-'reviewed_at' IS DISTINCT FROM review THEN
         RAISE EXCEPTION 'Historical review operation ID reused with different evidence'
           USING ERRCODE='23514';
       END IF;
       PERFORM set_config('app.current_org',COALESCE(previous_org,''),true);
       PERFORM set_config('app.platform_admin',COALESCE(previous_platform,''),true);
       RETURN jsonb_build_object('disposition','already_recorded','capacity_state',b.capacity_state,
         'operation_id',review->>'operation_id');
     END IF;
   END LOOP;
   IF b.capacity_state <> 'legacy_held' THEN
     RAISE EXCEPTION 'Historical capacity was already released' USING ERRCODE='23514';
   END IF;
   PERFORM pg_advisory_xact_lock(1447977557,1);
   PERFORM set_config('app.platform_admin','true',true);
   IF EXISTS(SELECT 1 FROM public.backups WHERE id<>b.id AND
     capacity_legacy_reviews @> jsonb_build_array(
       jsonb_build_object('operation_id',review->>'operation_id'))) THEN
     RAISE EXCEPTION 'Historical review operation ID already belongs to another row'
       USING ERRCODE='23514';
   END IF;
   PERFORM set_config('app.platform_admin','',true);
   entry:=review || jsonb_build_object('reviewed_at',
     to_char(clock_timestamp() AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'));
   PERFORM set_config('app.legacy_capacity_review',review->>'operation_id',true);
   IF decision='released' THEN
     IF b.status NOT IN ('completed','failed','cancelled')
       OR EXISTS(SELECT 1 FROM public.backup_queue WHERE started_backup_id=b.id
         AND status IN ('pending','claimed','running'))
       OR EXISTS(SELECT 1 FROM public.s3_publications WHERE backup_id=b.id
         AND state NOT IN ('published','deleted')) THEN
       RAISE EXCEPTION 'Historical producer or publication is not terminal'
         USING ERRCODE='23514';
     END IF;
     PERFORM set_config('app.platform_admin','true',true);
     SELECT value::jsonb INTO policy FROM public.settings_v3
       WHERE key='backup.capacity_admission';
     PERFORM set_config('app.platform_admin','',true);
     IF policy IS NULL OR jsonb_typeof(policy)<>'object'
       OR NOT policy ?& ARRAY['schema','revision','limit','maintenance']
       OR policy-ARRAY['schema','revision','limit','maintenance']<>'{}'::jsonb
       OR policy->'schema' IS DISTINCT FROM '1'::jsonb
       OR (policy->>'revision') !~ '^[1-9][0-9]*$'
       OR (policy->>'revision')::numeric>9223372036854775807
       OR (policy->>'limit') !~ '^[1-9][0-9]*$'
       OR (policy->>'limit')::numeric NOT BETWEEN 1 AND 100000
       OR jsonb_typeof(policy->'maintenance') IS DISTINCT FROM 'boolean' THEN
       RAISE EXCEPTION 'Capacity policy must be enrolled before historical release'
         USING ERRCODE='23514';
     END IF;
     revision_number:=(policy->>'revision')::bigint;
     UPDATE public.backups SET capacity_state='released',
       capacity_policy_revision=revision_number,
       capacity_release=jsonb_build_object('schema',1,'capacity_id',b.capacity_id,
         'operation_id',review->>'operation_id','reason','reviewed_historical_quiescence',
         'evidence_sha256',review->>'evidence_sha256','released_at',entry->>'reviewed_at'),
       capacity_legacy_reviews=b.capacity_legacy_reviews || jsonb_build_array(entry)
       WHERE id=b.id AND org_id=b.org_id;
   ELSE
     UPDATE public.backups SET
       capacity_legacy_reviews=b.capacity_legacy_reviews || jsonb_build_array(entry)
       WHERE id=b.id AND org_id=b.org_id;
   END IF;
   PERFORM set_config('app.legacy_capacity_review','',true);
   PERFORM set_config('app.current_org',COALESCE(previous_org,''),true);
   PERFORM set_config('app.platform_admin',COALESCE(previous_platform,''),true);
   RETURN jsonb_build_object('disposition','recorded','capacity_state',
     CASE WHEN decision='released' THEN 'released' ELSE 'legacy_held' END,
     'operation_id',review->>'operation_id');
 EXCEPTION WHEN OTHERS THEN
   PERFORM set_config('app.legacy_capacity_review','',true);
   PERFORM set_config('app.current_org',COALESCE(previous_org,''),true);
   PERFORM set_config('app.platform_admin',COALESCE(previous_platform,''),true);
   RAISE;
 END;
END $$
"""


def _previous_owner_sql():
    revisions = ScriptDirectory.from_config(op.get_context().config)
    predecessor = revisions.get_revision("callback_provider_create").module
    generation = revisions.get_revision("storage_generation_publication").module
    original = predecessor.OWNER
    release_anchor = (
        " IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname=current_user "
        "AND (rolsuper OR rolbypassrls)) THEN"
    )
    if original.count(release_anchor) != 1:
        raise RuntimeError("Previous capacity release anchor changed")
    original = original.replace(
        release_anchor, generation.CAPACITY_RELEASE + release_anchor, 1
    )
    if hashlib.sha256(original.encode()).hexdigest() != PREVIOUS_OWNER_SHA256:
        raise RuntimeError("Current capacity trigger source changed; review migration")
    marker = " IF ROW(NEW.capacity_id,NEW.capacity_reserved_at,NEW.capacity_policy_revision,NEW.capacity_release)"
    if original.count(marker) != 1:
        raise RuntimeError("Previous capacity trigger anchor changed")
    insert_guard = "IF NEW.capacity_state IS DISTINCT FROM 'unreserved' OR NEW.capacity_id IS NOT NULL"
    if original.count(insert_guard) != 1:
        raise RuntimeError("Previous capacity insert guard changed")
    original = original.replace(
        insert_guard,
        "IF NEW.capacity_legacy_reviews IS DISTINCT FROM '[]'::jsonb OR "
        + insert_guard.removeprefix("IF "),
        1,
    )
    return original.replace("CREATE FUNCTION", "CREATE OR REPLACE FUNCTION", 1).replace(
        marker,
        REVIEW_GUARD
        + " IF NEW.capacity_legacy_reviews IS DISTINCT FROM OLD.capacity_legacy_reviews THEN\n"
        + "   RAISE EXCEPTION 'Historical review is operator-owned' USING ERRCODE='23514';\n"
        + " END IF;\n"
        + marker,
        1,
    )


def upgrade():
    # A fresh single-transaction Alembic upgrade backfills backups earlier in
    # this chain, leaving pending audit trigger events. Do not ALTER that table
    # again in the same transaction. Older already-applied capacity migrations
    # lack the column and have no such pending event in this upgrade.
    bind = op.get_bind()
    present = bind.execute(
        sa.text(
            "SELECT EXISTS(SELECT 1 FROM information_schema.columns WHERE "
            "table_schema='public' AND table_name='backups' AND "
            "column_name='capacity_legacy_reviews')"
        )
    ).scalar_one()
    if not present:
        op.add_column(
            "backups",
            sa.Column(
                "capacity_legacy_reviews",
                JSONB(),
                nullable=False,
                server_default=sa.text("'[]'::jsonb"),
            ),
        )
    # Repair installations that ran the predecessor backfill with a FORCE-RLS
    # non-superuser owner before that migration was corrected. This is a
    # conservative hold, never a release. The narrowly gated replacement
    # trigger is installed first; no trigger disabling or table ALTER follows
    # the historical-row update in this transaction.
    op.execute(_previous_owner_sql())
    op.execute("""DO $$ DECLARE prior text; prior_org text; held_row record;
        BEGIN
          prior:=current_setting('app.platform_admin',true);
          prior_org:=current_setting('app.current_org',true);
          PERFORM set_config('app.platform_admin','true',true);
          PERFORM set_config('app.legacy_capacity_backfill','true',true);
          FOR held_row IN SELECT id,org_id FROM public.backups
            WHERE capacity_state='unreserved' AND capacity_id IS NULL ORDER BY org_id,id LOOP
            PERFORM set_config('app.current_org',held_row.org_id,true);
            UPDATE public.backups SET capacity_state='legacy_held',
              capacity_id=gen_random_uuid(),capacity_reserved_at=clock_timestamp()
              WHERE id=held_row.id AND org_id=held_row.org_id;
          END LOOP;
          PERFORM set_config('app.legacy_capacity_backfill','',true);
          PERFORM set_config('app.current_org',COALESCE(prior_org,''),true);
          PERFORM set_config('app.platform_admin',COALESCE(prior,''),true);
        EXCEPTION WHEN OTHERS THEN
          PERFORM set_config('app.legacy_capacity_backfill','',true);
          PERFORM set_config('app.current_org',COALESCE(prior_org,''),true);
          PERFORM set_config('app.platform_admin',COALESCE(prior,''),true);
          RAISE;
        END $$""")
    op.execute(REVIEW_FUNCTION)
    op.execute("REVOKE ALL ON FUNCTION vnbui_review_legacy_capacity(jsonb) FROM PUBLIC")


def downgrade():
    raise RuntimeError("Historical capacity reviews require reviewed rollback")
