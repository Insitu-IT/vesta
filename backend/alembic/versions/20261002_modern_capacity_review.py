"""Owner-only, evidence-recorded disposition of held KubeVirt attempts.

The migration never classifies or releases a row. A reviewed release requires
maintenance, explicit producer/journal/chain/object evidence and exact
publication identities. Remote effects are settled by the operator before the
function is called; a failed or ambiguous observation remains reserved.
"""

import hashlib

from alembic import op
from alembic.script import ScriptDirectory
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = "modern_capacity_review"
down_revision = "legacy_capacity_review"
branch_labels = None
depends_on = None

PREVIOUS_OWNER_SHA256 = (
    "1bc111135e5f5bc8c341012a907d53987e9bf548b9e98a29bbe82c3fc883751c"
)

MODERN_GUARD = """
 IF NEW.capacity_modern_reviews IS DISTINCT FROM OLD.capacity_modern_reviews THEN
   IF current_user <> pg_get_userbyid(
       (SELECT relowner FROM pg_class WHERE oid='public.backups'::regclass))
     OR current_setting('app.modern_capacity_review',true) IS DISTINCT FROM
       NEW.capacity_modern_reviews->-1->>'operation_id'
     OR OLD.capacity_state <> 'reserved'
     OR jsonb_typeof(OLD.capacity_modern_reviews) <> 'array'
     OR jsonb_typeof(NEW.capacity_modern_reviews) <> 'array'
     OR NEW.capacity_modern_reviews IS DISTINCT FROM
       OLD.capacity_modern_reviews || jsonb_build_array(NEW.capacity_modern_reviews->-1)
     OR ROW(NEW.id,NEW.org_id,NEW.vm_id,NEW.capacity_id,NEW.capacity_reserved_at,
            NEW.capacity_policy_revision,NEW.authority_kind,NEW.initiating_user_id,
            NEW.scheduler_occurrence_id,NEW.native_job_intent,NEW.native_inventory,
            NEW.wrapped_dek,NEW.capacity_legacy_reviews)
        IS DISTINCT FROM
        ROW(OLD.id,OLD.org_id,OLD.vm_id,OLD.capacity_id,OLD.capacity_reserved_at,
            OLD.capacity_policy_revision,OLD.authority_kind,OLD.initiating_user_id,
            OLD.scheduler_occurrence_id,OLD.native_job_intent,OLD.native_inventory,
            OLD.wrapped_dek,OLD.capacity_legacy_reviews) THEN
     RAISE EXCEPTION 'Modern review is migration-owner-only and append-only'
       USING ERRCODE='23514';
   END IF;
   IF NEW.capacity_state='reserved' THEN
     IF NEW.capacity_release IS DISTINCT FROM OLD.capacity_release
       OR NEW.status IS DISTINCT FROM OLD.status
       OR NEW.capacity_modern_reviews->-1->>'classification' NOT IN ('uncertain','occupied') THEN
       RAISE EXCEPTION 'Held review cannot free capacity' USING ERRCODE='23514';
     END IF;
   ELSIF NEW.capacity_state='released' THEN
     IF NEW.status<>'failed' OR NEW.capacity_modern_reviews->-1->>'classification'<>'released'
       OR NEW.capacity_release->>'reason'<>'reviewed_modern_quiescence'
       OR NEW.capacity_release->>'capacity_id' IS DISTINCT FROM OLD.capacity_id::text
       OR NEW.capacity_release->>'operation_id' IS DISTINCT FROM
         NEW.capacity_modern_reviews->-1->>'operation_id'
       OR NEW.capacity_release->>'journal_sha256' IS DISTINCT FROM
         NEW.capacity_modern_reviews->-1->>'journal_sha256' THEN
       RAISE EXCEPTION 'Modern release lacks bound review' USING ERRCODE='23514';
     END IF;
   ELSE
     RAISE EXCEPTION 'Unsupported modern capacity transition' USING ERRCODE='23514';
   END IF;
   RETURN NEW;
 END IF;
 IF NEW.capacity_modern_reviews IS DISTINCT FROM OLD.capacity_modern_reviews THEN
   RAISE EXCEPTION 'Modern review is owner-owned' USING ERRCODE='23514';
 END IF;
"""

REVIEW_FUNCTION = """
CREATE FUNCTION vnbui_review_modern_capacity(review jsonb) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SET search_path=pg_catalog,public AS $$
DECLARE b public.backups; prior jsonb; entry jsonb; policy jsonb;
  previous_org text; previous_platform text; decision text; field_name text;
  publications jsonb; release_record jsonb; release_hash text;
  common_keys text[]:=ARRAY['schema','operation_id','backup_id','org_id','vm_id',
    'capacity_id','classification','evidence_sha256','approved_by','ticket'];
  release_keys text[]:=ARRAY['producer_quiescence_sha256','chain_custody_sha256',
    'object_custody_sha256','journal_sha256','publication_ids'];
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
   RAISE EXCEPTION 'Invalid modern review envelope' USING ERRCODE='23514';
 END IF;
 FOR field_name IN SELECT unnest(common_keys) LOOP
   IF field_name<>'schema' AND jsonb_typeof(review->field_name) IS DISTINCT FROM 'string' THEN
     RAISE EXCEPTION 'Modern review identity/evidence must be text' USING ERRCODE='23514';
   END IF;
 END LOOP;
 decision:=review->>'classification';
 IF decision='released' THEN
   IF review-common_keys-release_keys <> '{}'::jsonb
     OR NOT review ?& release_keys
     OR review->>'producer_quiescence_sha256' !~ '^[0-9a-f]{64}$'
     OR review->>'chain_custody_sha256' !~ '^[0-9a-f]{64}$'
     OR review->>'object_custody_sha256' !~ '^[0-9a-f]{64}$'
     OR review->>'journal_sha256' !~ '^[0-9a-f]{64}$'
     OR jsonb_typeof(review->'publication_ids') <> 'array' THEN
     RAISE EXCEPTION 'Release needs exact producer, chain, object and journal reviews'
       USING ERRCODE='23514';
   END IF;
   FOR field_name IN SELECT unnest(release_keys[1:4]) LOOP
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
   IF NOT FOUND THEN RAISE EXCEPTION 'Review organization unavailable' USING ERRCODE='23514'; END IF;
   SELECT * INTO b FROM public.backups WHERE id=review->>'backup_id'
     AND org_id=review->>'org_id' AND vm_id=review->>'vm_id' FOR UPDATE;
   IF NOT FOUND OR b.capacity_id::text IS DISTINCT FROM review->>'capacity_id'
     OR b.capacity_state NOT IN ('reserved','released') THEN
     RAISE EXCEPTION 'Modern capacity identity changed' USING ERRCODE='23514';
   END IF;
   FOR prior IN SELECT value FROM jsonb_array_elements(b.capacity_modern_reviews) LOOP
     IF prior->>'operation_id'=review->>'operation_id' THEN
       IF prior-'reviewed_at' IS DISTINCT FROM review THEN
         RAISE EXCEPTION 'Modern review operation ID reused with different evidence'
           USING ERRCODE='23514';
       END IF;
       PERFORM set_config('app.current_org',COALESCE(previous_org,''),true);
       PERFORM set_config('app.platform_admin',COALESCE(previous_platform,''),true);
       RETURN jsonb_build_object('disposition','already_recorded',
         'capacity_state',b.capacity_state,'operation_id',review->>'operation_id',
         'release_sha256',CASE WHEN b.capacity_state='released' THEN
           encode(sha256(convert_to(b.capacity_release::text,'UTF8')),'hex') ELSE NULL END);
     END IF;
   END LOOP;
   IF b.capacity_state<>'reserved' OR b.status IN ('completed','deleting','deleted')
     OR b.native_job_intent IS NOT NULL OR b.native_inventory IS NOT NULL
     OR NOT EXISTS(SELECT 1 FROM public.vms WHERE id=b.vm_id AND org_id=b.org_id
       AND provider='kubevirt') THEN
     RAISE EXCEPTION 'Modern KubeVirt hold unavailable' USING ERRCODE='23514';
   END IF;
   PERFORM pg_advisory_xact_lock(1447977557,1);
   PERFORM set_config('app.platform_admin','true',true);
   IF EXISTS(SELECT 1 FROM public.backups WHERE id<>b.id AND
     capacity_modern_reviews @> jsonb_build_array(
       jsonb_build_object('operation_id',review->>'operation_id'))) THEN
     RAISE EXCEPTION 'Modern review operation ID already belongs to another row'
       USING ERRCODE='23514';
   END IF;
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
     RAISE EXCEPTION 'Capacity policy unavailable' USING ERRCODE='23514';
   END IF;
   entry:=review || jsonb_build_object('reviewed_at',
     to_char(clock_timestamp() AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'));
   PERFORM set_config('app.modern_capacity_review',review->>'operation_id',true);
   IF decision='released' THEN
     IF policy->'maintenance' IS DISTINCT FROM 'true'::jsonb
       OR EXISTS(SELECT 1 FROM public.storage_lineage_generations
         WHERE backup_id=b.id AND org_id=b.org_id)
       OR EXISTS(SELECT 1 FROM public.backup_queue
         WHERE started_backup_id=b.id AND status IN ('queued','processing','claimed','running')) THEN
       RAISE EXCEPTION 'Producer, policy or lineage is not terminal'
         USING ERRCODE='23514';
     END IF;
     SELECT coalesce(jsonb_agg(id ORDER BY id),'[]'::jsonb) INTO publications
       FROM public.s3_publications WHERE backup_id=b.id AND org_id=b.org_id;
     IF jsonb_array_length(publications)=0
       OR publications IS DISTINCT FROM review->'publication_ids'
       OR NOT EXISTS(SELECT 1 FROM public.s3_publications
         WHERE backup_id=b.id AND org_id=b.org_id AND kind='payload')
       OR EXISTS(SELECT 1 FROM public.s3_publications
         WHERE backup_id=b.id AND org_id=b.org_id AND state='published') THEN
       RAISE EXCEPTION 'Exact unpublished storage custody required'
         USING ERRCODE='23514';
     END IF;
     UPDATE public.s3_publications SET state='deleted'
       WHERE backup_id=b.id AND org_id=b.org_id AND state<>'deleted';
     UPDATE public.backup_queue SET status='failed'
       WHERE started_backup_id=b.id AND status IN ('started','held');
     release_record:=jsonb_build_object('schema',1,'capacity_id',b.capacity_id,
       'operation_id',review->>'operation_id','reason','reviewed_modern_quiescence',
       'evidence_sha256',review->>'evidence_sha256',
       'journal_sha256',review->>'journal_sha256',
       'released_at',entry->>'reviewed_at');
     UPDATE public.backups SET status='failed',capacity_state='released',
       capacity_release=release_record,
       capacity_modern_reviews=b.capacity_modern_reviews || jsonb_build_array(entry)
       WHERE id=b.id AND org_id=b.org_id;
     release_hash:=encode(sha256(convert_to(release_record::text,'UTF8')),'hex');
   ELSE
     UPDATE public.backups SET
       capacity_modern_reviews=b.capacity_modern_reviews || jsonb_build_array(entry)
       WHERE id=b.id AND org_id=b.org_id;
   END IF;
   PERFORM set_config('app.modern_capacity_review','',true);
   PERFORM set_config('app.current_org',COALESCE(previous_org,''),true);
   PERFORM set_config('app.platform_admin',COALESCE(previous_platform,''),true);
   RETURN jsonb_build_object('disposition','recorded','capacity_state',
     CASE WHEN decision='released' THEN 'released' ELSE 'reserved' END,
     'operation_id',review->>'operation_id','release_sha256',release_hash);
 EXCEPTION WHEN OTHERS THEN
   PERFORM set_config('app.modern_capacity_review','',true);
   PERFORM set_config('app.current_org',COALESCE(previous_org,''),true);
   PERFORM set_config('app.platform_admin',COALESCE(previous_platform,''),true);
   RAISE;
 END;
END $$
"""


def _owner_sql():
    revisions = ScriptDirectory.from_config(op.get_context().config)
    predecessor = revisions.get_revision("legacy_capacity_review").module
    original = predecessor._previous_owner_sql()
    if hashlib.sha256(original.encode()).hexdigest() != PREVIOUS_OWNER_SHA256:
        raise RuntimeError("Current capacity trigger source changed; review migration")
    # The historical migration splices its new guard before the old INSERT
    # expression; anchor on the actual resulting SQL, not an assumed rewrite.
    insert_anchor = "IF NEW.capacity_legacy_reviews IS DISTINCT FROM '[]'::jsonb OR NEW.capacity_state IS DISTINCT FROM 'unreserved'"
    if original.count(insert_anchor) != 1:
        raise RuntimeError("Capacity insert guard changed")
    original = original.replace(
        insert_anchor,
        "IF NEW.capacity_modern_reviews IS DISTINCT FROM '[]'::jsonb OR "
        + insert_anchor.removeprefix("IF "),
        1,
    )
    review_anchor = (
        " IF NEW.capacity_legacy_reviews IS DISTINCT FROM OLD.capacity_legacy_reviews THEN\n"
        "   RAISE EXCEPTION 'Historical review is operator-owned' USING ERRCODE='23514';\n"
        " END IF;\n"
    )
    if original.count(review_anchor) != 1:
        raise RuntimeError("Historical review guard changed")
    return original.replace(review_anchor, MODERN_GUARD + review_anchor, 1)


def upgrade():
    # Fresh single-transaction upgrades created this in capacity_prerequisite
    # before its historical-row UPDATE. Installations that already applied that
    # predecessor still need it here, in a new transaction with no pending
    # backup audit trigger events.
    present = (
        op.get_bind()
        .execute(
            sa.text(
                "SELECT EXISTS(SELECT 1 FROM information_schema.columns WHERE "
                "table_schema='public' AND table_name='backups' AND "
                "column_name='capacity_modern_reviews')"
            )
        )
        .scalar_one()
    )
    if not present:
        op.add_column(
            "backups",
            sa.Column(
                "capacity_modern_reviews",
                JSONB(),
                nullable=False,
                server_default=sa.text("'[]'::jsonb"),
            ),
        )
    op.execute(_owner_sql())
    op.execute(REVIEW_FUNCTION)
    op.execute("REVOKE ALL ON FUNCTION vnbui_review_modern_capacity(jsonb) FROM PUBLIC")


def downgrade():
    raise RuntimeError("Modern capacity reviews require reviewed rollback")
