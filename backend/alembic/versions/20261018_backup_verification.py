"""Durable original-principal scrub custody; no simulated result enrollment."""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = "backup_verification"
down_revision = "native_fenced_failure"
branch_labels = None
depends_on = None

EXPECTED = r"""
CREATE FUNCTION public.vnbui_verification_expected(p jsonb, selected text, tenant text, agent text)
RETURNS jsonb LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
DECLARE m jsonb; r jsonb; g public.storage_lineage_generations%ROWTYPE;
 c public.s3_publications%ROWTYPE; b public.backups%ROWTYPE;
 previous public.storage_lineage_generations%ROWTYPE; root text; root_hash text;
 vm text; target jsonb; results jsonb:='[]'::jsonb; n integer:=0;
BEGIN
 IF jsonb_typeof(p) IS DISTINCT FROM 'object'
 OR p->>'schema' IS DISTINCT FROM 'vnbui-backup-verification/1'
 OR p->>'org_id' IS DISTINCT FROM tenant OR p->>'agent_id' IS DISTINCT FROM agent
 OR (p->>'provider' IN ('libvirt','kubevirt')) IS NOT TRUE
 OR NOT p ?& ARRAY['schema','verification_id','org_id','agent_id','provider','authority_sha256','bundle']
 OR p-ARRAY['schema','verification_id','org_id','agent_id','provider','authority_sha256','bundle']<>'{}'::jsonb
 OR jsonb_typeof(p->'bundle') IS DISTINCT FROM 'object'
 OR (p->'bundle')-ARRAY['schema','members']<>'{}'::jsonb
 OR (p->>'provider'='libvirt' AND p->'bundle'->>'schema' IS DISTINCT FROM 'vnbui-native-restore/1')
 OR (p->>'provider'='kubevirt' AND p->'bundle'->>'schema' IS DISTINCT FROM 'vnbui-kubevirt-restore/1')
 OR jsonb_typeof(p->'bundle'->'members') IS DISTINCT FROM 'array' THEN
   RAISE EXCEPTION 'Verification catalog unavailable' USING ERRCODE='23514';
 END IF;
 IF jsonb_array_length(p->'bundle'->'members') NOT BETWEEN 1 AND 256 THEN
   RAISE EXCEPTION 'Verification chain bounds unavailable' USING ERRCODE='23514';
 END IF;
 FOR m IN SELECT value FROM jsonb_array_elements(p->'bundle'->'members') LOOP
   n:=n+1; r:=m->'request';
   IF jsonb_typeof(m) IS DISTINCT FROM 'object'
     OR NOT m ?& ARRAY['request','receipt']
     OR (p->>'provider'='kubevirt' AND m-ARRAY['request','receipt']<>'{}'::jsonb)
     OR (p->>'provider'='libvirt' AND (NOT m ? 'push_result' OR m-ARRAY['request','receipt','push_result']<>'{}'::jsonb))
     OR r->>'org_id' IS DISTINCT FROM tenant OR r->>'agent_id' IS DISTINCT FROM agent
     OR r->'plan'->>'provider' IS DISTINCT FROM p->>'provider' THEN
     RAISE EXCEPTION 'Verification member owner unavailable' USING ERRCODE='23514';
   END IF;
   SELECT * INTO g FROM public.storage_lineage_generations
     WHERE backup_id=r->>'backup_id' AND org_id=tenant AND state='accepted';
   IF NOT FOUND OR g.accepted_request IS DISTINCT FROM r THEN
     RAISE EXCEPTION 'Accepted verification generation unavailable' USING ERRCODE='23514';
   END IF;
   SELECT * INTO b FROM public.backups WHERE id=g.backup_id AND org_id=tenant
     AND vm_id=g.vm_id AND status='completed';
   IF NOT FOUND OR NOT EXISTS(SELECT 1 FROM public.s3_publications WHERE id=g.id
      AND backup_id=g.backup_id AND org_id=tenant AND kind='chain_manifest' AND state='published') THEN
     RAISE EXCEPTION 'Retained verification backup unavailable' USING ERRCODE='23514';
   END IF;
   SELECT * INTO c FROM public.s3_publications WHERE id=r->>'reservation_id'
     AND backup_id=g.backup_id AND org_id=tenant AND kind='payload' AND state='published';
   IF NOT FOUND OR c.expected_plan::jsonb->'transaction' IS DISTINCT FROM r
     OR c.prepared_receipt::jsonb->'receipt' IS DISTINCT FROM m->'receipt'
     OR c.prepared_receipt->>'receipt_sha256' IS DISTINCT FROM g.receipt_sha256
     OR c.prepared_receipt::jsonb->'response'->'accepted' IS DISTINCT FROM 'true'::jsonb
     OR c.prepared_receipt->'response'->>'receipt_sha256' IS DISTINCT FROM g.receipt_sha256
     OR (p->>'provider'='libvirt' AND b.native_inventory::jsonb->'push_result' IS DISTINCT FROM m->'push_result') THEN
     RAISE EXCEPTION 'Original verification receipt unavailable' USING ERRCODE='23514';
   END IF;
   IF n=1 THEN
     root:=g.backup_id; root_hash:=g.receipt_sha256; vm:=g.vm_id; target:=r->'plan'->'target';
     IF r->'plan'->'parent' IS DISTINCT FROM 'null'::jsonb OR r->'plan'->>'backup_type' IS DISTINCT FROM 'full' THEN
       RAISE EXCEPTION 'Verification full root unavailable' USING ERRCODE='23514';
     END IF;
   ELSE
     IF r->'plan'->>'backup_type' IS DISTINCT FROM 'incremental'
       OR r->'plan'->'parent' IS DISTINCT FROM jsonb_build_object('backup_id',previous.backup_id,
         'root_backup_id',previous.root_backup_id,'receipt_sha256',previous.receipt_sha256,
         'generation_id',previous.id,'tracker_uid',previous.tracker_uid,'checkpoint',previous.checkpoint)
       OR g.tracker_uid IS DISTINCT FROM previous.tracker_uid THEN
       RAISE EXCEPTION 'Verification parent continuity unavailable' USING ERRCODE='23514';
     END IF;
   END IF;
   IF g.vm_id IS DISTINCT FROM vm OR g.root_backup_id IS DISTINCT FROM root
      OR g.root_receipt_sha256 IS DISTINCT FROM root_hash
      OR r->'plan'->'source'->>'vm_id' IS DISTINCT FROM vm OR r->'plan'->'target' IS DISTINCT FROM target
      OR NOT EXISTS(SELECT 1 FROM public.vms WHERE id=vm AND org_id=tenant AND agent_id=agent) THEN
     RAISE EXCEPTION 'Verification source or target changed' USING ERRCODE='23514';
   END IF;
   results:=results||jsonb_build_array(jsonb_build_object('backup_id',g.backup_id,
      'reservation_id',c.id,'plan_sha256',r->>'plan_sha256','receipt_sha256',g.receipt_sha256,
      'objects',jsonb_array_length(m->'receipt'->'objects')));
   previous:=g;
 END LOOP;
 IF previous.backup_id IS DISTINCT FROM selected THEN
   RAISE EXCEPTION 'Selected verification point unavailable' USING ERRCODE='23514';
 END IF;
 RETURN jsonb_build_object('schema','vnbui-chain-verification/1','provider',p->>'provider',
   'org_id',tenant,'agent_id',agent,'vm_id',vm,'members',results);
END $$;
"""

GUARD = r"""
CREATE FUNCTION public.vnbui_verification_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
DECLARE p jsonb; a jsonb; active boolean; expected jsonb; policy jsonb; previous_platform text; positive boolean;
BEGIN
 IF TG_OP='DELETE' THEN
   RAISE EXCEPTION 'Verification custody is retained' USING ERRCODE='23514';
 END IF;
 IF TG_OP='UPDATE' AND OLD.verification_type IS DISTINCT FROM 'artifact_scrub' THEN
   IF to_jsonb(NEW) IS DISTINCT FROM to_jsonb(OLD) THEN
     RAISE EXCEPTION 'Historical verification evidence is immutable' USING ERRCODE='23514';
   END IF;
   RETURN NEW;
 END IF;
 IF NEW.verification_type IS DISTINCT FROM 'artifact_scrub'
   OR NEW.verification_plan_canonical IS NULL OR NEW.verification_authority_canonical IS NULL
   OR octet_length(NEW.verification_plan_canonical)>33488896
   OR octet_length(NEW.verification_authority_canonical)>4096
   OR NEW.verification_plan_sha256 IS DISTINCT FROM encode(sha256(convert_to(NEW.verification_plan_canonical,'UTF8')),'hex')
   OR NEW.verification_cancel_requested IS NULL
   OR current_setting('app.current_org',true) IS DISTINCT FROM NEW.org_id
   OR current_setting('app.platform_admin',true)='true' OR current_setting('app.demo',true)='true' THEN
   RAISE EXCEPTION 'Original verification custody unavailable' USING ERRCODE='23514';
 END IF;
 p:=NEW.verification_plan_canonical::jsonb; a:=NEW.verification_authority_canonical::jsonb;
 IF p->>'verification_id' IS DISTINCT FROM NEW.id
   OR p->>'org_id' IS DISTINCT FROM NEW.org_id OR p->>'agent_id' IS DISTINCT FROM NEW.verification_agent_id
   OR p->>'authority_sha256' IS DISTINCT FROM encode(sha256(convert_to(NEW.verification_authority_canonical,'UTF8')),'hex')
   OR jsonb_typeof(a) IS DISTINCT FROM 'object'
   OR NOT a ?& ARRAY['actor_id','org_id','role','org_epoch']
   OR a-ARRAY['actor_id','org_id','role','org_epoch']<>'{}'::jsonb
   OR a->>'actor_id' IS DISTINCT FROM NEW.created_by OR a->>'org_id' IS DISTINCT FROM NEW.org_id
   OR (a->>'role' IN ('admin','operator')) IS NOT TRUE
   OR jsonb_typeof(a->'org_epoch') IS DISTINCT FROM 'number'
   OR (a->>'org_epoch' ~ '^[0-9]+$') IS NOT TRUE
   OR NEW.created_by IS NULL OR NEW.verification_agent_id IS NULL
   OR NOT EXISTS(SELECT 1 FROM public.agents WHERE id=NEW.verification_agent_id AND org_id=NEW.org_id) THEN
   RAISE EXCEPTION 'Verification principal binding unavailable' USING ERRCODE='23514';
 END IF;
 active:=EXISTS(SELECT 1 FROM public.organizations o JOIN public.users u ON u.org_id=o.id
   WHERE o.id=NEW.org_id AND o.enabled AND u.id=NEW.created_by AND u.is_active
     AND u.role=a->>'role' AND o.scheduler_epoch::text=a->>'org_epoch');
 positive:=TG_OP='INSERT' OR NEW.status='passed';
 IF TG_OP='UPDATE' THEN
   positive:=positive OR NEW.verification_read_attempts IS DISTINCT FROM OLD.verification_read_attempts
     OR NEW.verification_read_limit IS DISTINCT FROM OLD.verification_read_limit;
 END IF;
 IF positive THEN
   IF NULLIF(current_setting('app.user_id',true),'') IS DISTINCT FROM NEW.created_by THEN
     RAISE EXCEPTION 'Verification positive work requires original principal scope' USING ERRCODE='23514';
   END IF;
   PERFORM pg_advisory_xact_lock(1447977557,1);
   previous_platform:=current_setting('app.platform_admin',true);
   BEGIN
     PERFORM set_config('app.platform_admin','true',true);
     SELECT value::jsonb INTO policy FROM public.settings_v3 WHERE key='backup.capacity_admission';
     PERFORM set_config('app.platform_admin',COALESCE(previous_platform,'false'),true);
   EXCEPTION WHEN OTHERS THEN
     PERFORM set_config('app.platform_admin',COALESCE(previous_platform,'false'),true);
     RAISE;
   END;
   IF policy IS NULL OR jsonb_typeof(policy) IS DISTINCT FROM 'object'
     OR NOT policy ?& ARRAY['schema','revision','limit','maintenance']
     OR policy-ARRAY['schema','revision','limit','maintenance']<>'{}'::jsonb
     OR policy->'schema' IS DISTINCT FROM '1'::jsonb
     OR jsonb_typeof(policy->'revision') IS DISTINCT FROM 'number'
     OR (policy->>'revision' ~ '^[1-9][0-9]*$') IS NOT TRUE
     OR (policy->>'revision')::numeric>9223372036854775807
     OR jsonb_typeof(policy->'limit') IS DISTINCT FROM 'number'
     OR (policy->>'limit' ~ '^[1-9][0-9]*$') IS NOT TRUE
     OR (policy->>'limit')::numeric NOT BETWEEN 1 AND 100000
     OR policy->'maintenance' IS DISTINCT FROM 'false'::jsonb THEN
     RAISE EXCEPTION 'Verification reads require open installation admission' USING ERRCODE='23514';
   END IF;
 END IF;
 IF TG_OP='INSERT' THEN
   IF EXISTS(SELECT 1 FROM public.backup_verifications
       WHERE org_id=NEW.org_id AND backup_id=NEW.backup_id
         AND verification_type='artifact_scrub' AND status NOT IN ('passed','failed','cancelled'))
     OR (SELECT count(*) FROM public.backup_verifications
       WHERE org_id=NEW.org_id AND verification_agent_id=NEW.verification_agent_id
         AND verification_type='artifact_scrub' AND status NOT IN ('passed','failed','cancelled'))>=16 THEN
     RAISE EXCEPTION 'Verification unfinished queue is bounded' USING ERRCODE='23514';
   END IF;
   IF NEW.status IS DISTINCT FROM 'pending' OR NOT active
     OR NULLIF(current_setting('app.user_id',true),'') IS DISTINCT FROM NEW.created_by
     OR NEW.verification_bound_xid IS NOT NULL OR NEW.verification_worker_id IS NOT NULL
     OR NEW.verification_worker_xid IS NOT NULL OR NEW.verification_result IS NOT NULL
     OR NEW.verification_cancel_requested OR NEW.started_at IS NOT NULL OR NEW.completed_at IS NOT NULL THEN
     RAISE EXCEPTION 'Verification requires original pending admission' USING ERRCODE='23514';
   END IF;
   IF NEW.verification_read_attempts IS DISTINCT FROM 0 OR NEW.verification_read_limit IS DISTINCT FROM 3
      OR NEW.verification_last_busy_attempt IS DISTINCT FROM 0 THEN
     RAISE EXCEPTION 'Verification starts with a bounded read budget' USING ERRCODE='23514';
   END IF;
   PERFORM public.vnbui_verification_expected(p,NEW.backup_id,NEW.org_id,NEW.verification_agent_id);
   NEW.verification_bound_xid:=txid_current();
   RETURN NEW;
 END IF;
 IF (to_jsonb(NEW)-ARRAY['status','result_message','started_at','completed_at','verification_worker_id','verification_result','verification_cancel_requested','verification_read_attempts','verification_read_limit','verification_next_poll_at','verification_last_busy_attempt'])
    IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['status','result_message','started_at','completed_at','verification_worker_id','verification_result','verification_cancel_requested','verification_read_attempts','verification_read_limit','verification_next_poll_at','verification_last_busy_attempt'])
   OR (OLD.verification_cancel_requested AND NOT NEW.verification_cancel_requested) THEN
   RAISE EXCEPTION 'Verification original plan is immutable' USING ERRCODE='23514';
 END IF;
 IF NEW.verification_read_attempts IS NULL OR NEW.verification_read_limit IS NULL
   OR NEW.verification_last_busy_attempt IS NULL
   OR NEW.verification_last_busy_attempt<OLD.verification_last_busy_attempt
   OR NEW.verification_last_busy_attempt>NEW.verification_read_attempts
   OR NEW.verification_read_attempts<OLD.verification_read_attempts
   OR NEW.verification_read_attempts>OLD.verification_read_attempts+1
   OR NEW.verification_read_limit<OLD.verification_read_limit
   OR NEW.verification_read_attempts>NEW.verification_read_limit THEN
   RAISE EXCEPTION 'Verification read budget is monotonic' USING ERRCODE='23514';
 END IF;
 IF NEW.verification_last_busy_attempt IS DISTINCT FROM OLD.verification_last_busy_attempt THEN
   IF NEW.verification_last_busy_attempt<>OLD.verification_read_attempts
     OR NEW.verification_read_attempts<>OLD.verification_read_attempts
     OR NEW.verification_read_limit<>OLD.verification_read_limit+1
     OR NEW.status<>'held' OR NOT active OR NEW.verification_cancel_requested
     OR OLD.verification_bound_xid>=txid_current()
     OR NULLIF(current_setting('app.user_id',true),'') IS DISTINCT FROM NEW.created_by THEN
     RAISE EXCEPTION 'Busy credit requires one prior original admission attempt' USING ERRCODE='23514';
   END IF;
 ELSIF NEW.verification_read_limit IS DISTINCT FROM OLD.verification_read_limit THEN
   IF NEW.verification_read_limit<>OLD.verification_read_limit+3 OR OLD.status<>'held'
     OR NEW.verification_read_attempts<>OLD.verification_read_attempts OR NOT active
     OR NEW.verification_cancel_requested
     OR NULLIF(current_setting('app.user_id',true),'') IS DISTINCT FROM NEW.created_by THEN
     RAISE EXCEPTION 'Verification budget renewal requires original operator' USING ERRCODE='23514';
   END IF;
 END IF;
 IF NEW.verification_read_attempts IS DISTINCT FROM OLD.verification_read_attempts
   AND (NOT active OR NEW.verification_cancel_requested OR OLD.verification_bound_xid>=txid_current()) THEN
   RAISE EXCEPTION 'Verification read requires prior original authority' USING ERRCODE='23514';
 END IF;
 IF OLD.status IN ('passed','failed','cancelled') AND to_jsonb(NEW) IS DISTINCT FROM to_jsonb(OLD) THEN
   RAISE EXCEPTION 'Verification terminal evidence is immutable' USING ERRCODE='23514';
 END IF;
 IF NEW.verification_worker_id IS DISTINCT FROM OLD.verification_worker_id THEN
   IF OLD.verification_worker_id IS NOT NULL OR NEW.verification_worker_id IS NULL
     OR (NEW.verification_worker_id ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$') IS NOT TRUE
     OR NEW.verification_worker_id='00000000-0000-0000-0000-000000000000'
     OR OLD.verification_bound_xid>=txid_current() THEN
     RAISE EXCEPTION 'Verification worker requires prior original custody' USING ERRCODE='23514';
   END IF;
   NEW.verification_worker_xid:=txid_current();
 END IF;
 IF (NEW.status IN ('pending','running','held','failed','passed','cancelled')) IS NOT TRUE
   OR (NEW.status<>'passed' AND NEW.verification_result IS NOT NULL)
   OR (NEW.status IN ('running','passed') AND NEW.verification_worker_id IS NULL) THEN
   RAISE EXCEPTION 'Invalid verification result state' USING ERRCODE='23514';
 END IF;
 IF NEW.status='cancelled' AND (NOT NEW.verification_cancel_requested
    OR NEW.completed_at IS NULL OR (NEW.verification_worker_id IS NULL
      AND (OLD.verification_read_attempts<>0 OR NEW.verification_read_attempts<>0))) THEN
   RAISE EXCEPTION 'Cancellation requires original worker quiescence' USING ERRCODE='23514';
 END IF;
 IF NEW.status='passed' THEN
   IF NOT active OR NEW.verification_cancel_requested OR OLD.verification_worker_xid IS NULL
     OR OLD.verification_worker_xid>=txid_current() OR OLD.verification_worker_id IS NULL
     OR NEW.completed_at IS NULL OR NEW.started_at IS NULL THEN
     RAISE EXCEPTION 'Verification completion requires durable prior worker custody' USING ERRCODE='23514';
   END IF;
   expected:=public.vnbui_verification_expected(p,NEW.backup_id,NEW.org_id,NEW.verification_agent_id);
   IF NEW.verification_result IS DISTINCT FROM expected THEN
     RAISE EXCEPTION 'Verification result differs from original accepted inventory' USING ERRCODE='23514';
   END IF;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER backup_verification_custody BEFORE INSERT OR UPDATE OR DELETE
 ON public.backup_verifications FOR EACH ROW EXECUTE FUNCTION public.vnbui_verification_guard();
"""


def upgrade():
    for column in (
        sa.Column("verification_plan_canonical", sa.Text()),
        sa.Column("verification_plan_sha256", sa.String(64)),
        sa.Column("verification_authority_canonical", sa.Text()),
        sa.Column("verification_agent_id", sa.String(), sa.ForeignKey("agents.id")),
        sa.Column("verification_bound_xid", sa.BigInteger()),
        sa.Column("verification_worker_id", sa.String(36)),
        sa.Column("verification_worker_xid", sa.BigInteger()),
        sa.Column("verification_next_poll_at", sa.DateTime()),
        sa.Column("verification_result", JSONB()),
        sa.Column(
            "verification_read_attempts",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("0"),
        ),
        sa.Column(
            "verification_last_busy_attempt",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("0"),
        ),
        sa.Column(
            "verification_read_limit",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("3"),
        ),
        sa.Column(
            "verification_cancel_requested",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
    ):
        op.add_column("backup_verifications", column)
    op.create_index(
        "ix_backup_verifications_one_unfinished_backup",
        "backup_verifications",
        ["org_id", "backup_id"],
        unique=True,
        postgresql_where=sa.text(
            "(((verification_type)::text = 'artifact_scrub'::text) AND "
            "((status)::text <> ALL (ARRAY['passed'::text, 'failed'::text, 'cancelled'::text])))"
        ),
    )
    op.create_index(
        "ix_backup_verifications_unfinished_scrub",
        "backup_verifications",
        ["org_id", "status"],
        postgresql_where=sa.text(
            "(((verification_type)::text = 'artifact_scrub'::text) AND "
            "((status)::text <> ALL (ARRAY['passed'::text, 'failed'::text, 'cancelled'::text])))"
        ),
    )
    op.execute(EXPECTED)
    op.execute(GUARD)


def downgrade():
    bind = op.get_bind()
    if bind.execute(
        sa.text(
            "SELECT EXISTS(SELECT 1 FROM public.backup_verifications WHERE verification_plan_canonical IS NOT NULL)"
        )
    ).scalar():
        raise RuntimeError("Verification custody must be retained; downgrade refused")
    op.execute(
        "DROP TRIGGER backup_verification_custody ON public.backup_verifications"
    )
    op.execute("DROP FUNCTION public.vnbui_verification_guard()")
    op.execute("DROP FUNCTION public.vnbui_verification_expected(jsonb,text,text,text)")
    op.drop_index(
        "ix_backup_verifications_one_unfinished_backup",
        table_name="backup_verifications",
    )
    op.drop_index(
        "ix_backup_verifications_unfinished_scrub", table_name="backup_verifications"
    )
    for name in (
        "verification_last_busy_attempt",
        "verification_next_poll_at",
        "verification_read_limit",
        "verification_read_attempts",
        "verification_cancel_requested",
        "verification_result",
        "verification_worker_xid",
        "verification_worker_id",
        "verification_bound_xid",
        "verification_agent_id",
        "verification_authority_canonical",
        "verification_plan_sha256",
        "verification_plan_canonical",
    ):
        op.drop_column("backup_verifications", name)
