"""Permit owner-reviewed retirement of an uncertain KubeVirt restore.

The migration does not retire existing work. An owner operation can do so only
after separately proving the agent journal and exact destination resources
quiescent. The original restore row and evidence remain durable.
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = "restore_cleanup_review"
down_revision = "agent_service_endpoint"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        "restores", sa.Column("kubevirt_cleanup_review", JSONB(), nullable=True)
    )
    op.execute("""
CREATE FUNCTION vnbui_guard_restore_cleanup_review() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
BEGIN
  IF OLD.kubevirt_cleanup_review IS NOT NULL THEN
    IF to_jsonb(NEW) IS DISTINCT FROM to_jsonb(OLD) THEN
      RAISE EXCEPTION 'Reviewed restore custody is immutable' USING ERRCODE='23514';
    END IF;
  ELSIF NEW.kubevirt_cleanup_review IS DISTINCT FROM OLD.kubevirt_cleanup_review THEN
    IF current_user <> pg_get_userbyid(
        (SELECT relowner FROM pg_class WHERE oid='public.restores'::regclass))
      OR OLD.status <> 'cleanup_required' OR NEW.status <> 'failed'
      OR current_setting('app.restore_cleanup_review',true) IS DISTINCT FROM
        NEW.kubevirt_cleanup_review->>'operation_id'
      OR to_jsonb(NEW)-ARRAY['status','error_message','completed_at','kubevirt_cleanup_review']
         IS DISTINCT FROM
         to_jsonb(OLD)-ARRAY['status','error_message','completed_at','kubevirt_cleanup_review']
      OR NEW.error_message IS DISTINCT FROM
        'Operator-reviewed cleanup; original journal and evidence retained' THEN
      RAISE EXCEPTION 'Restore cleanup review is owner-only' USING ERRCODE='23514';
    END IF;
  ELSIF OLD.status='cleanup_required' AND
    to_jsonb(NEW) IS DISTINCT FROM to_jsonb(OLD) THEN
    RAISE EXCEPTION 'Held restore requires owner review' USING ERRCODE='23514';
  END IF;
  RETURN NEW;
END $$;
""")
    op.execute("""CREATE TRIGGER guard_restore_cleanup_review BEFORE UPDATE ON restores
FOR EACH ROW EXECUTE FUNCTION vnbui_guard_restore_cleanup_review()""")
    op.execute("""
CREATE FUNCTION vnbui_review_restore_cleanup(review jsonb) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SET search_path=pg_catalog,public AS $$
DECLARE r public.restores; b public.backups; previous_org text;
  previous_platform text;
  required text[]:=ARRAY['schema','operation_id','restore_id','org_id','backup_id',
    'target_namespace','target_vm_name','target_pvc_names','plan_sha256',
    'result_sha256','journal_sha256','producer_quiescence_sha256',
    'resource_quiescence_sha256','evidence_sha256','approved_by','ticket'];
  pvc_names jsonb; entry jsonb;
BEGIN
  IF current_user <> pg_get_userbyid(
      (SELECT relowner FROM pg_class WHERE oid='public.restores'::regclass))
    OR (SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname=current_user)
    OR current_setting('transaction_isolation') <> 'read committed' THEN
    RAISE EXCEPTION 'Migration-owner review required' USING ERRCODE='42501';
  END IF;
  IF jsonb_typeof(review)<>'object' OR review->'schema' IS DISTINCT FROM '1'::jsonb
    OR NOT review ?& required OR review-required <> '{}'::jsonb
    OR review->>'operation_id' !~ '^[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}$'
    OR review->>'restore_id' !~ '^[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}$'
    OR review->>'plan_sha256' !~ '^[0-9a-f]{64}$'
    OR review->>'result_sha256' !~ '^[0-9a-f]{64}$'
    OR review->>'journal_sha256' !~ '^[0-9a-f]{64}$'
    OR review->>'producer_quiescence_sha256' !~ '^[0-9a-f]{64}$'
    OR review->>'resource_quiescence_sha256' !~ '^[0-9a-f]{64}$'
    OR review->>'evidence_sha256' !~ '^[0-9a-f]{64}$'
    OR jsonb_typeof(review->'target_pvc_names') <> 'array'
    OR length(review->>'approved_by') NOT BETWEEN 1 AND 200
    OR length(review->>'ticket') NOT BETWEEN 1 AND 200 THEN
    RAISE EXCEPTION 'Invalid restore cleanup review envelope' USING ERRCODE='23514';
  END IF;
  previous_org:=current_setting('app.current_org',true);
  previous_platform:=current_setting('app.platform_admin',true);
  BEGIN
    PERFORM set_config('app.current_org',review->>'org_id',true);
    PERFORM set_config('app.platform_admin','',true);
    PERFORM id FROM public.organizations WHERE id=review->>'org_id' FOR UPDATE;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'Review organization unavailable' USING ERRCODE='23514';
    END IF;
    SELECT * INTO r FROM public.restores
      WHERE id=review->>'restore_id' AND org_id=review->>'org_id' FOR UPDATE;
    IF NOT FOUND OR r.backup_id IS DISTINCT FROM review->>'backup_id' THEN
      RAISE EXCEPTION 'Restore identity changed' USING ERRCODE='23514';
    END IF;
    IF r.kubevirt_cleanup_review IS NOT NULL THEN
      IF r.status <> 'failed'
        OR r.kubevirt_cleanup_review-'reviewed_at' IS DISTINCT FROM review THEN
        RAISE EXCEPTION 'Review operation differs from recorded evidence'
          USING ERRCODE='23514';
      END IF;
      PERFORM set_config('app.current_org',COALESCE(previous_org,''),true);
      PERFORM set_config('app.platform_admin',COALESCE(previous_platform,''),true);
      RETURN jsonb_build_object('disposition','already_recorded',
        'operation_id',review->>'operation_id','restore_status',r.status);
    END IF;
    PERFORM pg_advisory_xact_lock(1447977557,2);
    PERFORM set_config('app.platform_admin','true',true);
    IF EXISTS(SELECT 1 FROM public.restores WHERE id<>r.id AND
      kubevirt_cleanup_review->>'operation_id'=review->>'operation_id') THEN
      RAISE EXCEPTION 'Review operation ID already belongs to another restore'
        USING ERRCODE='23514';
    END IF;
    PERFORM set_config('app.platform_admin','',true);
    SELECT * INTO b FROM public.backups WHERE id=r.backup_id AND org_id=r.org_id
      FOR UPDATE;
    IF NOT FOUND OR b.status <> 'completed'
      OR r.status <> 'cleanup_required' OR r.kubevirt_plan IS NULL
      OR r.native_plan IS NOT NULL OR r.kubevirt_plan->>'restore_id' IS DISTINCT FROM r.id
      OR r.kubevirt_plan->>'org_id' IS DISTINCT FROM r.org_id
      OR r.kubevirt_plan->'target'->>'namespace' IS DISTINCT FROM
         review->>'target_namespace'
      OR r.kubevirt_plan->'target'->>'vm_name' IS DISTINCT FROM
         review->>'target_vm_name'
      OR encode(sha256(convert_to(r.kubevirt_plan::text,'UTF8')),'hex') IS DISTINCT FROM
         review->>'plan_sha256'
      OR encode(sha256(convert_to(COALESCE(r.kubevirt_result,'null'::jsonb)::text,'UTF8')),'hex')
         IS DISTINCT FROM review->>'result_sha256' THEN
      RAISE EXCEPTION 'Held KubeVirt restore or plan identity unavailable'
        USING ERRCODE='23514';
    END IF;
    SELECT COALESCE(jsonb_agg(value->>'pvc_name' ORDER BY value->>'pvc_name'),'[]'::jsonb)
      INTO pvc_names FROM jsonb_array_elements(r.kubevirt_plan->'target'->'disks') value;
    IF jsonb_array_length(pvc_names)=0 OR pvc_names IS DISTINCT FROM
       review->'target_pvc_names' THEN
      RAISE EXCEPTION 'Destination PVC identities differ' USING ERRCODE='23514';
    END IF;
    entry:=review || jsonb_build_object('reviewed_at',
      to_char(clock_timestamp() AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'));
    PERFORM set_config('app.restore_cleanup_review',review->>'operation_id',true);
    UPDATE public.restores SET status='failed',
      error_message='Operator-reviewed cleanup; original journal and evidence retained',
      completed_at=clock_timestamp(),kubevirt_cleanup_review=entry
      WHERE id=r.id AND org_id=r.org_id;
    PERFORM set_config('app.restore_cleanup_review','',true);
    PERFORM set_config('app.current_org',COALESCE(previous_org,''),true);
    PERFORM set_config('app.platform_admin',COALESCE(previous_platform,''),true);
    RETURN jsonb_build_object('disposition','recorded',
      'operation_id',review->>'operation_id','restore_status','failed');
  EXCEPTION WHEN OTHERS THEN
    PERFORM set_config('app.restore_cleanup_review','',true);
    PERFORM set_config('app.current_org',COALESCE(previous_org,''),true);
    PERFORM set_config('app.platform_admin',COALESCE(previous_platform,''),true);
    RAISE;
  END;
END $$;
""")
    op.execute("REVOKE ALL ON FUNCTION vnbui_review_restore_cleanup(jsonb) FROM PUBLIC")


def downgrade():
    raise RuntimeError("Restore cleanup reviews require reviewed rollback")
