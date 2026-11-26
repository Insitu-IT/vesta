"""Owner-bound dormant dispatch admission; runtime scheduler production stays off."""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = "scheduler_primitives"
down_revision = "scheduler_authority"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        "s3_publications", sa.Column("dispatch_admission", JSONB(), nullable=True)
    )
    op.execute(FUNCTION)
    op.execute("REVOKE ALL ON FUNCTION vnbui_dispatch_admission() FROM PUBLIC")
    op.execute("""CREATE TRIGGER dispatch_admission BEFORE INSERT OR UPDATE OR DELETE
        ON s3_publications FOR EACH ROW EXECUTE FUNCTION vnbui_dispatch_admission()""")

    op.execute(
        """CREATE TRIGGER audit_dispatch_admission AFTER UPDATE ON s3_publications
        FOR EACH ROW WHEN (OLD.dispatch_admission IS NULL AND NEW.dispatch_admission IS NOT NULL)
        EXECUTE FUNCTION audit_access()"""
    )


def downgrade():
    raise RuntimeError(
        "Dispatch admission custody requires reviewed database/image rollback"
    )


FUNCTION = """CREATE FUNCTION vnbui_dispatch_admission() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
DECLARE a jsonb; b public.backups; o public.organizations; g public.scheduler_grants;
        c public.schedule_occurrences; s public.schedules; u public.users;
        keys text[] := ARRAY['schema','effect_kind','dispatch_token','backup_id','reservation_id',
        'attempt_id','request_sha256','authority_kind','user_id','occurrence_id','grant_id',
        'scope_sha256','org_epoch','admission_order'];
BEGIN
  IF TG_OP='DELETE' THEN
    IF OLD.dispatch_admission IS NOT NULL THEN
      RAISE EXCEPTION 'Admission custody is retained' USING ERRCODE='23514';
    END IF;
    RETURN OLD;
  END IF;
  a := NEW.dispatch_admission;
  IF TG_OP='INSERT' THEN
    IF a IS NOT NULL THEN RAISE EXCEPTION 'Admission requires existing dispatch custody' USING ERRCODE='23514'; END IF;
    RETURN NEW;
  END IF;
  IF OLD.dispatch_admission IS NOT NULL THEN
    IF a IS DISTINCT FROM OLD.dispatch_admission THEN
      RAISE EXCEPTION 'Dispatch admission is immutable' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
  END IF;
  IF a IS NULL THEN RETURN NEW; END IF;
  IF jsonb_typeof(a) IS DISTINCT FROM 'object' OR NOT a ?& keys OR a-keys <> '{}'::jsonb
     OR octet_length(a::text)>8192 OR a->'schema' IS DISTINCT FROM '1'::jsonb
     OR a->>'schema' IS DISTINCT FROM '1'
     OR a->>'effect_kind' IS DISTINCT FROM 'storage_dispatch'
     OR OLD.dispatch_token IS NULL OR OLD.dispatch_transaction_id IS NULL
     OR OLD.dispatch_transaction_id=txid_current()
     OR a->'dispatch_token' IS DISTINCT FROM to_jsonb(OLD.dispatch_token)
     OR NEW.dispatch_token IS DISTINCT FROM OLD.dispatch_token
     OR (NEW.expected_plan::jsonb) IS DISTINCT FROM (OLD.expected_plan::jsonb)
     OR OLD.state<>'reserved' OR NEW.state<>'reserved' OR OLD.kind<>'payload'
     OR OLD.prepared_receipt IS NOT NULL OR NEW.prepared_receipt IS NOT NULL
     OR (OLD.expected_plan::jsonb)->'schema' IS DISTINCT FROM '3'::jsonb
     OR a->'backup_id' IS DISTINCT FROM to_jsonb(NEW.backup_id)
     OR a->'reservation_id' IS DISTINCT FROM to_jsonb(NEW.id)
     OR a->'attempt_id' IS DISTINCT FROM (OLD.expected_plan::jsonb)->'transaction'->'plan'->'attempt_id'
     OR a->'request_sha256' IS DISTINCT FROM to_jsonb(encode(sha256(convert_to(((OLD.expected_plan::jsonb)->'transaction')::text,'UTF8')),'hex'))
     OR a->'backup_id' IS DISTINCT FROM (OLD.expected_plan::jsonb)->'transaction'->'backup_id'
     OR a->'reservation_id' IS DISTINCT FROM (OLD.expected_plan::jsonb)->'transaction'->'reservation_id'
     OR to_jsonb(NEW.org_id) IS DISTINCT FROM (OLD.expected_plan::jsonb)->'transaction'->'org_id'
     OR jsonb_typeof(a->'org_epoch') IS DISTINCT FROM 'number'
     OR jsonb_typeof(a->'admission_order') IS DISTINCT FROM 'number'
     OR (a->>'org_epoch') !~ '^(0|[1-9][0-9]*)$'
     OR (a->>'admission_order') !~ '^[1-9][0-9]*$' THEN
    RAISE EXCEPTION 'Invalid exact dispatch admission binding' USING ERRCODE='23514';
  END IF;
  SELECT * INTO o FROM public.organizations WHERE id=NEW.org_id FOR UPDATE;
  IF NOT FOUND OR o.enabled IS NOT TRUE OR a->'org_epoch' IS DISTINCT FROM to_jsonb(o.scheduler_epoch)
     OR o.scheduler_order=9223372036854775807
     OR a->'admission_order' IS DISTINCT FROM to_jsonb(o.scheduler_order+1) THEN
    RAISE EXCEPTION 'Admission organization fenced' USING ERRCODE='23514';
  END IF;
  UPDATE public.organizations SET scheduler_order=scheduler_order+1 WHERE id=o.id;
  SELECT * INTO b FROM public.backups WHERE id=NEW.backup_id AND org_id=NEW.org_id;
  IF NOT FOUND OR (b.status IN ('pending','running')) IS NOT TRUE
     OR a->'authority_kind' IS DISTINCT FROM to_jsonb(b.authority_kind)
     OR a->'user_id' IS DISTINCT FROM COALESCE(to_jsonb(b.initiating_user_id),'null'::jsonb)
     OR a->'occurrence_id' IS DISTINCT FROM COALESCE(to_jsonb(b.scheduler_occurrence_id),'null'::jsonb) THEN
    RAISE EXCEPTION 'Original authority unavailable' USING ERRCODE='23514';
  END IF;
  IF b.authority_kind='human' THEN
    SELECT * INTO u FROM public.users WHERE id=b.initiating_user_id AND org_id=NEW.org_id;
    IF NOT FOUND OR u.is_active IS NOT TRUE OR (u.role IN ('admin','operator')) IS NOT TRUE
       OR a->'grant_id' IS DISTINCT FROM 'null'::jsonb OR a->'scope_sha256' IS DISTINCT FROM 'null'::jsonb THEN
      RAISE EXCEPTION 'Human admission unavailable' USING ERRCODE='23514';
    END IF;
  ELSIF b.authority_kind='scheduler' THEN
    SELECT * INTO c FROM public.schedule_occurrences WHERE id=b.scheduler_occurrence_id AND org_id=NEW.org_id;
    IF NOT FOUND THEN RAISE EXCEPTION 'Occurrence unavailable' USING ERRCODE='23514'; END IF;
    SELECT * INTO s FROM public.schedules WHERE id=c.schedule_id AND org_id=NEW.org_id FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION 'Schedule unavailable' USING ERRCODE='23514'; END IF;
    SELECT * INTO g FROM public.scheduler_grants WHERE id=c.grant_id AND org_id=NEW.org_id FOR UPDATE;
    IF NOT FOUND OR g.state<>'active' OR g.org_epoch<>o.scheduler_epoch
       OR s.retired_at IS NOT NULL OR s.current_grant_id IS DISTINCT FROM g.id
       OR s.authority_revision<>g.schedule_revision OR c.schedule_revision<>g.schedule_revision
       OR g.schedule_id<>s.id OR a->'grant_id' IS DISTINCT FROM to_jsonb(g.id)
       OR a->'scope_sha256' IS DISTINCT FROM to_jsonb(g.scope_sha256)
       OR NOT EXISTS (SELECT 1 FROM public.schedule_occurrence_members
                      WHERE occurrence_id=c.id AND vm_id=b.vm_id AND org_id=NEW.org_id) THEN
      RAISE EXCEPTION 'Scheduler admission fenced' USING ERRCODE='23514';
    END IF;
  ELSE RAISE EXCEPTION 'Historical authority remains held' USING ERRCODE='23514';
  END IF;
  RETURN NEW;
END $$"""
