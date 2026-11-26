"""Unmounted scheduler construction and permanent preparation custody."""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID

revision = "scheduler_transactions"
down_revision = "scheduler_primitives"
branch_labels = None
depends_on = None

QUEUE_CHECK = """authority_kind <> 'scheduler' OR (
    status IS NOT NULL AND
    ((status IN ('queued','held_unclaimed') AND claim_id IS NULL AND claimed_at IS NULL AND started_backup_id IS NULL)
     OR (status IN ('claimed','held_claimed') AND claim_id IS NOT NULL
         AND claimed_at IS NOT NULL AND started_backup_id IS NOT NULL))
    AND ((status IN ('queued','claimed') AND hold_reason IS NULL)
      OR (status IN ('held_unclaimed','held_claimed') AND hold_reason IS NOT NULL AND hold_reason IN
        ('source_unavailable','authority_revoked','organization_fenced','scope_drift','recovery_required','commit_outcome_unknown')))
)"""


def upgrade():
    op.add_column(
        "schedule_occurrences", sa.Column("construction_xid", sa.BigInteger())
    )
    op.add_column("backup_queue", sa.Column("claim_id", UUID(as_uuid=False)))
    op.add_column("backup_queue", sa.Column("claimed_at", sa.DateTime(timezone=True)))
    op.add_column("backup_queue", sa.Column("hold_reason", sa.String(64)))
    op.create_unique_constraint("uq_backup_queue_claim", "backup_queue", ["claim_id"])
    op.create_check_constraint("ck_scheduler_queue_state", "backup_queue", QUEUE_CHECK)
    for name, body in FUNCTIONS.items():
        op.execute(body)
        op.execute(f"REVOKE ALL ON FUNCTION {name}() FROM PUBLIC")
    # Keep the trigger name so historical fixture/provenance tooling still names
    # the same enforcement site. Its implementation now seals construction.
    for table in ("schedule_occurrences", "schedule_occurrence_members"):
        op.execute(f"DROP TRIGGER scheduler_dormant ON {table}")
        op.execute(
            f"CREATE TRIGGER scheduler_dormant BEFORE INSERT ON {table} FOR EACH ROW EXECUTE FUNCTION vnbui_scheduler_construct()"
        )
    for table in (
        "schedule_occurrences",
        "schedule_occurrence_members",
        "backup_queue",
        "backups",
    ):
        op.execute(
            f"CREATE CONSTRAINT TRIGGER scheduler_complete AFTER INSERT OR UPDATE OR DELETE ON {table} DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION vnbui_scheduler_complete()"
        )
    op.execute(
        "CREATE TRIGGER scheduler_queue BEFORE INSERT OR UPDATE OR DELETE ON backup_queue FOR EACH ROW EXECUTE FUNCTION vnbui_scheduler_queue()"
    )
    op.execute(
        "CREATE TRIGGER audit_scheduler_queue AFTER INSERT OR UPDATE ON backup_queue FOR EACH ROW WHEN (NEW.authority_kind='scheduler') EXECUTE FUNCTION vnbui_scheduler_queue_audit()"
    )
    op.execute(
        "CREATE TRIGGER scheduler_backup_delete BEFORE DELETE ON backups FOR EACH ROW EXECUTE FUNCTION vnbui_scheduler_authority()"
    )


def downgrade():
    raise RuntimeError(
        "Scheduler construction/claim custody requires reviewed database/image rollback"
    )


# Repeated SQL is generated from one fragment, not separate policy implementations.
AUTHORITY = """
  SELECT * INTO o FROM public.organizations WHERE id=oid FOR UPDATE;
  SELECT * INTO s FROM public.schedules WHERE id=sid AND org_id=oid FOR UPDATE;
  SELECT * INTO g FROM public.scheduler_grants WHERE id=gid AND org_id=oid FOR UPDATE;
  IF o.id IS NULL OR o.enabled IS NOT TRUE OR s.id IS NULL OR g.id IS NULL
    OR g.state IS DISTINCT FROM 'active' OR g.org_epoch IS DISTINCT FROM o.scheduler_epoch
    OR s.current_grant_id IS DISTINCT FROM g.id OR s.authority_revision IS DISTINCT FROM g.schedule_revision
    OR g.schedule_id IS DISTINCT FROM s.id OR s.retired_at IS NOT NULL THEN
    RAISE EXCEPTION 'Scheduler authority fenced' USING ERRCODE='23514';
  END IF;
"""

FUNCTIONS = {}
FUNCTIONS["vnbui_scheduler_construct"] = (
    """CREATE FUNCTION vnbui_scheduler_construct() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
DECLARE o public.organizations; s public.schedules; g public.scheduler_grants; c public.schedule_occurrences;
        oid text; sid text; gid text; parts text[]; values_at integer[]; lows integer[]:=ARRAY[0,0,1,1,0]; highs integer[]:=ARRAY[59,23,31,12,7];
        matches boolean[]; i integer; term text; span text; step_n integer; lo integer; hi integer; value_n integer; instant timestamp;
BEGIN
  IF TG_TABLE_NAME='schedule_occurrences' THEN
    IF NEW.construction_xid IS NOT NULL THEN
      RAISE EXCEPTION 'Construction marker is server allocated' USING ERRCODE='23514';
    END IF;
    oid:=NEW.org_id; sid:=NEW.schedule_id; gid:=NEW.grant_id;
"""
    + AUTHORITY
    + """
    IF s.enabled IS NOT TRUE THEN
      RAISE EXCEPTION 'Schedule disabled' USING ERRCODE='23514';
    END IF;
    IF NEW.schedule_revision IS DISTINCT FROM g.schedule_revision
      OR NEW.scheduled_at IS NULL OR NEW.scheduled_at>statement_timestamp()
      OR date_trunc('minute',NEW.scheduled_at) IS DISTINCT FROM NEW.scheduled_at
      OR NEW.admission_order IS DISTINCT FROM o.scheduler_order+1
      OR jsonb_typeof(g.scope->'members') IS DISTINCT FROM 'array'
      OR jsonb_array_length(g.scope->'members') NOT BETWEEN 1 AND 256
      OR g.scope->>'org_id' IS DISTINCT FROM oid OR g.scope->>'schedule_id' IS DISTINCT FROM sid
      OR g.scope->>'revision' IS DISTINCT FROM g.schedule_revision::text
      OR g.scope->'options'->>'backup_type' IS DISTINCT FROM 'full' THEN
      RAISE EXCEPTION 'Invalid occurrence binding' USING ERRCODE='23514';
    END IF;
    parts:=regexp_split_to_array(trim(s.cron_expression), '\s+');
    IF array_length(parts,1) IS DISTINCT FROM 5 THEN RAISE EXCEPTION 'Five-field numeric cron required' USING ERRCODE='23514'; END IF;
    instant:=NEW.scheduled_at AT TIME ZONE 'UTC';
    values_at:=ARRAY[extract(minute from instant)::integer,extract(hour from instant)::integer,
      extract(day from instant)::integer,extract(month from instant)::integer,extract(dow from instant)::integer];
    FOR i IN 1..5 LOOP
      matches[i]:=false;
      FOREACH term IN ARRAY string_to_array(parts[i], ',') LOOP
        IF term !~ '^(\*|[0-9]+(-[0-9]+)?)(/[0-9]+)?$' THEN RAISE EXCEPTION 'Unsupported numeric cron' USING ERRCODE='23514'; END IF;
        span:=split_part(term,'/',1); step_n:=CASE WHEN position('/' in term)>0 THEN split_part(term,'/',2)::integer ELSE 1 END;
        lo:=CASE WHEN span='*' THEN lows[i] ELSE split_part(span,'-',1)::integer END;
        hi:=CASE WHEN span='*' THEN highs[i] WHEN position('-' in span)>0 THEN split_part(span,'-',2)::integer WHEN position('/' in term)>0 THEN highs[i] ELSE lo END;
        IF step_n<=0 OR lo<lows[i] OR hi>highs[i] OR hi<lo THEN RAISE EXCEPTION 'Invalid numeric cron range' USING ERRCODE='23514'; END IF;
        FOR value_n IN SELECT generate_series(lo,hi,step_n) LOOP
          IF values_at[i]=value_n OR i=5 AND values_at[i]=0 AND value_n=7 THEN matches[i]:=true; END IF;
        END LOOP;
      END LOOP;
    END LOOP;
    IF NOT (matches[1] AND matches[2] AND matches[4] AND
      CASE WHEN parts[3]<>'*' AND parts[5]<>'*' THEN matches[3] OR matches[5] ELSE matches[3] AND matches[5] END) THEN
      RAISE EXCEPTION 'Occurrence is not a cron instant' USING ERRCODE='23514';
    END IF;
    NEW.construction_xid:=pg_catalog.txid_current();
    UPDATE public.organizations SET scheduler_order=scheduler_order+1 WHERE id=oid RETURNING scheduler_order INTO NEW.admission_order;
  ELSE
    SELECT * INTO c FROM public.schedule_occurrences WHERE id=NEW.occurrence_id AND org_id=NEW.org_id;
    IF c.id IS NULL OR c.construction_xid IS NULL OR c.construction_xid IS DISTINCT FROM pg_catalog.txid_current() THEN
      RAISE EXCEPTION 'Occurrence construction is sealed' USING ERRCODE='23514';
    END IF;
  END IF;
  RETURN NEW;
END $$"""
)

FUNCTIONS["vnbui_scheduler_queue"] = (
    """CREATE FUNCTION vnbui_scheduler_queue() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
DECLARE c public.schedule_occurrences; o public.organizations; s public.schedules; g public.scheduler_grants;
        oid text; sid text; gid text;
BEGIN
  IF TG_OP='DELETE' THEN
    IF OLD.authority_kind='scheduler' THEN RAISE EXCEPTION 'Scheduler queue custody retained' USING ERRCODE='23514'; END IF;
    RETURN OLD;
  END IF;
  IF NEW.authority_kind IS DISTINCT FROM 'scheduler' THEN
    IF NEW.claim_id IS NOT NULL OR NEW.claimed_at IS NOT NULL OR NEW.hold_reason IS NOT NULL THEN
      RAISE EXCEPTION 'Scheduler claim on non-scheduler queue' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
  END IF;
  IF TG_OP='INSERT' THEN
    SELECT * INTO c FROM public.schedule_occurrences WHERE id=NEW.scheduler_occurrence_id;
    IF c.id IS NULL OR c.construction_xid IS NULL OR c.construction_xid IS DISTINCT FROM pg_catalog.txid_current()
      OR NEW.status IS DISTINCT FROM 'queued' OR NEW.claim_id IS NOT NULL OR NEW.claimed_at IS NOT NULL
      OR NEW.started_backup_id IS NOT NULL OR NEW.hold_reason IS NOT NULL
      OR NEW.tags IS DISTINCT FROM (SELECT COALESCE(tags,'{}'::jsonb) FROM public.schedules WHERE id=c.schedule_id)
      OR NEW.priority IS DISTINCT FROM 0 OR NEW.is_bulk_operation IS DISTINCT FROM false THEN
      RAISE EXCEPTION 'Queue requires original construction' USING ERRCODE='23514';
    END IF;
  ELSE
    IF (to_jsonb(NEW)-ARRAY['status','claim_id','claimed_at','started_backup_id','hold_reason']) IS DISTINCT FROM
       (to_jsonb(OLD)-ARRAY['status','claim_id','claimed_at','started_backup_id','hold_reason']) THEN
      RAISE EXCEPTION 'Scheduler queue input is immutable' USING ERRCODE='23514';
    END IF;
    IF OLD.claim_id IS NOT NULL AND ROW(NEW.claim_id,NEW.claimed_at,NEW.started_backup_id) IS DISTINCT FROM
       ROW(OLD.claim_id,OLD.claimed_at,OLD.started_backup_id) THEN
      RAISE EXCEPTION 'Scheduler claim is immutable' USING ERRCODE='23514';
    END IF;
    IF OLD.status='queued' AND NEW.status='claimed' THEN
      IF NEW.claim_id IS NOT NULL OR NEW.claimed_at IS NOT NULL OR NEW.started_backup_id IS NULL THEN
        RAISE EXCEPTION 'Claim identity is server allocated' USING ERRCODE='23514';
      END IF;
      SELECT * INTO c FROM public.schedule_occurrences WHERE id=NEW.scheduler_occurrence_id;
      oid:=c.org_id; sid:=c.schedule_id; gid:=c.grant_id;
"""
    + AUTHORITY
    + """
      NEW.claim_id:=pg_catalog.gen_random_uuid(); NEW.claimed_at:=clock_timestamp();
    ELSIF NOT (NEW.status IS NOT DISTINCT FROM OLD.status
       OR OLD.status='queued' AND NEW.status='held_unclaimed'
       OR OLD.status='claimed' AND NEW.status='held_claimed') THEN
      RAISE EXCEPTION 'Scheduler hold is absorbing' USING ERRCODE='23514';
    END IF;
  END IF;
  RETURN NEW;
END $$"""
)

FUNCTIONS["vnbui_scheduler_authority"] = (
    """CREATE OR REPLACE FUNCTION vnbui_scheduler_authority() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
DECLARE c public.schedule_occurrences; o public.organizations; s public.schedules; g public.scheduler_grants;
        oid text; sid text; gid text;
BEGIN
  IF TG_OP='DELETE' THEN
    IF OLD.authority_kind='scheduler' THEN RAISE EXCEPTION 'Scheduler backup custody retained' USING ERRCODE='23514'; END IF;
    RETURN OLD;
  ELSIF TG_OP='INSERT' THEN
    IF NEW.authority_kind='scheduler' AND NEW.initiating_user_id IS NULL AND NEW.scheduler_occurrence_id IS NOT NULL THEN
      SELECT c0.* INTO c FROM public.schedule_occurrences c0 JOIN public.schedule_occurrence_members m
        ON m.occurrence_id=c0.id WHERE c0.id=NEW.scheduler_occurrence_id AND m.vm_id=NEW.vm_id;
      IF c.id IS NULL OR c.construction_xid IS NULL THEN RAISE EXCEPTION 'Original scheduler member required' USING ERRCODE='23514'; END IF;
      oid:=c.org_id; sid:=c.schedule_id; gid:=c.grant_id;
"""
    + AUTHORITY
    + """
      IF TG_TABLE_NAME='backups' AND NOT EXISTS(SELECT 1 FROM public.backup_queue q
         WHERE q.scheduler_occurrence_id=c.id AND q.vm_id=NEW.vm_id AND q.status='queued' AND q.started_backup_id IS NULL) THEN
        RAISE EXCEPTION 'Unclaimed original queue required' USING ERRCODE='23514';
      END IF;
    ELSIF NEW.authority_kind IS DISTINCT FROM 'human' OR NEW.initiating_user_id IS NULL OR NEW.scheduler_occurrence_id IS NOT NULL THEN
      RAISE EXCEPTION 'Explicit human authority required; history unadoptable' USING ERRCODE='23514';
    END IF;
  ELSE
    IF NEW.vm_id IS DISTINCT FROM OLD.vm_id OR ROW(NEW.authority_kind,NEW.scheduler_occurrence_id,NEW.initiating_user_id)
      IS DISTINCT FROM ROW(OLD.authority_kind,OLD.scheduler_occurrence_id,OLD.initiating_user_id) THEN
      RAISE EXCEPTION 'Original authority is immutable' USING ERRCODE='23514';
    END IF;
  END IF;
  RETURN NEW;
END $$"""
)

FUNCTIONS[
    "vnbui_queue_started_backup"
] = """CREATE OR REPLACE FUNCTION vnbui_queue_started_backup() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$ BEGIN
  IF TG_OP='UPDATE' AND OLD.started_backup_id IS NOT NULL AND NEW.started_backup_id IS DISTINCT FROM OLD.started_backup_id THEN
    RAISE EXCEPTION 'Queue backup binding is immutable' USING ERRCODE='23514';
  END IF;
  IF NEW.started_backup_id IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM public.backups b WHERE b.id=NEW.started_backup_id AND b.vm_id=NEW.vm_id
      AND b.authority_kind IS NOT DISTINCT FROM NEW.authority_kind
      AND b.initiating_user_id IS NOT DISTINCT FROM NEW.initiating_user_id
      AND b.scheduler_occurrence_id IS NOT DISTINCT FROM NEW.scheduler_occurrence_id
  ) THEN RAISE EXCEPTION 'Queue backup has no matching original authority' USING ERRCODE='23514'; END IF;
  RETURN NEW;
END $$"""

FUNCTIONS[
    "vnbui_scheduler_complete"
] = """CREATE FUNCTION vnbui_scheduler_complete() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
DECLARE cid text; c public.schedule_occurrences; g public.scheduler_grants; expected jsonb; m record; q public.backup_queue; b public.backups;
BEGIN
  IF TG_TABLE_NAME='schedule_occurrences' THEN cid:=COALESCE(NEW.id,OLD.id);
  ELSIF TG_TABLE_NAME='schedule_occurrence_members' THEN cid:=COALESCE(NEW.occurrence_id,OLD.occurrence_id);
  ELSE cid:=COALESCE(NEW.scheduler_occurrence_id,OLD.scheduler_occurrence_id); END IF;
  IF cid IS NULL THEN RETURN NULL; END IF;
  SELECT * INTO c FROM public.schedule_occurrences WHERE id=cid;
  IF c.id IS NULL THEN RAISE EXCEPTION 'Occurrence custody unavailable' USING ERRCODE='23514'; END IF;
  -- Historical owner-seeded custody cannot authorize construction; leave it intact.
  IF c.construction_xid IS NULL THEN RETURN NULL; END IF;
  SELECT * INTO g FROM public.scheduler_grants WHERE id=c.grant_id AND org_id=c.org_id;
  expected:=g.scope->'members';
  IF g.id IS NULL OR jsonb_typeof(expected) IS DISTINCT FROM 'array'
    OR jsonb_array_length(expected) NOT BETWEEN 1 AND 256
    OR (SELECT count(DISTINCT value->>'vm_id') FROM jsonb_array_elements(expected))<>jsonb_array_length(expected)
    OR (SELECT count(*) FROM public.schedule_occurrence_members WHERE occurrence_id=cid)<>jsonb_array_length(expected)
    OR (SELECT count(*) FROM public.backup_queue WHERE scheduler_occurrence_id=cid)<>jsonb_array_length(expected) THEN
    RAISE EXCEPTION 'Incomplete scheduler construction' USING ERRCODE='23514';
  END IF;
  FOR m IN SELECT value snap FROM jsonb_array_elements(expected) LOOP
    IF NOT EXISTS(SELECT 1 FROM public.schedule_occurrence_members x WHERE x.occurrence_id=cid
      AND x.org_id=c.org_id AND x.vm_id=m.snap->>'vm_id' AND x.source_snapshot=m.snap
      AND x.source_sha256=encode(sha256(convert_to((SELECT '{'||string_agg(to_jsonb(key)::text||':'||value::text, ',' ORDER BY key COLLATE "C")||'}' FROM jsonb_each(m.snap)),'UTF8')),'hex')) THEN
      RAISE EXCEPTION 'Scheduler member snapshot mismatch' USING ERRCODE='23514';
    END IF;
    SELECT * INTO q FROM public.backup_queue WHERE scheduler_occurrence_id=cid AND vm_id=m.snap->>'vm_id';
    IF q.id IS NULL OR q.authority_kind IS DISTINCT FROM 'scheduler' OR q.initiating_user_id IS NOT NULL
      OR q.created_by IS NOT NULL OR q.schedule_id IS DISTINCT FROM c.schedule_id
      OR q.backup_type IS DISTINCT FROM g.scope->'options'->>'backup_type'
      OR to_jsonb(q.retention_days) IS DISTINCT FROM g.scope->'options'->'retention_days'
      OR COALESCE(to_jsonb(q.workers),'null'::jsonb) IS DISTINCT FROM g.scope->'options'->'workers'
      OR q.exclude_disks IS DISTINCT FROM g.scope->'options'->'exclude_disks' THEN
      RAISE EXCEPTION 'Scheduler queue scope mismatch' USING ERRCODE='23514';
    END IF;
    IF q.started_backup_id IS NOT NULL THEN
      SELECT * INTO b FROM public.backups WHERE id=q.started_backup_id;
      IF b.id IS NULL OR b.org_id IS DISTINCT FROM c.org_id OR b.vm_id IS DISTINCT FROM q.vm_id
        OR b.authority_kind IS DISTINCT FROM 'scheduler' OR b.initiating_user_id IS NOT NULL
        OR b.scheduler_occurrence_id IS DISTINCT FROM cid OR b.backup_type IS DISTINCT FROM q.backup_type
        OR b.retention_days IS DISTINCT FROM q.retention_days OR b.workers IS DISTINCT FROM q.workers
        OR b.exclude_disks IS DISTINCT FROM q.exclude_disks OR b.tags IS DISTINCT FROM q.tags OR q.claim_id IS NULL THEN
        RAISE EXCEPTION 'Scheduler claim backup mismatch' USING ERRCODE='23514';
      END IF;
    ELSIF EXISTS(SELECT 1 FROM public.backups WHERE scheduler_occurrence_id=cid AND vm_id=q.vm_id) THEN
      RAISE EXCEPTION 'Scheduler backup lacks permanent claim' USING ERRCODE='23514';
    END IF;
  END LOOP;
  RETURN NULL;
END $$"""

FUNCTIONS[
    "vnbui_scheduler_queue_audit"
] = """CREATE FUNCTION vnbui_scheduler_queue_audit() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
DECLARE oid text;
BEGIN
  IF TG_OP='UPDATE' AND NEW IS NOT DISTINCT FROM OLD THEN RETURN NEW; END IF;
  SELECT org_id INTO oid FROM public.schedule_occurrences WHERE id=NEW.scheduler_occurrence_id;
  IF oid IS NULL THEN RAISE EXCEPTION 'Queue audit requires original organization' USING ERRCODE='23514'; END IF;
  INSERT INTO public.access_audit(table_name,operation,org_id,user_id,row_id)
    VALUES(TG_TABLE_NAME,TG_OP,oid,NULLIF(current_setting('app.user_id',true),''),NEW.id);
  INSERT INTO public.system_events(id,attribution,org_id,event_type,source,source_id,resource_type,resource_id,details)
    VALUES(gen_random_uuid()::text,'tenant',oid,'scheduler_queue_custody','scheduler',NEW.schedule_id,'backup_queue',NEW.id,
      jsonb_build_object('old_state',CASE WHEN TG_OP='UPDATE' THEN OLD.status END,'state',NEW.status,
        'old_hold_reason',CASE WHEN TG_OP='UPDATE' THEN OLD.hold_reason END,'hold_reason',NEW.hold_reason,
        'occurrence_id',NEW.scheduler_occurrence_id,'claim_id',NEW.claim_id,'backup_id',NEW.started_backup_id));
  RETURN NEW;
END $$"""
