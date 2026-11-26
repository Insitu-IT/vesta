"""Dormant capacity custody, without producer or terminal-recovery integration."""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB, UUID

revision = "capacity_prerequisite"
down_revision = "scheduler_transactions"
branch_labels = None
depends_on = None

# Separate from singleton's bigint keyspace and transition's two-int key.
LOCK = "PERFORM pg_advisory_xact_lock(1447977557,1);"
POLICY = """
  SELECT value::jsonb INTO policy FROM public.settings_v3 WHERE key='backup.capacity_admission';
  IF policy IS NULL OR jsonb_typeof(policy)<>'object'
    OR NOT policy ?& ARRAY['schema','revision','limit','maintenance']
    OR policy-ARRAY['schema','revision','limit','maintenance']<>'{}'::jsonb
    OR policy->'schema' IS DISTINCT FROM '1'::jsonb OR policy->>'schema'<>'1'
    OR jsonb_typeof(policy->'revision') IS DISTINCT FROM 'number'
    OR (policy->>'revision') !~ '^[1-9][0-9]*$'
    OR (policy->>'revision')::numeric>9223372036854775807
    OR jsonb_typeof(policy->'limit') IS DISTINCT FROM 'number'
    OR (policy->>'limit') !~ '^[1-9][0-9]*$'
    OR (policy->>'limit')::numeric NOT BETWEEN 1 AND 100000
    OR jsonb_typeof(policy->'maintenance') IS DISTINCT FROM 'boolean' THEN
    RAISE EXCEPTION 'Persisted capacity policy absent or invalid' USING ERRCODE='23514';
  END IF;
"""
# No externally callable aggregate: the invoker trigger validates tenant owner
# first, then performs only these fixed reads in the platform-read scope.
READ = (
    """
  previous_platform := current_setting('app.platform_admin',true);
  BEGIN
    PERFORM set_config('app.platform_admin','true',true);
"""
    + POLICY
    + """
    SELECT count(*), count(*) FILTER (WHERE org_id=b.org_id AND vm_id=b.vm_id)
      INTO occupied,same_vm FROM public.backups WHERE capacity_state IN ('reserved','legacy_held');
    PERFORM set_config('app.platform_admin',COALESCE(previous_platform,''),true);
  EXCEPTION WHEN OTHERS THEN
    PERFORM set_config('app.platform_admin',COALESCE(previous_platform,''),true);
    RAISE;
  END;
"""
)
AUTHORITY = """
  SELECT * INTO o FROM public.organizations WHERE id=b.org_id FOR UPDATE;
  IF NOT FOUND OR o.enabled IS NOT TRUE THEN
    RAISE EXCEPTION 'Capacity organization fenced' USING ERRCODE='23514';
  END IF;
  IF b.authority_kind='human' THEN
    SELECT * INTO u FROM public.users WHERE id=b.initiating_user_id AND org_id=b.org_id FOR UPDATE;
    IF NOT FOUND OR u.is_active IS NOT TRUE OR (u.role IN ('admin','operator')) IS NOT TRUE
      OR NULLIF(current_setting('app.user_id',true),'') IS NOT NULL
         AND current_setting('app.user_id',true)<>u.id THEN
      RAISE EXCEPTION 'Capacity original human unavailable' USING ERRCODE='23514';
    END IF;
  ELSIF b.authority_kind='scheduler' THEN
    IF NULLIF(current_setting('app.user_id',true),'') IS NOT NULL THEN
      RAISE EXCEPTION 'Scheduler cannot impersonate human' USING ERRCODE='23514';
    END IF;
    SELECT * INTO c FROM public.schedule_occurrences WHERE id=b.scheduler_occurrence_id AND org_id=b.org_id;
    IF NOT FOUND THEN RAISE EXCEPTION 'Capacity occurrence unavailable' USING ERRCODE='23514'; END IF;
    SELECT * INTO s FROM public.schedules WHERE id=c.schedule_id AND org_id=b.org_id FOR UPDATE;
    SELECT * INTO g FROM public.scheduler_grants WHERE id=c.grant_id AND org_id=b.org_id FOR UPDATE;
    SELECT * INTO q FROM public.backup_queue WHERE started_backup_id=b.id
      AND scheduler_occurrence_id=c.id AND vm_id=b.vm_id FOR UPDATE;
    IF s.id IS NULL OR g.id IS NULL OR g.state IS DISTINCT FROM 'active'
      OR s.retired_at IS NOT NULL OR s.current_grant_id IS DISTINCT FROM g.id
      OR s.authority_revision IS DISTINCT FROM g.schedule_revision
      OR c.schedule_revision IS DISTINCT FROM g.schedule_revision
      OR g.org_epoch IS DISTINCT FROM o.scheduler_epoch
      OR g.schedule_id IS DISTINCT FROM s.id
      OR NOT EXISTS(SELECT 1 FROM public.schedule_occurrence_members
        WHERE occurrence_id=c.id AND org_id=b.org_id AND vm_id=b.vm_id)
      OR q.id IS NULL OR q.status IS DISTINCT FROM 'claimed' THEN
      RAISE EXCEPTION 'Capacity original scheduler unavailable' USING ERRCODE='23514';
    END IF;
  ELSE RAISE EXCEPTION 'Historical capacity has no execution authority' USING ERRCODE='23514';
  END IF;
  IF (b.status IN ('pending','running')) IS NOT TRUE OR NOT EXISTS(
    SELECT 1 FROM public.vms v JOIN public.agents a ON a.id=v.agent_id AND a.org_id=v.org_id
    WHERE v.id=b.vm_id AND v.org_id=b.org_id AND v.inventory_present IS TRUE AND a.status='online') THEN
    RAISE EXCEPTION 'Capacity source unavailable' USING ERRCODE='23514';
  END IF;
"""
DECL = """DECLARE b public.backups; o public.organizations; u public.users;
 s public.schedules; g public.scheduler_grants; c public.schedule_occurrences; q public.backup_queue;
 policy jsonb; previous_platform text; occupied bigint; same_vm bigint;
"""

FUNCTIONS = {}
FUNCTIONS["vnbui_capacity_owner"] = (
    """CREATE FUNCTION vnbui_capacity_owner() RETURNS trigger
LANGUAGE plpgsql VOLATILE SET search_path=pg_catalog,public AS $$
"""
    + DECL
    + """
BEGIN
 IF TG_OP='DELETE' THEN
   IF OLD.capacity_state<>'unreserved' THEN RAISE EXCEPTION 'Capacity custody retained' USING ERRCODE='23514'; END IF;
   RETURN OLD;
 END IF;
 IF NEW.capacity_terminal_evidence IS NOT NULL OR NEW.capacity_terminal_xid IS NOT NULL THEN
   RAISE EXCEPTION 'Terminal quiescence protocol unsupported' USING ERRCODE='23514';
 END IF;
 IF TG_OP='INSERT' THEN
   IF NEW.capacity_state IS DISTINCT FROM 'unreserved' OR NEW.capacity_id IS NOT NULL
     OR NEW.capacity_reserved_at IS NOT NULL OR NEW.capacity_policy_revision IS NOT NULL OR NEW.capacity_release IS NOT NULL THEN
     RAISE EXCEPTION 'Capacity begins unreserved' USING ERRCODE='23514';
   END IF;
   RETURN NEW;
 END IF;
 IF ROW(NEW.capacity_id,NEW.capacity_reserved_at,NEW.capacity_policy_revision,NEW.capacity_release)
   IS DISTINCT FROM ROW(OLD.capacity_id,OLD.capacity_reserved_at,OLD.capacity_policy_revision,OLD.capacity_release) THEN
   RAISE EXCEPTION 'Capacity fields are server owned' USING ERRCODE='23514';
 END IF;
 IF (OLD.capacity_state<>'unreserved' OR NEW.capacity_state<>'unreserved') AND ROW(NEW.id,NEW.org_id,NEW.vm_id,NEW.authority_kind,NEW.initiating_user_id,NEW.scheduler_occurrence_id)
   IS DISTINCT FROM ROW(OLD.id,OLD.org_id,OLD.vm_id,OLD.authority_kind,OLD.initiating_user_id,OLD.scheduler_occurrence_id) THEN
   RAISE EXCEPTION 'Capacity owner is immutable' USING ERRCODE='23514';
 END IF;
 IF OLD.wrapped_dek IS NOT NULL AND NEW.wrapped_dek IS DISTINCT FROM OLD.wrapped_dek THEN
   RAISE EXCEPTION 'Effect key custody is immutable' USING ERRCODE='23514';
 END IF;
 IF NEW.capacity_state IS NOT DISTINCT FROM OLD.capacity_state THEN RETURN NEW; END IF;
 IF current_setting('transaction_isolation')<>'read committed' THEN
   RAISE EXCEPTION 'Capacity transition requires READ COMMITTED' USING ERRCODE='23514';
 END IF;
"""
    + """
 -- Tenant lookup occurs BEFORE platform READ, and checks the old immutable owner.
 SELECT * INTO b FROM public.backups WHERE id=OLD.id AND org_id=OLD.org_id;
 IF NOT FOUND OR current_setting('app.platform_admin',true)='true'
   OR current_setting('app.demo',true)='true'
   OR current_setting('app.current_org',true) IS DISTINCT FROM b.org_id THEN
   RAISE EXCEPTION 'Capacity requires visible original tenant' USING ERRCODE='23514';
 END IF;
 IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname=current_user AND (rolsuper OR rolbypassrls)) THEN
   RAISE EXCEPTION 'Restricted runtime capacity required' USING ERRCODE='23514';
 END IF;
 IF OLD.capacity_state='unreserved' AND NEW.capacity_state='reserved' THEN
"""
    + AUTHORITY
    + LOCK
    + READ
    + """
   IF (policy->>'maintenance')::boolean OR occupied>=(policy->>'limit')::integer OR same_vm>0 THEN
     RAISE EXCEPTION 'Capacity unavailable' USING ERRCODE='23514';
   END IF;
   NEW.capacity_id:=gen_random_uuid(); NEW.capacity_reserved_at:=clock_timestamp();
   NEW.capacity_policy_revision:=(policy->>'revision')::bigint;
 ELSIF OLD.capacity_state='reserved' AND NEW.capacity_state='released' THEN
   PERFORM pg_advisory_xact_lock(1447977557,1);
   IF OLD.native_job_intent IS NOT NULL OR OLD.native_inventory IS NOT NULL OR OLD.wrapped_dek IS NOT NULL
     OR NEW.native_job_intent IS NOT NULL OR NEW.native_inventory IS NOT NULL OR NEW.wrapped_dek IS NOT NULL
     OR EXISTS(SELECT 1 FROM public.s3_publications WHERE backup_id=b.id AND (
       dispatch_token IS NOT NULL OR dispatch_admission IS NOT NULL OR wrapped_attempt_key IS NOT NULL
       OR provider_control IS NOT NULL OR prepared_receipt IS NOT NULL OR finalize_intent IS NOT NULL
       OR checkpoint_proof IS NOT NULL OR state<>'reserved')) THEN
     RAISE EXCEPTION 'Effect custody cannot use never-effect release' USING ERRCODE='23514';
   END IF;
   NEW.capacity_release:=jsonb_build_object('schema',1,'capacity_id',OLD.capacity_id,
     'reason','never_effect_admitted','evidence_sha256',NULL,'released_at',to_char(clock_timestamp() AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'));
 ELSE RAISE EXCEPTION 'Unsupported capacity transition' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$"""
)

FUNCTIONS["vnbui_capacity_effect"] = (
    """CREATE FUNCTION vnbui_capacity_effect() RETURNS trigger
LANGUAGE plpgsql VOLATILE SET search_path=pg_catalog,public AS $$
"""
    + DECL
    + """ new_effect jsonb; old_effect jsonb;
BEGIN
 IF TG_TABLE_NAME='backups' THEN
   new_effect:=jsonb_build_array(NEW.native_job_intent,NEW.native_inventory,NEW.wrapped_dek);
   IF TG_OP='UPDATE' THEN old_effect:=jsonb_build_array(OLD.native_job_intent,OLD.native_inventory,OLD.wrapped_dek); END IF;
   IF new_effect='[null,null,null]'::jsonb OR new_effect IS NOT DISTINCT FROM old_effect THEN RETURN NEW; END IF;
   SELECT * INTO b FROM public.backups WHERE id=OLD.id AND org_id=OLD.org_id FOR UPDATE;
 ELSE
   new_effect:=jsonb_build_array(NEW.dispatch_token,NEW.dispatch_admission,NEW.wrapped_attempt_key,
     NEW.provider_control,NEW.prepared_receipt,NEW.finalize_intent,NEW.checkpoint_proof,NEW.state);
   IF TG_OP='UPDATE' THEN old_effect:=jsonb_build_array(OLD.dispatch_token,OLD.dispatch_admission,OLD.wrapped_attempt_key,
     OLD.provider_control,OLD.prepared_receipt,OLD.finalize_intent,OLD.checkpoint_proof,OLD.state); END IF;
   IF new_effect='[null,null,null,null,null,null,null,"reserved"]'::jsonb OR new_effect IS NOT DISTINCT FROM old_effect THEN RETURN NEW; END IF;
 END IF;
"""
    + """
 IF TG_TABLE_NAME<>'backups' THEN
   SELECT * INTO b FROM public.backups WHERE id=NEW.backup_id AND org_id=NEW.org_id FOR UPDATE;
 END IF;
 IF current_setting('transaction_isolation')<>'read committed' THEN
   RAISE EXCEPTION 'Effect admission requires READ COMMITTED' USING ERRCODE='23514';
 END IF;
 IF b.id IS NULL OR b.capacity_state IS DISTINCT FROM 'reserved'
   OR current_setting('app.platform_admin',true)='true'
   OR current_setting('app.current_org',true) IS DISTINCT FROM b.org_id THEN
   RAISE EXCEPTION 'Effect requires reserved capacity' USING ERRCODE='23514';
 END IF;
 -- Custody observations are retained during maintenance; new capabilities stop.
 IF TG_TABLE_NAME='backups' THEN
 IF TG_OP='UPDATE' AND ROW(NEW.native_job_intent,NEW.wrapped_dek) IS DISTINCT FROM ROW(OLD.native_job_intent,OLD.wrapped_dek) THEN
"""
    + READ
    + """
   IF (policy->>'maintenance')::boolean THEN RAISE EXCEPTION 'Capacity maintenance' USING ERRCODE='23514'; END IF;
 END IF;
 ELSE
 IF TG_OP='INSERT' OR jsonb_build_array(NEW.dispatch_token,NEW.dispatch_admission,NEW.wrapped_attempt_key,NEW.provider_control,NEW.finalize_intent) IS DISTINCT FROM jsonb_build_array(OLD.dispatch_token,OLD.dispatch_admission,OLD.wrapped_attempt_key,OLD.provider_control,OLD.finalize_intent) THEN
"""
    + READ
    + """
   IF (policy->>'maintenance')::boolean THEN RAISE EXCEPTION 'Capacity maintenance' USING ERRCODE='23514'; END IF;
 END IF;
 END IF;
 RETURN NEW;
END $$"""
)

FUNCTIONS["vnbui_capacity_policy"] = (
    """CREATE FUNCTION vnbui_capacity_policy() RETURNS trigger
LANGUAGE plpgsql VOLATILE SET search_path=pg_catalog,public AS $$
DECLARE previous_revision bigint; policy jsonb;
BEGIN
 IF TG_OP='UPDATE' AND OLD.key='backup.capacity_admission' AND NEW.key<>OLD.key THEN
   RAISE EXCEPTION 'Capacity policy key is immutable' USING ERRCODE='23514';
 END IF;
 IF TG_OP='DELETE' THEN
   IF OLD.key='backup.capacity_admission' THEN RAISE EXCEPTION 'Capacity policy cannot be deleted' USING ERRCODE='23514'; END IF;
   RETURN OLD;
 END IF;
 IF NEW.key<>'backup.capacity_admission' THEN RETURN NEW; END IF;
"""
    + LOCK
    + """
"""
    + POLICY.replace(
        "SELECT value::jsonb INTO policy FROM public.settings_v3 WHERE key='backup.capacity_admission';",
        "policy:=NEW.value::jsonb;",
    )
    + """
 IF TG_OP='UPDATE' AND NEW.value IS DISTINCT FROM OLD.value THEN
   previous_revision:=(OLD.value::jsonb->>'revision')::bigint;
   IF (NEW.value::jsonb->>'revision')::bigint<=previous_revision THEN
     RAISE EXCEPTION 'Capacity revision must increase' USING ERRCODE='23514';
   END IF;
 END IF;
 RETURN NEW;
END $$"""
)


FUNCTIONS[
    "vnbui_capacity_audit"
] = """CREATE FUNCTION vnbui_capacity_audit() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
BEGIN
 INSERT INTO public.system_events(id,attribution,org_id,event_type,source,source_id,resource_type,resource_id,details)
 VALUES(gen_random_uuid()::text,'tenant',NEW.org_id,'backup_capacity_custody','backup_capacity',NEW.id,'backup',NEW.id,
   jsonb_build_object('old_state',OLD.capacity_state,'state',NEW.capacity_state,
     'capacity_id',NEW.capacity_id,'policy_revision',NEW.capacity_policy_revision,
     'authority_kind',NEW.authority_kind,'initiating_user_id',NEW.initiating_user_id,
     'occurrence_id',NEW.scheduler_occurrence_id,'release',NEW.capacity_release));
 RETURN NEW;
END $$"""


def upgrade():
    for column in (
        sa.Column(
            "capacity_state", sa.String(), nullable=False, server_default="unreserved"
        ),
        sa.Column("capacity_id", UUID(as_uuid=False)),
        sa.Column("capacity_reserved_at", sa.DateTime(timezone=True)),
        sa.Column("capacity_policy_revision", sa.BigInteger()),
        sa.Column("capacity_release", JSONB()),
        sa.Column(
            "capacity_legacy_reviews",
            JSONB(),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        # Install the later modern-review field before this migration's
        # historical-row UPDATE queues audit trigger events. A fresh
        # single-transaction upgrade cannot ALTER backups after that UPDATE.
        sa.Column(
            "capacity_modern_reviews",
            JSONB(),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column("capacity_terminal_evidence", JSONB()),
        sa.Column("capacity_terminal_xid", sa.BigInteger()),
    ):
        op.add_column("backups", column)
    op.create_check_constraint(
        "ck_backup_capacity_state",
        "backups",
        "(capacity_state = 'unreserved' AND capacity_id IS NULL AND capacity_reserved_at IS NULL AND capacity_policy_revision IS NULL AND capacity_release IS NULL) OR (capacity_state IN ('reserved','legacy_held','released') AND capacity_id IS NOT NULL AND capacity_reserved_at IS NOT NULL AND ((capacity_state='reserved' AND capacity_policy_revision IS NOT NULL AND capacity_policy_revision>0 AND capacity_release IS NULL) OR (capacity_state='legacy_held' AND capacity_policy_revision IS NULL AND capacity_release IS NULL) OR (capacity_state='released' AND capacity_policy_revision IS NOT NULL AND capacity_policy_revision>0 AND capacity_release IS NOT NULL)))",
    )
    op.create_check_constraint(
        "ck_backup_capacity_terminal_dormant",
        "backups",
        "capacity_terminal_evidence IS NULL AND capacity_terminal_xid IS NULL",
    )
    op.create_index(
        "uq_backup_capacity_vm",
        "backups",
        ["org_id", "vm_id"],
        unique=True,
        postgresql_where=sa.text("capacity_state = 'reserved'"),
    )
    # No status, token absence or presumed historical sender proves quiescence.
    # The migration owner is intentionally non-superuser. Earlier tenancy
    # migrations FORCE RLS on backups, so an unscoped UPDATE silently matches
    # zero predecessor rows. This one migration must see every organization;
    # restore the local setting even if the backfill raises.
    op.execute("""DO $$ DECLARE prior text;
        BEGIN
          prior:=current_setting('app.platform_admin',true);
          PERFORM set_config('app.platform_admin','true',true);
          UPDATE public.backups SET capacity_state='legacy_held',
            capacity_id=gen_random_uuid(),capacity_reserved_at=clock_timestamp();
          PERFORM set_config('app.platform_admin',COALESCE(prior,''),true);
        EXCEPTION WHEN OTHERS THEN
          PERFORM set_config('app.platform_admin',COALESCE(prior,''),true);
          RAISE;
        END $$""")
    for name, body in FUNCTIONS.items():
        op.execute(body)
        op.execute(f"REVOKE ALL ON FUNCTION {name}() FROM PUBLIC")
    for table, name, function in (
        ("backups", "capacity_owner", "vnbui_capacity_owner"),
        ("backups", "capacity_effect", "vnbui_capacity_effect"),
        ("s3_publications", "capacity_effect", "vnbui_capacity_effect"),
        ("settings_v3", "capacity_policy", "vnbui_capacity_policy"),
    ):
        actions = (
            "INSERT OR UPDATE"
            if name == "capacity_effect"
            else "INSERT OR UPDATE OR DELETE"
        )
        op.execute(
            f"CREATE TRIGGER {name} BEFORE {actions} ON {table} FOR EACH ROW EXECUTE FUNCTION {function}()"
        )
    op.execute(
        "CREATE TRIGGER audit_capacity AFTER UPDATE ON backups FOR EACH ROW WHEN (OLD.capacity_state IS DISTINCT FROM NEW.capacity_state) EXECUTE FUNCTION vnbui_capacity_audit()"
    )


def downgrade():
    raise RuntimeError("Capacity custody requires reviewed database/image rollback")
