"""Explicit automatic schedule policy and immutable decision storage.

No historical policy, grant or decision is manufactured. Existing fixed modes
keep their authority; automatic execution still needs its own enrolled scope.
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

from core.scheduler_policy import AUTOMATIC_POLICY_CHECK, SCHEDULE_POLICY_CHECK

revision = "scheduled_full_policy"
down_revision = "native_no_effect"
branch_labels = None
depends_on = None


def _rewrite(name, replacements):
    definition = op.get_bind().scalar(
        sa.text("SELECT pg_get_functiondef(CAST(:signature AS regprocedure))"),
        {"signature": f"public.{name}()"},
    )
    for old, new in replacements:
        if definition.count(old) != 1:
            raise RuntimeError(f"{name} changed; inspect automatic-policy integration")
        definition = definition.replace(old, new)
    op.execute(definition)


# Runs only inside the original queued->claimed authority check, after the
# organization/schedule/grant locks. Snapshot/member privileges remain unchanged.
CLAIM_DECISION = """
      IF g.scope->'options'->>'backup_type'='automatic' THEN
        DECLARE d jsonb:=NEW.backup_decision; h public.storage_lineage_heads;
          gen public.storage_lineage_generations; root public.backups; selected public.backups;
          chain_n integer; reaches_root boolean; root_grant text; root_clock timestamptz;
        BEGIN
          PERFORM 1 FROM public.vms WHERE id=NEW.vm_id AND org_id=c.org_id FOR UPDATE;
          IF (jsonb_typeof(d)='object'
            AND d ?& ARRAY['schema','policy','backup_type','reason','observed_date','generation_id','root_backup_id','root_date','incremental_count']
            AND d-ARRAY['schema','policy','backup_type','reason','observed_date','generation_id','root_backup_id','root_date','incremental_count']='{}'::jsonb
            AND jsonb_typeof(d->'schema')='number' AND d->>'schema'='1'
            AND d->'policy'=g.scope->'options'->'backup_policy'
            AND d->'policy'=s.backup_policy AND s.backup_type='automatic'
            AND jsonb_typeof(d->'backup_type')='string' AND d->>'backup_type'=NEW.backup_type
            AND jsonb_typeof(d->'reason')='string'
            AND jsonb_typeof(d->'observed_date')='string'
            AND d->>'observed_date'=to_char(clock_timestamp() AT TIME ZONE 'UTC','YYYY-MM-DD')
            AND OLD.backup_type='automatic' AND OLD.backup_decision IS NULL
            AND NEW.backup_type IN ('full','incremental')) IS NOT TRUE THEN
            RAISE EXCEPTION 'Automatic decision binding mismatch' USING ERRCODE='23514';
          END IF;
          IF d->>'reason' IN ('parent_unavailable','new_grant','source_changed','root_time_unavailable','previous_failure') THEN
            IF (NEW.backup_type='full' AND d->'generation_id'='null'::jsonb
              AND d->'root_backup_id'='null'::jsonb AND d->'root_date'='null'::jsonb
              AND d->'incremental_count'='null'::jsonb) IS NOT TRUE THEN
              RAISE EXCEPTION 'Invalid early-full decision' USING ERRCODE='23514';
            END IF;
          ELSE
            SELECT * INTO h FROM public.storage_lineage_heads WHERE vm_id=NEW.vm_id AND org_id=c.org_id;
            SELECT * INTO gen FROM public.storage_lineage_generations
              WHERE id=h.generation_id AND vm_id=NEW.vm_id AND org_id=c.org_id;
            SELECT * INTO root FROM public.backups WHERE id=gen.root_backup_id AND vm_id=NEW.vm_id AND org_id=c.org_id;
            SELECT * INTO selected FROM public.backups WHERE id=gen.backup_id AND vm_id=NEW.vm_id AND org_id=c.org_id;
            SELECT grant_id INTO root_grant FROM public.schedule_occurrences
              WHERE id=root.scheduler_occurrence_id AND org_id=c.org_id;
            SELECT claimed_at INTO root_clock FROM public.backup_queue
              WHERE started_backup_id=root.id AND scheduler_occurrence_id=root.scheduler_occurrence_id AND vm_id=NEW.vm_id;
            IF h.state IS DISTINCT FROM 'current' OR gen.state IS DISTINCT FROM 'accepted'
              OR h.root_backup_id IS DISTINCT FROM gen.root_backup_id
              OR h.tracker_uid IS DISTINCT FROM gen.tracker_uid OR h.checkpoint IS DISTINCT FROM gen.checkpoint
              OR h.manifest_receipt_sha256 IS DISTINCT FROM gen.manifest_receipt_sha256
              OR gen.id IS DISTINCT FROM d->>'generation_id' OR root.id IS DISTINCT FROM d->>'root_backup_id'
              OR root_clock IS NULL OR timezone('UTC',root_clock)::date>timezone('UTC',clock_timestamp())::date
              OR to_char(timezone('UTC',root_clock),'YYYY-MM-DD') IS DISTINCT FROM d->>'root_date'
              OR root.status IS DISTINCT FROM 'completed' OR selected.status IS DISTINCT FROM 'completed'
              OR root.authority_kind IS DISTINCT FROM 'scheduler' OR root_grant IS DISTINCT FROM g.id
              OR NOT EXISTS(SELECT 1 FROM public.schedule_occurrence_members x
                JOIN public.schedule_occurrence_members y ON y.occurrence_id=c.id AND y.vm_id=NEW.vm_id AND y.org_id=c.org_id
                WHERE x.occurrence_id=root.scheduler_occurrence_id AND x.vm_id=NEW.vm_id AND x.org_id=c.org_id
                  AND x.source_snapshot=y.source_snapshot) THEN
              RAISE EXCEPTION 'Accepted policy parent unavailable' USING ERRCODE='23514';
            END IF;
            WITH RECURSIVE chain AS (
              SELECT x.id,x.backup_id,x.accepted_request->'plan'->'parent' AS parent,ARRAY[x.id] AS seen,0 AS depth
              FROM public.storage_lineage_generations x WHERE x.id=gen.id AND x.org_id=c.org_id
                AND x.vm_id=NEW.vm_id AND x.state='accepted'
              UNION ALL
              SELECT x.id,x.backup_id,x.accepted_request->'plan'->'parent',chain.seen||x.id,chain.depth+1
              FROM chain JOIN public.storage_lineage_generations x ON x.id=chain.parent->>'generation_id'
              WHERE x.org_id=c.org_id AND x.vm_id=NEW.vm_id AND x.state='accepted'
                AND x.root_backup_id=root.id AND NOT x.id=ANY(chain.seen) AND chain.depth<255
            ) SELECT count(*)-1,bool_or(backup_id=root.id AND parent='null'::jsonb)
              INTO chain_n,reaches_root FROM chain;
            IF reaches_root IS DISTINCT FROM true OR jsonb_typeof(d->'incremental_count') IS DISTINCT FROM 'number'
              OR d->>'incremental_count' IS DISTINCT FROM chain_n::text THEN
              RAISE EXCEPTION 'Accepted policy chain mismatch' USING ERRCODE='23514';
            END IF;
            IF chain_n >= (d->'policy'->>'max_incrementals')::integer THEN
              IF NEW.backup_type<>'full' OR d->>'reason'<>'max_incrementals' THEN
                RAISE EXCEPTION 'Maximum incremental chain reached' USING ERRCODE='23514'; END IF;
            ELSIF timezone('UTC',clock_timestamp())::date-timezone('UTC',root_clock)::date >= (d->'policy'->>'full_every_days')::integer THEN
              IF NEW.backup_type<>'full' OR d->>'reason'<>'full_interval' THEN
                RAISE EXCEPTION 'Periodic full required' USING ERRCODE='23514'; END IF;
            ELSIF NEW.backup_type<>'incremental' OR d->>'reason'<>'within_policy' THEN
              RAISE EXCEPTION 'Invalid within-policy decision' USING ERRCODE='23514';
            END IF;
            IF NEW.backup_type='incremental' AND EXISTS(SELECT 1 FROM public.backups
              WHERE org_id=c.org_id AND vm_id=NEW.vm_id AND status IN ('failed','cancelled')
                AND capacity_state='released' AND created_at>selected.created_at) THEN
              RAISE EXCEPTION 'Full required after failed attempt' USING ERRCODE='23514';
            END IF;
          END IF;
        END;
      ELSIF NEW.backup_decision IS NOT NULL THEN
        RAISE EXCEPTION 'Decision on fixed schedule' USING ERRCODE='23514';
      END IF;
"""


def upgrade():
    op.execute("SET CONSTRAINTS ALL IMMEDIATE")
    op.add_column(
        "schedules", sa.Column("backup_policy", JSONB(none_as_null=True), nullable=True)
    )
    op.add_column(
        "backup_queue",
        sa.Column("backup_decision", JSONB(none_as_null=True), nullable=True),
    )
    op.create_check_constraint(
        "ck_schedule_backup_policy", "schedules", SCHEDULE_POLICY_CHECK
    )
    definition = op.get_bind().scalar(
        sa.text(
            "SELECT pg_get_functiondef('public.vnbui_scheduler_revision()'::regprocedure)"
        )
    )
    for prefix in ("NEW", "OLD"):
        old = f"{prefix}.workers,{prefix}.tags)"
        if definition.count(old) != 1:
            raise RuntimeError(
                "Schedule revision guard changed; inspect policy integration"
            )
        definition = definition.replace(
            old, f"{prefix}.workers,{prefix}.tags,{prefix}.backup_policy)"
        )
    op.execute(definition)
    policy_check = AUTOMATIC_POLICY_CHECK.replace(
        "__policy__", "(g.scope->'options'->'backup_policy')"
    )
    _rewrite(
        "vnbui_scheduler_construct",
        [
            (
                "(g.scope->'options'->>'backup_type' IN ('full','incremental')) IS NOT TRUE",
                "((g.scope->'options'->>'backup_type' IN ('full','incremental')) OR "
                "(g.scope->'options'->>'backup_type'='automatic' AND "
                + policy_check
                + " IS TRUE AND g.scope->'options'->'backup_policy'=s.backup_policy AND s.backup_type='automatic')) IS NOT TRUE",
            )
        ],
    )
    old_input = """    IF (to_jsonb(NEW)-ARRAY['status','claim_id','claimed_at','started_backup_id','hold_reason']) IS DISTINCT FROM
       (to_jsonb(OLD)-ARRAY['status','claim_id','claimed_at','started_backup_id','hold_reason']) THEN"""
    _rewrite(
        "vnbui_scheduler_queue",
        [
            (
                "BEGIN\n  IF TG_OP='DELETE'",
                "BEGIN\n  IF TG_OP='INSERT' AND NEW.backup_decision IS NOT NULL THEN\n"
                "    RAISE EXCEPTION 'Decision requires atomic claim' USING ERRCODE='23514'; END IF;\n  IF TG_OP='DELETE'",
            ),
            (
                old_input,
                old_input[:-5]
                + " AND NOT (OLD.status='queued' AND NEW.status='claimed' "
                "AND OLD.backup_type='automatic' AND OLD.backup_decision IS NULL AND NEW.backup_decision IS NOT NULL "
                "AND (to_jsonb(NEW)-ARRAY['status','claim_id','claimed_at','started_backup_id','hold_reason','backup_type','backup_decision']) "
                "IS NOT DISTINCT FROM (to_jsonb(OLD)-ARRAY['status','claim_id','claimed_at','started_backup_id','hold_reason','backup_type','backup_decision'])) THEN",
            ),
            (
                "      NEW.claim_id:=pg_catalog.gen_random_uuid();",
                CLAIM_DECISION + "      NEW.claim_id:=pg_catalog.gen_random_uuid();",
            ),
        ],
    )
    _rewrite(
        "vnbui_scheduler_complete",
        [
            (
                "q.backup_type IS DISTINCT FROM g.scope->'options'->>'backup_type'",
                "q.backup_type IS DISTINCT FROM (CASE WHEN g.scope->'options'->>'backup_type'='automatic' "
                "AND q.started_backup_id IS NOT NULL THEN q.backup_decision->>'backup_type' "
                "ELSE g.scope->'options'->>'backup_type' END) "
                "OR (q.backup_decision IS NOT NULL) IS DISTINCT FROM "
                "(g.scope->'options'->>'backup_type'='automatic' AND q.started_backup_id IS NOT NULL)",
            )
        ],
    )
    _rewrite(
        "vnbui_native_inventory",
        [
            (
                "        NEW.native_job_transaction_id := txid_current();",
                """        IF OLD.authority_kind='scheduler' AND EXISTS(
          SELECT 1 FROM public.backup_queue q WHERE q.started_backup_id=OLD.id
            AND q.scheduler_occurrence_id=OLD.scheduler_occurrence_id AND q.vm_id=OLD.vm_id
            AND q.backup_decision IS NOT NULL AND (
              NEW.native_job_intent->'source'->>'backup_type' IS DISTINCT FROM q.backup_type
              OR q.backup_type='incremental' AND NEW.native_job_intent->'parent'->>'generation_id'
                 IS DISTINCT FROM q.backup_decision->>'generation_id'
              OR q.backup_type='full' AND NEW.native_job_intent->'parent' IS DISTINCT FROM 'null'::jsonb)) THEN
          RAISE EXCEPTION 'Native job differs from saved policy decision' USING ERRCODE='23514';
        END IF;
        NEW.native_job_transaction_id := txid_current();""",
            )
        ],
    )
    _rewrite(
        "vnbui_dispatch_admission",
        [
            (
                "  RETURN NEW;\nEND ",
                """  IF b.authority_kind='scheduler' AND EXISTS(
    SELECT 1 FROM public.backup_queue q WHERE q.started_backup_id=b.id
      AND q.scheduler_occurrence_id=b.scheduler_occurrence_id AND q.vm_id=b.vm_id
      AND q.backup_decision IS NOT NULL AND (
        (NEW.expected_plan::jsonb)->'transaction'->'plan'->>'backup_type' IS DISTINCT FROM q.backup_type
        OR q.backup_type='incremental' AND (NEW.expected_plan::jsonb)->'transaction'->'plan'->'parent'->>'generation_id'
           IS DISTINCT FROM q.backup_decision->>'generation_id'
        OR q.backup_type='full' AND (NEW.expected_plan::jsonb)->'transaction'->'plan'->'parent' IS DISTINCT FROM 'null'::jsonb)) THEN
    RAISE EXCEPTION 'Dispatch differs from saved policy decision' USING ERRCODE='23514';
  END IF;
  RETURN NEW;
END """,
            )
        ],
    )


def downgrade():
    raise RuntimeError(
        "Automatic schedule decisions require reviewed database/image rollback"
    )
