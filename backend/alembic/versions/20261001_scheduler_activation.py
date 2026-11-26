"""Mount organization-owned scheduling, including incremental publication."""

from alembic import op
from sqlalchemy import text

revision = "scheduler_activation"
down_revision = "storage_generation_publication"
branch_labels = None
depends_on = None


SCHEDULER_PUBLICATION = """
 IF b.authority_kind='human' THEN
  SELECT * INTO u FROM public.users WHERE id=b.initiating_user_id AND org_id=org FOR UPDATE;
  IF u.id IS NULL OR u.is_active IS DISTINCT FROM true OR u.role NOT IN ('admin','operator') THEN
   RAISE EXCEPTION 'Publication human authority unavailable' USING ERRCODE='23514'; END IF;
 ELSIF b.authority_kind='scheduler' THEN
  SELECT * INTO occurrence FROM public.schedule_occurrences WHERE id=b.scheduler_occurrence_id AND org_id=org;
  SELECT * INTO schedule FROM public.schedules WHERE id=occurrence.schedule_id AND org_id=org FOR UPDATE;
  SELECT * INTO grant_record FROM public.scheduler_grants WHERE id=occurrence.grant_id AND org_id=org FOR UPDATE;
  IF occurrence.id IS NULL OR schedule.id IS NULL OR grant_record.id IS NULL
    OR b.initiating_user_id IS NOT NULL OR grant_record.state<>'active'
    OR grant_record.org_epoch IS DISTINCT FROM (SELECT scheduler_epoch FROM public.organizations WHERE id=org)
    OR schedule.retired_at IS NOT NULL OR schedule.current_grant_id IS DISTINCT FROM grant_record.id
    OR schedule.authority_revision IS DISTINCT FROM grant_record.schedule_revision
    OR occurrence.schedule_revision IS DISTINCT FROM grant_record.schedule_revision
    OR p.dispatch_admission->>'grant_id' IS DISTINCT FROM grant_record.id
    OR p.dispatch_admission->>'scope_sha256' IS DISTINCT FROM grant_record.scope_sha256
    OR NOT EXISTS(SELECT 1 FROM public.schedule_occurrence_members WHERE occurrence_id=occurrence.id AND vm_id=b.vm_id AND org_id=org)
    OR NOT EXISTS(SELECT 1 FROM public.backup_queue WHERE scheduler_occurrence_id=occurrence.id
                  AND started_backup_id=b.id AND authority_kind='scheduler' AND status='claimed') THEN
   RAISE EXCEPTION 'Publication scheduler authority unavailable' USING ERRCODE='23514'; END IF;
 ELSE RAISE EXCEPTION 'Publication original authority unavailable' USING ERRCODE='23514';
 END IF;
 IF b.status NOT IN ('pending','running')
"""

GRANT_ADMIN = """
  -- Schema owners can provision controlled fixtures/migrations. Runtime is
  -- separately prohibited from owning these tables or bypassing row security.
  IF current_user<>pg_get_userbyid((SELECT relowner FROM pg_class WHERE oid='public.scheduler_grants'::regclass)) THEN
    IF NEW.enrolled_by IS DISTINCT FROM nullif(current_setting('app.user_id',true),'')
       OR NEW.org_id IS DISTINCT FROM nullif(current_setting('app.current_org',true),'')
       OR current_setting('app.platform_admin',true)='true'
       OR NOT EXISTS(SELECT 1 FROM public.users WHERE id=NEW.enrolled_by AND org_id=NEW.org_id
                     AND is_active=true AND role='admin') THEN
      RAISE EXCEPTION 'Only organization administrators may issue scheduler grants' USING ERRCODE='23514';
    END IF;
  END IF;
"""


def _definition(signature):
    return op.get_bind().scalar(
        text("SELECT pg_get_functiondef(CAST(:signature AS regprocedure))"),
        {"signature": signature},
    )


def upgrade():
    grant = _definition("public.vnbui_scheduler_grant_insert()")
    marker = "  RETURN NEW;"
    assert grant.count(marker) == 1
    op.execute(grant.replace(marker, GRANT_ADMIN + marker))
    construct = _definition("public.vnbui_scheduler_construct()")
    old = "g.scope->'options'->>'backup_type' IS DISTINCT FROM 'full'"
    assert old in construct
    op.execute(
        construct.replace(
            old,
            "(g.scope->'options'->>'backup_type' IN ('full','incremental')) IS NOT TRUE",
        )
    )
    complete = _definition("public.vnbui_scheduler_complete()")
    old_tags = "b.tags IS DISTINCT FROM q.tags"
    assert complete.count(old_tags) == 1
    # Published status and retention presentation are not schedule options.
    # Keep arbitrary caller tags frozen, allowing only these server-owned facts
    # after the narrow publisher has installed an accepted generation. The
    # generation/receipt, not a tag, remains the completion authority.
    status_tags = "ARRAY['checkpoint_required','checkpoint_committed','generation_id','guest_consistency','scrub_required','storage_deletion','deletion_error','deletion_failed_at']::text[]"
    op.execute(
        complete.replace(
            old_tags,
            f"""(b.tags IS DISTINCT FROM q.tags AND (
          NOT EXISTS(SELECT 1 FROM public.storage_lineage_generations WHERE backup_id=b.id AND org_id=b.org_id AND state='accepted')
          OR (coalesce(b.tags,'{{}}'::jsonb)-{status_tags}) IS DISTINCT FROM
             (coalesce(q.tags,'{{}}'::jsonb)-{status_tags})))""",
        )
    )
    publication = _definition(
        "public.vnbui_publish_storage_generation(text,text,text,text)"
    )
    declaration = " a public.agents; u public.users; v public.vms;"
    assert declaration in publication
    publication = publication.replace(
        declaration,
        declaration
        + "\n occurrence public.schedule_occurrences; schedule public.schedules; grant_record public.scheduler_grants; cert public.agent_certificates;",
    )
    old = """ SELECT * INTO u FROM public.users WHERE id=b.initiating_user_id AND org_id=org FOR UPDATE;
 IF b.authority_kind IS DISTINCT FROM 'human' OR u.id IS NULL OR u.is_active IS DISTINCT FROM true
   OR u.role NOT IN ('admin','operator') OR b.status NOT IN ('pending','running')"""
    assert old in publication
    publication = publication.replace(old, SCHEDULER_PUBLICATION)
    old_credential = " ELSE\n  RAISE EXCEPTION 'Publication requires authenticated agent key' USING ERRCODE='23514';"
    assert old_credential in publication
    publication = publication.replace(
        old_credential,
        """ ELSIF credential_kind='certificate' THEN
  SELECT * INTO cert FROM public.agent_certificates WHERE fingerprint=credential_id AND agent_id=a.id FOR UPDATE;
  IF cert.id IS NULL OR (SELECT count(*) FROM public.agent_certificates WHERE fingerprint=credential_id)<>1
    OR cert.status IS DISTINCT FROM 'active' OR cert.expires_at<=timezone('UTC',clock_timestamp()) THEN
   RAISE EXCEPTION 'Publication credential unavailable' USING ERRCODE='23514'; END IF;
 ELSE
  RAISE EXCEPTION 'Publication requires authenticated agent credential' USING ERRCODE='23514';""",
    )
    op.execute(publication)


def downgrade():
    raise RuntimeError(
        "Scheduler grants and accepted lineage require forward migration or reviewed restore"
    )
