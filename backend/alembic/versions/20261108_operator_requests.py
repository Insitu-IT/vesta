"""Retained operator identity, dispatch custody and staged agent credentials."""

from alembic import op
import sqlalchemy as sa
from sqlalchemy import (
    Column,
    String,
    Integer,
    Boolean,
    DateTime,
    ForeignKey,
    UniqueConstraint,
    Index,
    text,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB

revision = "operator_requests"
down_revision = "verification_budget"
branch_labels = None
depends_on = None

GUARDS = r"""
CREATE FUNCTION public.vnbui_operator_custody() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
DECLARE request public.operator_requests%ROWTYPE; immutable_old jsonb; immutable_new jsonb;
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'Operator custody is retained' USING ERRCODE='23514'; END IF;
 IF TG_TABLE_NAME='operator_requests' THEN
  IF TG_OP='INSERT' AND NOT EXISTS(SELECT 1 FROM public.users WHERE id=NEW.actor_id AND org_id=NEW.org_id AND is_active) THEN
   RAISE EXCEPTION 'Active operator principal unavailable' USING ERRCODE='23514'; END IF;
  IF TG_OP='UPDATE' THEN
   immutable_old:=to_jsonb(OLD)-ARRAY['response_status','response_body','completed_at'];
   immutable_new:=to_jsonb(NEW)-ARRAY['response_status','response_body','completed_at'];
   IF immutable_new IS DISTINCT FROM immutable_old OR (OLD.completed_at IS NOT NULL AND to_jsonb(NEW) IS DISTINCT FROM to_jsonb(OLD)) THEN
    RAISE EXCEPTION 'Operator request identity and outcomes are immutable' USING ERRCODE='23514'; END IF;
  END IF;
  IF NEW.contract_version<>1 OR NEW.fingerprint !~ '^[0-9a-f]{64}$'
   OR NEW.request_id !~ '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
   OR NEW.action='' OR NEW.actor_id='' THEN
   RAISE EXCEPTION 'Operator request binding unavailable' USING ERRCODE='23514'; END IF;
  IF (NEW.completed_at IS NULL) IS DISTINCT FROM (NEW.response_status IS NULL)
   OR (NEW.completed_at IS NULL) IS DISTINCT FROM (NEW.response_body IS NULL)
   OR (NEW.response_status IS NOT NULL AND NEW.response_status NOT BETWEEN 200 AND 599)
   OR (NEW.response_body IS NOT NULL AND jsonb_typeof(NEW.response_body)<>'object') THEN
   RAISE EXCEPTION 'Operator outcome unavailable' USING ERRCODE='23514'; END IF;
  RETURN NEW;
 END IF;
 SELECT * INTO request FROM public.operator_requests WHERE id=NEW.request_record_id AND org_id=NEW.org_id;
 IF NOT FOUND THEN RAISE EXCEPTION 'Original operator request unavailable' USING ERRCODE='23514'; END IF;
 IF TG_TABLE_NAME='operator_dispatches' THEN
  IF NEW.actor_id IS DISTINCT FROM request.actor_id OR NEW.kind NOT IN ('backup','restore') OR NEW.state NOT IN ('pending','dispatching','delivered','held') THEN
   RAISE EXCEPTION 'Dispatch binding unavailable' USING ERRCODE='23514'; END IF;
  IF TG_OP='INSERT' THEN
   IF NEW.state<>'pending' OR NOT (
    (NEW.kind='backup' AND request.action IN ('backup.create','backup.bulk_create') AND EXISTS(SELECT 1 FROM public.backups WHERE id=NEW.resource_id AND org_id=NEW.org_id AND initiating_user_id=NEW.actor_id AND authority_kind='human'))
    OR (NEW.kind='restore' AND request.action='restore.create' AND EXISTS(SELECT 1 FROM public.restores WHERE id=NEW.resource_id AND org_id=NEW.org_id AND created_by=NEW.actor_id))) THEN
    RAISE EXCEPTION 'Original dispatch resource unavailable' USING ERRCODE='23514'; END IF;
  END IF;
  IF TG_OP='UPDATE' AND (to_jsonb(NEW)-ARRAY['state','reason','updated_at'] IS DISTINCT FROM to_jsonb(OLD)-ARRAY['state','reason','updated_at']
   OR (NEW.state IS DISTINCT FROM OLD.state AND NOT ((OLD.state='pending' AND NEW.state='dispatching') OR (OLD.state='dispatching' AND NEW.state IN ('delivered','held')) OR (OLD.state='held' AND NEW.state='dispatching')))) THEN
   RAISE EXCEPTION 'Dispatch custody transition unavailable' USING ERRCODE='23514'; END IF;
 ELSE
  IF NEW.created_by IS DISTINCT FROM request.actor_id OR request.action<>'credential.agent.rotate'
   OR ((TG_OP='INSERT' OR (TG_OP='UPDATE' AND NEW.state='activated' AND OLD.state='pending')) AND NOT EXISTS(SELECT 1 FROM public.agents WHERE id=NEW.agent_id AND org_id=NEW.org_id))
   OR NEW.state NOT IN ('pending','activated','cancelled','expired') OR NEW.expires_at<=NEW.created_at
   OR NEW.predecessor_hash !~ '^[0-9a-f]{64}$' OR NEW.candidate_hash !~ '^[0-9a-f]{64}$'
   OR (NEW.state='activated') IS DISTINCT FROM (NEW.activated_at IS NOT NULL) THEN
   RAISE EXCEPTION 'Staged key binding unavailable' USING ERRCODE='23514'; END IF;
  IF TG_OP='INSERT' AND NEW.state<>'pending' THEN RAISE EXCEPTION 'Staged key must begin pending' USING ERRCODE='23514'; END IF;
  IF TG_OP='UPDATE' AND (to_jsonb(NEW)-ARRAY['state','activated_at'] IS DISTINCT FROM to_jsonb(OLD)-ARRAY['state','activated_at']
    OR (OLD.state<>'pending' AND to_jsonb(NEW) IS DISTINCT FROM to_jsonb(OLD))
    OR (OLD.state='pending' AND NEW.state NOT IN ('pending','activated','cancelled','expired'))) THEN
   RAISE EXCEPTION 'Staged key custody is immutable' USING ERRCODE='23514'; END IF;
 END IF;
 RETURN NEW;
END $$;
CREATE FUNCTION public.vnbui_operator_request_complete() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM public.operator_requests WHERE id=NEW.id AND completed_at IS NOT NULL) THEN
  RAISE EXCEPTION 'Incomplete operator request cannot commit' USING ERRCODE='23514'; END IF;
 RETURN NULL;
END $$;
"""


def upgrade():
    op.create_table(
        "operator_requests",
        Column("id", String, primary_key=True),
        Column("request_id", String(36), nullable=False),
        Column("actor_id", String, nullable=False),
        Column("action", String(64), nullable=False),
        Column("fingerprint", String(64), nullable=False),
        Column("contract_version", Integer, nullable=False, server_default=text("1")),
        Column(
            "created_at",
            DateTime(timezone=True),
            nullable=False,
            server_default=func.now(),
        ),
        Column("response_status", Integer),
        Column("response_body", JSONB),
        Column("completed_at", DateTime(timezone=True)),
        Column(
            "secret_delivery", Boolean, nullable=False, server_default=text("false")
        ),
        Column(
            "org_id",
            String,
            ForeignKey("organizations.id", name="fk_operator_requests_org_id"),
            nullable=False,
        ),
        UniqueConstraint(
            "org_id", "request_id", name="uq_operator_requests_org_request"
        ),
    )
    op.create_table(
        "operator_dispatches",
        Column("id", String, primary_key=True),
        Column(
            "request_record_id",
            String,
            ForeignKey("operator_requests.id"),
            nullable=False,
        ),
        Column("kind", String(16), nullable=False),
        Column("resource_id", String, nullable=False),
        Column("actor_id", String, nullable=False),
        Column("state", String(16), nullable=False, server_default=text("'pending'")),
        Column("reason", String(64)),
        Column(
            "created_at",
            DateTime(timezone=True),
            nullable=False,
            server_default=func.now(),
        ),
        Column(
            "updated_at",
            DateTime(timezone=True),
            nullable=False,
            server_default=func.now(),
        ),
        Column(
            "org_id",
            String,
            ForeignKey("organizations.id", name="fk_operator_dispatches_org_id"),
            nullable=False,
        ),
        UniqueConstraint("kind", "resource_id", name="uq_operator_dispatches_resource"),
    )
    op.create_table(
        "agent_key_rotations",
        Column("id", String, primary_key=True),
        Column("agent_id", String, nullable=False),
        Column(
            "request_record_id",
            String,
            ForeignKey("operator_requests.id"),
            nullable=False,
        ),
        Column("predecessor_hash", String(64), nullable=False),
        Column("candidate_hash", String(64), nullable=False),
        Column("key_prefix", String(8), nullable=False),
        Column("state", String(16), nullable=False, server_default=text("'pending'")),
        Column(
            "created_at",
            DateTime(timezone=True),
            nullable=False,
            server_default=func.now(),
        ),
        Column("expires_at", DateTime(timezone=True), nullable=False),
        Column("activated_at", DateTime(timezone=True)),
        Column("created_by", String, nullable=False),
        Column(
            "org_id",
            String,
            ForeignKey("organizations.id", name="fk_agent_key_rotations_org_id"),
            nullable=False,
        ),
        UniqueConstraint("request_record_id", name="uq_agent_key_rotations_request"),
        UniqueConstraint("candidate_hash", name="uq_agent_key_rotations_candidate"),
    )
    op.create_index(
        "ix_agent_key_rotations_pending",
        "agent_key_rotations",
        ["agent_id"],
        unique=True,
        postgresql_where=text("(state)::text = 'pending'::text"),
    )
    for table in ("operator_requests", "operator_dispatches", "agent_key_rotations"):
        op.create_index(f"idx_{table}_org_id", table, ["org_id"])
    op.create_index(
        "ix_operator_dispatches_state_created",
        "operator_dispatches",
        ["state", "created_at", "id"],
    )
    op.execute(GUARDS)
    for table in ("operator_requests", "operator_dispatches", "agent_key_rotations"):
        op.execute(f"ALTER TABLE public.{table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE public.{table} FORCE ROW LEVEL SECURITY")
        op.execute(
            f"CREATE POLICY tenant_isolation_{table} ON public.{table} USING (org_id::text = NULLIF(current_setting('app.current_org',true),'') OR current_setting('app.platform_admin',true)='true') WITH CHECK (org_id::text = NULLIF(current_setting('app.current_org',true),'') OR current_setting('app.platform_admin',true)='true')"
        )
        op.execute(f"REVOKE ALL ON public.{table} FROM PUBLIC")
        op.execute(
            f"CREATE TRIGGER operator_custody BEFORE INSERT OR UPDATE OR DELETE ON public.{table} FOR EACH ROW EXECUTE FUNCTION public.vnbui_operator_custody()"
        )
    op.execute(
        "CREATE CONSTRAINT TRIGGER operator_request_complete AFTER INSERT OR UPDATE ON public.operator_requests DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.vnbui_operator_request_complete()"
    )
    op.execute(
        "REVOKE ALL ON FUNCTION public.vnbui_operator_custody(), public.vnbui_operator_request_complete() FROM PUBLIC"
    )


def downgrade():
    if (
        op.get_bind()
        .execute(text("SELECT EXISTS(SELECT 1 FROM public.operator_requests)"))
        .scalar()
    ):
        raise RuntimeError(
            "Operator request identities must be retained; downgrade refused"
        )
    for table in ("agent_key_rotations", "operator_dispatches", "operator_requests"):
        op.drop_table(table)
    op.execute("DROP FUNCTION public.vnbui_operator_custody()")
    op.execute("DROP FUNCTION public.vnbui_operator_request_complete()")
