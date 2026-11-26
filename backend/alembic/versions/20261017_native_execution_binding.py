"""Bind original producer execution before local or hypervisor effects."""

import json

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = "native_execution_binding"
down_revision = "native_closed_failure"
branch_labels = None
depends_on = None

GUARD = r"""
CREATE FUNCTION vnbui_native_execution() RETURNS trigger
LANGUAGE plpgsql VOLATILE SET search_path=pg_catalog,public AS $$
BEGIN
 IF TG_OP='INSERT' THEN
   IF NEW.native_execution IS NOT NULL THEN
     RAISE EXCEPTION 'Native execution requires original committed intent' USING ERRCODE='23514';
   END IF;
   RETURN NEW;
 END IF;
 IF NEW.native_execution IS NOT DISTINCT FROM OLD.native_execution THEN RETURN NEW; END IF;
 IF OLD.native_execution IS NOT NULL THEN
   IF OLD.native_execution->>'state' IS DISTINCT FROM 'preexisting'
     OR OLD.native_job_transaction_id IS NULL
     OR (OLD.native_execution->>'boundary_xid')::bigint>=OLD.native_job_transaction_id THEN
     RAISE EXCEPTION 'Native execution is immutable or unbound existing custody' USING ERRCODE='23514';
   END IF;
 END IF;
 IF current_setting('transaction_isolation')<>'read committed'
   OR current_setting('app.platform_admin',true)='true'
   OR current_setting('app.demo',true)='true'
   OR NULLIF(current_setting('app.user_id',true),'') IS NOT NULL
   OR current_setting('app.current_org',true) IS DISTINCT FROM OLD.org_id
   OR EXISTS(SELECT 1 FROM pg_roles WHERE rolname=current_user AND (rolsuper OR rolbypassrls))
   OR OLD.capacity_state IS DISTINCT FROM 'reserved'
   OR (OLD.status IN ('pending','running','cleanup_required','failed')) IS NOT TRUE
   OR OLD.native_job_intent IS NULL OR OLD.native_job_transaction_id IS NULL
   OR OLD.native_job_transaction_id=txid_current()
   OR OLD.native_job_intent->>'producer' IS DISTINCT FROM 'libvirt-push-qcow2/1'
   OR OLD.native_job_intent->>'backup_id' IS DISTINCT FROM OLD.id
   OR OLD.native_job_intent->>'org_id' IS DISTINCT FROM OLD.org_id
   OR OLD.native_inventory IS NOT NULL OR OLD.native_no_effect IS NOT NULL
   OR OLD.native_closed_failure IS NOT NULL OR OLD.wrapped_dek IS NOT NULL
   OR EXISTS(SELECT 1 FROM public.s3_publications WHERE backup_id=OLD.id)
   OR NOT EXISTS(SELECT 1 FROM public.vms WHERE id=OLD.vm_id AND org_id=OLD.org_id
      AND provider='libvirt' AND agent_id=OLD.native_job_intent->>'agent_id')
   OR (to_jsonb(NEW)-'native_execution') IS DISTINCT FROM (to_jsonb(OLD)-'native_execution')
   OR jsonb_typeof(NEW.native_execution) IS DISTINCT FROM 'object'
   OR NOT NEW.native_execution ?& ARRAY['schema','state','request_sha256','intent_sha256','intent_canonical']
   OR NEW.native_execution-ARRAY['schema','state','request_sha256','intent_sha256','intent_canonical']<>'{}'::jsonb
   OR NEW.native_execution->'schema' IS DISTINCT FROM '1'::jsonb
   OR NEW.native_execution->>'state' IS DISTINCT FROM 'bound'
   OR jsonb_typeof(NEW.native_execution->'state') IS DISTINCT FROM 'string'
   OR jsonb_typeof(NEW.native_execution->'request_sha256') IS DISTINCT FROM 'string'
   OR jsonb_typeof(NEW.native_execution->'intent_sha256') IS DISTINCT FROM 'string'
   OR jsonb_typeof(NEW.native_execution->'intent_canonical') IS DISTINCT FROM 'string'
   OR (NEW.native_execution->>'request_sha256' ~ '^[0-9a-f]{64}$') IS NOT TRUE
   OR (NEW.native_execution->>'intent_sha256' ~ '^[0-9a-f]{64}$') IS NOT TRUE
   OR octet_length(NEW.native_execution::text)>131072
   OR (NEW.native_execution->>'intent_canonical')::jsonb IS DISTINCT FROM OLD.native_job_intent
   OR NEW.native_execution->>'intent_sha256' IS DISTINCT FROM
      encode(sha256(convert_to(NEW.native_execution->>'intent_canonical','UTF8')),'hex') THEN
   RAISE EXCEPTION 'Native execution binding unavailable' USING ERRCODE='23514';
 END IF;
 NEW.native_execution:=NEW.native_execution||jsonb_build_object('bound_xid',txid_current());
 RETURN NEW;
END $$;
CREATE TRIGGER native_execution BEFORE INSERT OR UPDATE ON backups
 FOR EACH ROW EXECUTE FUNCTION vnbui_native_execution();
"""


def upgrade():
    op.execute("SET CONSTRAINTS ALL IMMEDIATE")
    boundary = int(op.get_bind().scalar(sa.text("SELECT txid_current()")))
    # Constant fast default fences old rows without running UPDATE triggers or
    # editing any accepted/held custody. Future rows start with no execution.
    prior = json.dumps(dict(schema=1, state="preexisting", boundary_xid=boundary))
    op.add_column(
        "backups",
        sa.Column(
            "native_execution",
            JSONB(),
            nullable=True,
            server_default=sa.text("'" + prior + "'::jsonb"),
        ),
    )
    op.alter_column("backups", "native_execution", server_default=None)
    op.execute(GUARD)


def downgrade():
    raise RuntimeError(
        "Native execution binding requires reviewed database/image rollback"
    )
