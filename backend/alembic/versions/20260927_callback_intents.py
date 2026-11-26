"""Immutable first callback intents; IO and recovery remain dormant."""

import importlib.util
from pathlib import Path

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = "callback_intents"
down_revision = "capacity_prerequisite"
branch_labels = None
depends_on = None

KINDS = ("receipt_verification", "attempt_key_preparation", "attempt_key_disclosure")
spec = importlib.util.spec_from_file_location(
    "capacity_predecessor",
    Path(__file__).with_name("20260923_capacity_prerequisite.py"),
)
capacity = importlib.util.module_from_spec(spec)
spec.loader.exec_module(capacity)

# Explicitly extend the existing capacity accounting predicates, not its order.
OWNER = (
    capacity.FUNCTIONS["vnbui_capacity_owner"]
    .replace("CREATE FUNCTION", "CREATE OR REPLACE FUNCTION", 1)
    .replace(
        "dispatch_token IS NOT NULL OR dispatch_admission IS NOT NULL",
        "receipt_verification_intent IS NOT NULL OR attempt_key_preparation_intent IS NOT NULL "
        "OR attempt_key_disclosure_intent IS NOT NULL OR dispatch_token IS NOT NULL OR dispatch_admission IS NOT NULL",
    )
)
EFFECT = capacity.FUNCTIONS["vnbui_capacity_effect"].replace(
    "CREATE FUNCTION", "CREATE OR REPLACE FUNCTION", 1
)
for prefix in ("NEW", "OLD"):
    EFFECT = EFFECT.replace(
        f"{prefix}.dispatch_token,{prefix}.dispatch_admission,",
        f"{prefix}.receipt_verification_intent,{prefix}.attempt_key_preparation_intent,"
        f"{prefix}.attempt_key_disclosure_intent,{prefix}.dispatch_token,{prefix}.dispatch_admission,",
    )
EFFECT = EFFECT.replace(
    '[null,null,null,null,null,null,null,"reserved"]',
    '[null,null,null,null,null,null,null,null,null,null,"reserved"]',
)

SQL = (
    """CREATE FUNCTION vnbui_callback_intent() RETURNS trigger
LANGUAGE plpgsql VOLATILE SET search_path=pg_catalog,public AS $$
DECLARE
 b public.backups; o public.organizations; u public.users;
 s public.schedules; g public.scheduler_grants; c public.schedule_occurrences; q public.backup_queue;
 callback_agent public.agents; cert public.agent_certificates; keyrow public.encryption_keys;
 k text; oldv jsonb; v jsonb; doc jsonb; plan jsonb; expected jsonb; obj jsonb;
 field text; cert_ids text[]; idx integer; nowsec bigint; changed integer:=0;
BEGIN
 IF TG_OP='DELETE' THEN
   IF OLD.receipt_verification_intent IS NOT NULL OR OLD.attempt_key_preparation_intent IS NOT NULL
     OR OLD.attempt_key_disclosure_intent IS NOT NULL THEN
     RAISE EXCEPTION 'Callback custody cannot be deleted' USING ERRCODE='23514';
   END IF;
   RETURN OLD;
 END IF;
 FOREACH k IN ARRAY ARRAY['receipt_verification','attempt_key_preparation','attempt_key_disclosure'] LOOP
   v:=CASE k WHEN 'receipt_verification' THEN NEW.receipt_verification_intent
     WHEN 'attempt_key_preparation' THEN NEW.attempt_key_preparation_intent
     ELSE NEW.attempt_key_disclosure_intent END;
   IF v='null'::jsonb THEN
     RAISE EXCEPTION 'Callback JSON null is not absence' USING ERRCODE='23514';
   END IF;
   IF TG_OP='INSERT' THEN
     IF v IS NOT NULL OR to_jsonb(NEW)->(k||'_xid')<>'null'::jsonb THEN
       RAISE EXCEPTION 'Callback requires prior custody' USING ERRCODE='23514';
     END IF;
     CONTINUE;
   END IF;
   oldv:=to_jsonb(OLD)->(k||'_intent');
   IF oldv='null'::jsonb THEN oldv:=NULL; END IF;
   IF to_jsonb(NEW)->(k||'_xid') IS DISTINCT FROM to_jsonb(OLD)->(k||'_xid') THEN
     RAISE EXCEPTION 'Callback transaction marker is server owned' USING ERRCODE='23514';
   END IF;
   IF oldv IS NOT NULL AND (v IS DISTINCT FROM oldv OR
       ROW(NEW.id,NEW.org_id,NEW.backup_id) IS DISTINCT FROM ROW(OLD.id,OLD.org_id,OLD.backup_id)) THEN
     RAISE EXCEPTION 'Callback intent is immutable' USING ERRCODE='23514';
   END IF;
   IF v IS NOT DISTINCT FROM oldv THEN CONTINUE; END IF;
   changed:=changed+1;
   IF changed>1 OR v IS NULL OR jsonb_typeof(v) IS DISTINCT FROM 'object'
     OR octet_length(v::text)>1048576 OR v->>'schema' IS DISTINCT FROM '1' THEN
     RAISE EXCEPTION 'Invalid callback intent shape' USING ERRCODE='23514';
   END IF;
   SELECT * INTO b FROM public.backups WHERE id=OLD.backup_id AND org_id=OLD.org_id FOR UPDATE;
   IF b.id IS NULL OR current_setting('app.current_org',true) IS DISTINCT FROM b.org_id
     OR current_setting('app.platform_admin',true)='true' OR current_setting('app.demo',true)='true'
     OR current_setting('transaction_isolation')<>'read committed'
     OR EXISTS(SELECT 1 FROM pg_roles WHERE rolname=current_user AND (rolsuper OR rolbypassrls))
     OR b.capacity_state IS DISTINCT FROM 'reserved'
     OR OLD.state IS DISTINCT FROM 'reserved' OR NEW.state IS DISTINCT FROM OLD.state
     OR OLD.dispatch_admission IS NULL OR OLD.dispatch_token IS NULL OR OLD.dispatch_transaction_id IS NULL
     OR OLD.dispatch_transaction_id=txid_current() OR OLD.expected_plan->>'schema' IS DISTINCT FROM '3'
     OR OLD.prepared_receipt IS NOT NULL THEN
     RAISE EXCEPTION 'Callback requires original reserved custody' USING ERRCODE='23514';
   END IF;
"""
    # Callback effects continue during upload; allocation retains its narrow states.
    + capacity.AUTHORITY.replace(
        "b.status IN ('pending','running')",
        "b.status IN ('pending','running','uploading')",
    )
    + """
   doc:=OLD.expected_plan::jsonb->'transaction'; plan:=doc->'plan';
   SELECT * INTO callback_agent FROM public.agents WHERE id=doc->>'agent_id' AND org_id=b.org_id FOR UPDATE;
   IF callback_agent.id IS NULL OR callback_agent.status IS DISTINCT FROM 'online' THEN
     RAISE EXCEPTION 'Callback agent unavailable' USING ERRCODE='23514';
   END IF;
   IF jsonb_typeof(v->'credential_id') IS DISTINCT FROM 'string' THEN
     RAISE EXCEPTION 'Callback credential identifier must be a string' USING ERRCODE='23514';
   END IF;
   IF v->>'credential_kind'='api-key' THEN
     IF callback_agent.api_key_hash IS NULL OR v->>'credential_id' IS DISTINCT FROM callback_agent.api_key_hash THEN
       RAISE EXCEPTION 'Callback credential unavailable' USING ERRCODE='23514';
     END IF;
   ELSIF v->>'credential_kind'='certificate' THEN
     SELECT array_agg(matches.id) INTO cert_ids FROM (
       SELECT id FROM public.agent_certificates WHERE fingerprint=v->>'credential_id' LIMIT 2 FOR UPDATE
     ) matches;
     IF cardinality(cert_ids) IS DISTINCT FROM 1 THEN
       RAISE EXCEPTION 'Callback credential unavailable' USING ERRCODE='23514';
     END IF;
     SELECT * INTO cert FROM public.agent_certificates WHERE id=cert_ids[1];
     IF cert.id IS NULL OR cert.agent_id IS DISTINCT FROM callback_agent.id
       OR cert.status IS DISTINCT FROM 'active' OR cert.expires_at IS NULL
       OR cert.expires_at<=clock_timestamp() THEN
       RAISE EXCEPTION 'Callback credential unavailable' USING ERRCODE='23514';
     END IF;
   ELSE RAISE EXCEPTION 'Callback credential kind invalid' USING ERRCODE='23514'; END IF;
   expected:=jsonb_build_object('schema',1,'operation',k,'org_id',OLD.org_id,
     'agent_id',callback_agent.id,'backup_id',OLD.backup_id,'reservation_id',OLD.id,
     'attempt_id',plan->>'attempt_id','claim_id',q.claim_id,'capacity_id',b.capacity_id,
     'plan_sha256',doc->>'plan_sha256',
     'dispatch_sha256',encode(sha256(convert_to(OLD.dispatch_admission::text,'UTF8')),'hex'),
     'target_sha256',encode(sha256(convert_to((plan->'target')::text,'UTF8')),'hex'),
     'credential_kind',v->'credential_kind','credential_id',v->'credential_id',
     'nonce',v->'nonce','created_at',v->'created_at','expires_at',v->'expires_at');
   FOREACH field IN ARRAY ARRAY['nonce','org_id','agent_id','backup_id','reservation_id','attempt_id','capacity_id'] LOOP
     IF jsonb_typeof(v->field) IS DISTINCT FROM 'string' OR v->>field !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$' THEN
       RAISE EXCEPTION 'Callback UUID invalid' USING ERRCODE='23514';
     END IF;
   END LOOP;
   nowsec:=floor(extract(epoch FROM clock_timestamp()));
   IF jsonb_typeof(v->'created_at') IS DISTINCT FROM 'number' OR v->>'created_at' !~ '^[0-9]{1,12}$'
     OR jsonb_typeof(v->'expires_at') IS DISTINCT FROM 'number' OR v->>'expires_at' !~ '^[0-9]{1,12}$' THEN
     RAISE EXCEPTION 'Callback lifetime invalid' USING ERRCODE='23514';
   END IF;
   IF (v->>'created_at')::bigint NOT BETWEEN nowsec-5 AND nowsec
     OR (v->>'expires_at')::bigint NOT BETWEEN nowsec+1 AND (v->>'created_at')::bigint+60 THEN
     RAISE EXCEPTION 'Callback lifetime expired or unbounded' USING ERRCODE='23514';
   END IF;
   IF k='receipt_verification' THEN
     IF jsonb_typeof(v->'receipt_sha256') IS DISTINCT FROM 'string' OR v->>'receipt_sha256' !~ '^[0-9a-f]{64}$'
       OR jsonb_typeof(v->'objects') IS DISTINCT FROM 'array' THEN
       RAISE EXCEPTION 'Receipt intent invalid' USING ERRCODE='23514';
     END IF;
     IF jsonb_array_length(v->'objects')<>jsonb_array_length(plan->'artifacts') OR jsonb_array_length(v->'objects')=0 THEN
       RAISE EXCEPTION 'Receipt membership invalid' USING ERRCODE='23514';
     END IF;
     idx:=0;
     FOR obj IN SELECT * FROM jsonb_array_elements(v->'objects') LOOP
       IF obj IS DISTINCT FROM jsonb_build_object('artifact_key',plan->'artifacts'->idx->>'key','version_id',obj->'version_id','etag',obj->'etag')
         OR NOT obj ?& ARRAY['artifact_key','version_id','etag']
         OR jsonb_typeof(obj->'artifact_key') IS DISTINCT FROM 'string'
         OR jsonb_typeof(obj->'etag') IS DISTINCT FROM 'string' OR length(obj->>'etag') NOT BETWEEN 1 AND 1024
         OR (obj->'version_id'<>'null'::jsonb AND (jsonb_typeof(obj->'version_id') IS DISTINCT FROM 'string' OR length(obj->>'version_id') NOT BETWEEN 1 AND 1024)) THEN
         RAISE EXCEPTION 'Receipt object binding invalid' USING ERRCODE='23514';
       END IF;
       idx:=idx+1;
     END LOOP;
     expected:=expected||jsonb_build_object('receipt_sha256',v->'receipt_sha256','objects',v->'objects');
   ELSE
     SELECT * INTO keyrow FROM public.encryption_keys WHERE id=split_part(plan->'encryption'->>'key_ref',':',2) AND org_id=b.org_id FOR UPDATE;
     IF keyrow.id IS NULL OR keyrow.status IS DISTINCT FROM 'active' OR keyrow.provider IS DISTINCT FROM 'local'
       OR keyrow.algorithm IS DISTINCT FROM 'aes-256-gcm' OR keyrow.provider_key_ref IS NOT NULL
       OR keyrow.key_hash IS DISTINCT FROM split_part(plan->'encryption'->>'key_ref',':',3)
       OR plan->'encryption'->>'format' IS DISTINCT FROM 'vnbu1-aes256gcm-chunk5242880' THEN
       RAISE EXCEPTION 'Callback key identity unavailable' USING ERRCODE='23514';
     END IF;
     expected:=expected||jsonb_build_object('key_ref',plan->'encryption'->>'key_ref','format',plan->'encryption'->>'format');
     IF k='attempt_key_preparation' THEN
       IF OLD.wrapped_attempt_key IS NOT NULL THEN RAISE EXCEPTION 'Key already exists' USING ERRCODE='23514'; END IF;
     ELSE
       IF OLD.wrapped_attempt_key IS NULL THEN RAISE EXCEPTION 'Committed key required' USING ERRCODE='23514'; END IF;
       expected:=expected||jsonb_build_object('wrapped_key_sha256',encode(sha256(convert_to(OLD.wrapped_attempt_key::jsonb::text,'UTF8')),'hex'));
     END IF;
   END IF;
   IF v IS DISTINCT FROM expected THEN RAISE EXCEPTION 'Callback binding mismatch' USING ERRCODE='23514'; END IF;
   NEW:=jsonb_populate_record(NEW,jsonb_build_object(k||'_xid',txid_current()));
 END LOOP;
 -- Checkpoint A records admission only. B must explicitly implement attachment.
 IF TG_OP='UPDATE' AND (NEW.receipt_verification_intent IS NOT NULL OR NEW.attempt_key_preparation_intent IS NOT NULL OR NEW.attempt_key_disclosure_intent IS NOT NULL)
   AND jsonb_build_array(NEW.wrapped_attempt_key,NEW.prepared_receipt,NEW.provider_control,NEW.finalize_intent,NEW.checkpoint_proof)
     IS DISTINCT FROM jsonb_build_array(OLD.wrapped_attempt_key,OLD.prepared_receipt,OLD.provider_control,OLD.finalize_intent,OLD.checkpoint_proof) THEN
   RAISE EXCEPTION 'Callback effect continuation remains dormant' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$"""
)


def upgrade():
    for kind in KINDS:
        op.add_column("s3_publications", sa.Column(kind + "_intent", JSONB()))
        op.add_column("s3_publications", sa.Column(kind + "_xid", sa.BigInteger()))
    op.execute(OWNER)
    op.execute(EFFECT)
    op.execute(SQL)
    op.execute("REVOKE ALL ON FUNCTION vnbui_callback_intent() FROM PUBLIC")
    op.execute(
        "CREATE TRIGGER callback_intent BEFORE INSERT OR UPDATE OR DELETE ON s3_publications FOR EACH ROW EXECUTE FUNCTION vnbui_callback_intent()"
    )


def downgrade():
    raise RuntimeError("Callback custody requires reviewed database/image rollback")
