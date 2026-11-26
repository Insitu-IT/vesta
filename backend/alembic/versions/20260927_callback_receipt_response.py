"""Exact callback receipt response attachment; other intent consumers dormant."""

import importlib.util
from pathlib import Path
from alembic import op

revision = "callback_receipt_response"
down_revision = "callback_intents"
branch_labels = None
depends_on = None

spec = importlib.util.spec_from_file_location(
    "callback_intent_predecessor",
    Path(__file__).with_name("20260927_callback_intents.py"),
)
previous = importlib.util.module_from_spec(spec)
spec.loader.exec_module(previous)

# Preserve the first-intent contract verbatim and narrow only its final effect
# guard. Wrapped key/control/finalize/checkpoint consumers remain unavailable.
AUTHORITY = (
    """
   SELECT * INTO b FROM public.backups WHERE id=OLD.backup_id AND org_id=OLD.org_id FOR UPDATE;
   IF b.id IS NULL OR current_setting('app.current_org',true) IS DISTINCT FROM b.org_id
     OR current_setting('app.platform_admin',true)='true' OR current_setting('app.demo',true)='true'
     OR current_setting('transaction_isolation')<>'read committed' THEN
     RAISE EXCEPTION 'Callback response owner unavailable' USING ERRCODE='23514';
   END IF;
"""
    + previous.capacity.AUTHORITY.replace(
        "b.status IN ('pending','running')",
        "b.status IN ('pending','running','uploading')",
    )
    + """
   SELECT * INTO callback_agent FROM public.agents WHERE id=expected->>'agent_id' AND org_id=b.org_id FOR UPDATE;
   IF callback_agent.id IS NULL THEN RAISE EXCEPTION 'Callback response agent unavailable' USING ERRCODE='23514'; END IF;
   IF expected->>'credential_kind'='api-key' THEN
     IF expected->>'credential_id' IS DISTINCT FROM callback_agent.api_key_hash THEN
       RAISE EXCEPTION 'Callback response credential unavailable' USING ERRCODE='23514';
     END IF;
   ELSE
     SELECT array_agg(matches.id) INTO cert_ids FROM (
       SELECT id FROM public.agent_certificates WHERE fingerprint=expected->>'credential_id' LIMIT 2 FOR UPDATE
     ) matches;
     IF cardinality(cert_ids) IS DISTINCT FROM 1 THEN
       RAISE EXCEPTION 'Callback response credential unavailable' USING ERRCODE='23514';
     END IF;
     SELECT * INTO cert FROM public.agent_certificates WHERE id=cert_ids[1];
     IF cert.agent_id IS DISTINCT FROM callback_agent.id OR cert.status IS DISTINCT FROM 'active'
       OR cert.expires_at IS NULL OR cert.expires_at<=clock_timestamp() THEN
       RAISE EXCEPTION 'Callback response credential unavailable' USING ERRCODE='23514';
     END IF;
   END IF;
"""
)
ATTACHMENT = (
    """
   IF OLD.receipt_verification_intent IS NULL OR OLD.receipt_verification_xid IS NULL
     OR OLD.receipt_verification_xid=txid_current()
     OR NEW.receipt_verification_intent IS DISTINCT FROM OLD.receipt_verification_intent
     OR NEW.attempt_key_preparation_intent IS DISTINCT FROM OLD.attempt_key_preparation_intent
     OR NEW.attempt_key_disclosure_intent IS DISTINCT FROM OLD.attempt_key_disclosure_intent
     OR jsonb_build_array(NEW.wrapped_attempt_key,NEW.provider_control,NEW.finalize_intent,NEW.checkpoint_proof)
       IS DISTINCT FROM jsonb_build_array(OLD.wrapped_attempt_key,OLD.provider_control,OLD.finalize_intent,OLD.checkpoint_proof)
     OR OLD.prepared_receipt IS NOT NULL OR NEW.prepared_receipt IS NULL
     OR NEW.state IS DISTINCT FROM 'reserved' OR OLD.state IS DISTINCT FROM 'reserved' THEN
     RAISE EXCEPTION 'Callback effect continuation remains dormant' USING ERRCODE='23514';
   END IF;
   expected:=OLD.receipt_verification_intent;
"""
    + AUTHORITY
    + """
   v:=NEW.prepared_receipt::jsonb;
   IF jsonb_typeof(v) IS DISTINCT FROM 'object' OR octet_length(v::text)>12582912
     OR NOT v ?& ARRAY['receipt','receipt_canonical','receipt_sha256','plan_sha256','attempt_id','agent_id','callback_intent','response']
     OR v-ARRAY['receipt','receipt_canonical','receipt_sha256','plan_sha256','attempt_id','agent_id','callback_intent','response']<>'{}'::jsonb
     OR v->'callback_intent' IS DISTINCT FROM expected
     OR v->>'receipt_sha256' IS DISTINCT FROM expected->>'receipt_sha256'
     OR v->>'plan_sha256' IS DISTINCT FROM expected->>'plan_sha256'
     OR v->>'attempt_id' IS DISTINCT FROM expected->>'attempt_id'
     OR v->>'agent_id' IS DISTINCT FROM expected->>'agent_id'
     OR jsonb_typeof(v->'receipt_canonical') IS DISTINCT FROM 'string'
     OR encode(sha256(convert_to(v->>'receipt_canonical','UTF8')),'hex') IS DISTINCT FROM expected->>'receipt_sha256' THEN
     RAISE EXCEPTION 'Callback response binding invalid' USING ERRCODE='23514';
   END IF;
   BEGIN
     IF (v->>'receipt_canonical')::jsonb IS DISTINCT FROM v->'receipt' THEN
       RAISE EXCEPTION 'Callback receipt bytes differ' USING ERRCODE='23514';
     END IF;
   EXCEPTION WHEN invalid_text_representation THEN
     RAISE EXCEPTION 'Callback receipt bytes invalid' USING ERRCODE='23514';
   END;
   doc:=v->'response';
   IF jsonb_typeof(doc) IS DISTINCT FROM 'object'
     OR NOT doc ?& ARRAY['protocol','reservation_id','receipt_sha256','accepted','acceptance_id','verification','scrub_required']
     OR doc-ARRAY['protocol','reservation_id','receipt_sha256','accepted','acceptance_id','verification','scrub_required']<>'{}'::jsonb
     OR doc->>'protocol' IS DISTINCT FROM 'vnbui-storage-transaction/1'
     OR doc->>'reservation_id' IS DISTINCT FROM OLD.id
     OR doc->>'receipt_sha256' IS DISTINCT FROM expected->>'receipt_sha256'
     OR doc->'accepted' IS DISTINCT FROM 'true'::jsonb
     OR jsonb_typeof(doc->'acceptance_id') IS DISTINCT FROM 'string'
     OR doc->>'acceptance_id' !~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
     OR jsonb_typeof(doc->'scrub_required') IS DISTINCT FROM 'boolean'
     OR jsonb_typeof(doc->'verification') IS DISTINCT FROM 'array' THEN
     RAISE EXCEPTION 'Callback response shape invalid' USING ERRCODE='23514';
   END IF;
   IF jsonb_array_length(doc->'verification')<>jsonb_array_length(expected->'objects') THEN
     RAISE EXCEPTION 'Callback verification membership invalid' USING ERRCODE='23514';
   END IF;
   idx:=0;
   FOR obj IN SELECT * FROM jsonb_array_elements(doc->'verification') LOOP
     IF obj IS DISTINCT FROM jsonb_build_object('key',expected->'objects'->idx->'artifact_key',
       'version_id',expected->'objects'->idx->'version_id','assurance',obj->'assurance','reason',obj->'reason')
       OR obj->>'assurance' NOT IN ('provider_checksum_verified','identity_metadata_only')
       OR obj->>'assurance' IS NULL
       OR (obj->>'assurance'='provider_checksum_verified' AND obj->'reason' IS DISTINCT FROM 'null'::jsonb)
       OR (obj->>'assurance'='identity_metadata_only' AND obj->>'reason' IS DISTINCT FROM 'provider_full_object_sha256_unavailable') THEN
       RAISE EXCEPTION 'Callback verification binding invalid' USING ERRCODE='23514';
     END IF;
     idx:=idx+1;
   END LOOP;
   IF (doc->>'scrub_required')::boolean IS DISTINCT FROM EXISTS(
       SELECT 1 FROM jsonb_array_elements(doc->'verification') x WHERE x->>'assurance'<>'provider_checksum_verified') THEN
     RAISE EXCEPTION 'Callback assurance binding invalid' USING ERRCODE='23514';
   END IF;
"""
)
SQL = previous.SQL.replace("CREATE FUNCTION", "CREATE OR REPLACE FUNCTION", 1).replace(
    "   RAISE EXCEPTION 'Callback effect continuation remains dormant' USING ERRCODE='23514';",
    ATTACHMENT,
)


def upgrade():
    op.execute(SQL)
    op.execute("REVOKE ALL ON FUNCTION vnbui_callback_intent() FROM PUBLIC")


def downgrade():
    raise RuntimeError("Callback response custody requires reviewed rollback")
