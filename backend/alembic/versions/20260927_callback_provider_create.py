"""Owner-bound multipart creation custody; no mounted producer consumer."""

import importlib.util
from pathlib import Path

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = "callback_provider_create"
down_revision = "callback_key_order"
branch_labels = None
depends_on = None


def predecessor(filename):
    spec = importlib.util.spec_from_file_location(
        filename, Path(__file__).with_name(filename)
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


previous = predecessor("20260927_callback_key_order.py")
intents = predecessor("20260927_callback_intents.py")

# The shared first-intent owner, credential and canonical binding checks remain
# byte-identical. Result attachment uses the same checks, but not a new admission
# lifetime: a provider response can arrive after the creator's start deadline.
COMMON = intents.SQL.split("   SELECT * INTO b FROM public.backups", 1)[1].split(
    "   nowsec:=floor", 1
)[0]
COMMON = "   SELECT * INTO b FROM public.backups" + COMMON
LIFETIME = intents.SQL.split("   nowsec:=floor", 1)[1].split(
    "   IF k='receipt_verification' THEN", 1
)[0]
LIFETIME = "   nowsec:=floor" + LIFETIME
KEY_IDENTITY = (
    "     SELECT * INTO keyrow"
    + intents.SQL.split("     SELECT * INTO keyrow", 1)[1].split("     expected:=", 1)[
        0
    ]
)

GUARD = (
    """
 IF TG_OP='DELETE' AND OLD.provider_create IS NOT NULL THEN
   RAISE EXCEPTION 'Provider create custody cannot be deleted' USING ERRCODE='23514';
 ELSIF TG_OP='INSERT' AND NEW.provider_create IS NOT NULL THEN
   RAISE EXCEPTION 'Provider create requires prior custody' USING ERRCODE='23514';
 ELSIF TG_OP='UPDATE' THEN
   IF OLD.provider_create IS NOT NULL AND (
       ROW(NEW.id,NEW.org_id,NEW.backup_id) IS DISTINCT FROM ROW(OLD.id,OLD.org_id,OLD.backup_id)
       OR jsonb_build_array(NEW.receipt_verification_intent,NEW.prepared_receipt,NEW.provider_control,
         NEW.attempt_key_preparation_intent,NEW.wrapped_attempt_key,NEW.attempt_key_disclosure_intent,
         NEW.finalize_intent,NEW.checkpoint_proof)
       IS DISTINCT FROM jsonb_build_array(OLD.receipt_verification_intent,OLD.prepared_receipt,OLD.provider_control,
         OLD.attempt_key_preparation_intent,OLD.wrapped_attempt_key,OLD.attempt_key_disclosure_intent,
         OLD.finalize_intent,OLD.checkpoint_proof)) THEN
     RAISE EXCEPTION 'Provider create successor remains dormant' USING ERRCODE='23514';
   END IF;
   IF NEW.provider_create IS DISTINCT FROM OLD.provider_create THEN
     IF jsonb_typeof(NEW.provider_create) IS DISTINCT FROM 'object'
       OR octet_length(NEW.provider_create::text)>67108864
       OR NEW.provider_create='{}'::jsonb
       OR (to_jsonb(NEW)-'provider_create') IS DISTINCT FROM (to_jsonb(OLD)-'provider_create')
       OR OLD.provider_control IS NOT NULL OR OLD.receipt_verification_intent IS NOT NULL
       OR OLD.prepared_receipt IS NOT NULL OR OLD.finalize_intent IS NOT NULL OR OLD.checkpoint_proof IS NOT NULL
       OR OLD.wrapped_attempt_key IS NULL OR OLD.wrapped_attempt_key_xid IS NULL
       OR OLD.wrapped_attempt_key_xid=txid_current() THEN
       RAISE EXCEPTION 'Provider create transition unavailable' USING ERRCODE='23514';
     END IF;
     IF EXISTS(SELECT 1 FROM jsonb_object_keys(COALESCE(OLD.provider_create,'{}')) key
       WHERE NOT NEW.provider_create ? key)
       OR (SELECT count(*) FROM jsonb_object_keys(NEW.provider_create))>4096 THEN
       RAISE EXCEPTION 'Provider create membership invalid' USING ERRCODE='23514';
     END IF;
     pc_changed:=0;
     FOR pc IN SELECT * FROM jsonb_each(NEW.provider_create) LOOP
       pc_old:=OLD.provider_create->pc.key;
       IF pc.value IS NOT DISTINCT FROM pc_old THEN CONTINUE; END IF;
       pc_changed:=pc_changed+1;
       IF pc_changed>1 OR octet_length(pc.key) NOT BETWEEN 1 AND 1024
         OR jsonb_typeof(pc.value) IS DISTINCT FROM 'object' OR octet_length(pc.value::text)>8192
         OR NOT pc.value ?& ARRAY['intent','xid','response']
         OR pc.value-ARRAY['intent','xid','response']<>'{}'::jsonb
         OR jsonb_typeof(pc.value->'intent') IS DISTINCT FROM 'object' THEN
         RAISE EXCEPTION 'Provider create entry invalid' USING ERRCODE='23514';
       END IF;
       k:='provider_create'; v:=pc.value->'intent';
"""
    + COMMON
    + KEY_IDENTITY
    + """
       IF plan->>'provider' IS DISTINCT FROM 'kubevirt'
         OR plan->'encryption'->>'format' IS DISTINCT FROM 'vnbu1-aes256gcm-chunk5242880'
         OR (SELECT count(*) FROM jsonb_array_elements(plan->'artifacts') a WHERE a->>'key'=pc.key)<>1
         OR OLD.wrapped_attempt_key->>'org_id' IS DISTINCT FROM OLD.org_id
         OR OLD.wrapped_attempt_key->>'backup_id' IS DISTINCT FROM OLD.backup_id
         OR OLD.wrapped_attempt_key->>'reservation_id' IS DISTINCT FROM OLD.id
         OR OLD.wrapped_attempt_key->>'attempt_id' IS DISTINCT FROM plan->>'attempt_id'
         OR OLD.wrapped_attempt_key->>'plan_sha256' IS DISTINCT FROM doc->>'plan_sha256'
         OR OLD.wrapped_attempt_key->>'key_ref' IS DISTINCT FROM plan->'encryption'->>'key_ref'
         OR OLD.wrapped_attempt_key->>'format' IS DISTINCT FROM plan->'encryption'->>'format' THEN
         RAISE EXCEPTION 'Provider create committed key binding invalid' USING ERRCODE='23514';
       END IF;
       expected:=expected||jsonb_build_object('artifact_key',pc.key,'wrapped_key_sha256',
         encode(sha256(convert_to(OLD.wrapped_attempt_key::jsonb::text,'UTF8')),'hex'));
       IF v IS DISTINCT FROM expected THEN
         RAISE EXCEPTION 'Provider create intent binding invalid' USING ERRCODE='23514';
       END IF;
       IF pc_old IS NULL THEN
         IF EXISTS(SELECT 1 FROM jsonb_each(COALESCE(OLD.provider_create,'{}')) held
           WHERE held.value->'response' IS NOT DISTINCT FROM 'null'::jsonb) THEN
           RAISE EXCEPTION 'Provider create attempt effect-held' USING ERRCODE='23514';
         END IF;
         IF pc.value->'xid' IS DISTINCT FROM 'null'::jsonb OR pc.value->'response' IS DISTINCT FROM 'null'::jsonb THEN
           RAISE EXCEPTION 'Provider create first intent only' USING ERRCODE='23514';
         END IF;
"""
    + LIFETIME
    + """
         NEW.provider_create:=jsonb_set(NEW.provider_create,ARRAY[pc.key,'xid'],to_jsonb(txid_current()));
       ELSE
         IF pc_old->'response' IS DISTINCT FROM 'null'::jsonb
           OR (pc.value-'response') IS DISTINCT FROM (pc_old-'response')
           OR pc_old->'xid' IS NULL OR pc_old->>'xid' IS NULL
           OR (pc_old->>'xid')::bigint=txid_current() THEN
           RAISE EXCEPTION 'Provider create result requires committed intent' USING ERRCODE='23514';
         END IF;
         obj:=pc.value->'response';
         IF jsonb_typeof(obj) IS DISTINCT FROM 'object'
           OR NOT obj ?& ARRAY['schema','bucket','key','upload_id','request_id','host_id','body_sha256']
           OR obj-ARRAY['schema','bucket','key','upload_id','request_id','host_id','body_sha256']<>'{}'::jsonb
           OR obj->'schema' IS DISTINCT FROM '1'::jsonb
           OR obj->'bucket' IS DISTINCT FROM plan->'target'->'bucket'
           OR obj->'key' IS DISTINCT FROM to_jsonb(pc.key)
           OR jsonb_typeof(obj->'body_sha256') IS DISTINCT FROM 'string'
           OR obj->>'body_sha256' !~ '^[0-9a-f]{64}$' THEN
           RAISE EXCEPTION 'Provider create result binding invalid' USING ERRCODE='23514';
         END IF;
         FOREACH field IN ARRAY ARRAY['upload_id','request_id','host_id'] LOOP
           IF field<>'upload_id' AND obj->field='null'::jsonb THEN CONTINUE; END IF;
           IF jsonb_typeof(obj->field) IS DISTINCT FROM 'string'
             OR octet_length(obj->>field) NOT BETWEEN 1 AND 1024 OR obj->>field ~ '[[:cntrl:]]' THEN
             RAISE EXCEPTION 'Provider create result identifier invalid' USING ERRCODE='23514';
           END IF;
         END LOOP;
       END IF;
     END LOOP;
   END IF;
 END IF;
"""
)
SQL = previous.SQL.replace(
    "DECLARE\n", "DECLARE\n pc record; pc_old jsonb; pc_changed integer;\n", 1
).replace("BEGIN\n", "BEGIN\n" + GUARD, 1)
OWNER = intents.OWNER.replace(
    "provider_control IS NOT NULL",
    "provider_create IS NOT NULL OR provider_control IS NOT NULL",
)
EFFECT = intents.EFFECT
for prefix in ("NEW", "OLD"):
    EFFECT = EFFECT.replace(
        f"{prefix}.provider_control,",
        f"{prefix}.provider_create,{prefix}.provider_control,",
    )
EFFECT = EFFECT.replace(
    '[null,null,null,null,null,null,null,null,null,null,"reserved"]',
    '[null,null,null,null,null,null,null,null,null,null,null,"reserved"]',
)


def upgrade():
    op.add_column("s3_publications", sa.Column("provider_create", JSONB()))
    for sql in (SQL, OWNER, EFFECT):
        op.execute(sql)
    for name in (
        "vnbui_callback_intent",
        "vnbui_capacity_owner",
        "vnbui_capacity_effect",
    ):
        op.execute(f"REVOKE ALL ON FUNCTION {name}() FROM PUBLIC")


def downgrade():
    raise RuntimeError("Provider create custody requires reviewed rollback")
