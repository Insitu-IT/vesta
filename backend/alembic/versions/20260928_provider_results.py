"""Separate completion and checksum-verified HEAD custody; no mounted consumer."""

import importlib.util
from pathlib import Path

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = "provider_results"
down_revision = "provider_parts"
branch_labels = None
depends_on = None
spec = importlib.util.spec_from_file_location(
    "parts_predecessor", Path(__file__).with_name("20260928_provider_parts.py")
)
parts = importlib.util.module_from_spec(spec)
spec.loader.exec_module(parts)
create = parts.create
capacity = parts.capacity
COMMON = parts.COMMON.replace(
    "IF TG_OP='INSERT' OR NEW.acknowledgment IS DISTINCT FROM OLD.acknowledgment THEN",
    "IF TG_OP='INSERT' THEN",
)

# Publication locking serializes all three consumers, including direct SQL.
PART_SQL = parts.SQL.replace(
    "CREATE FUNCTION", "CREATE OR REPLACE FUNCTION", 1
).replace(
    " v:=NEW.intent;",
    """
 IF EXISTS(SELECT 1 FROM public.s3_upload_results WHERE publication_id=pub.id
   AND (artifact_key=NEW.artifact_key OR response IS NULL)) THEN
   RAISE EXCEPTION 'Completion fences part mutation' USING ERRCODE='23514';
 END IF;
 v:=NEW.intent;""",
)
PARENT_SQL = parts.PARENT.replace(
    "BEGIN\n",
    """BEGIN
 IF TG_OP='UPDATE' AND NEW.provider_create IS DISTINCT FROM OLD.provider_create
   AND EXISTS(SELECT 1 FROM public.s3_upload_results WHERE publication_id=OLD.id AND response IS NULL) THEN
   RAISE EXCEPTION 'Provider result attempt effect-held' USING ERRCODE='23514';
 END IF;
""",
    1,
)

SQL = (
    """CREATE FUNCTION vnbui_provider_result() RETURNS trigger
LANGUAGE plpgsql VOLATILE SET search_path=pg_catalog,public AS $$
DECLARE
 pub public.s3_publications; b public.backups; o public.organizations; u public.users;
 s public.schedules; g public.scheduler_grants; c public.schedule_occurrences; q public.backup_queue;
 callback_agent public.agents; cert public.agent_certificates; keyrow public.encryption_keys;
 v jsonb; expected jsonb; doc jsonb; plan jsonb; obj jsonb; artifact jsonb; entry jsonb;
 k text; field text; cert_ids text[]; nowsec bigint; policy jsonb; previous_platform text;
 occupied bigint; same_vm bigint; partset jsonb; total bigint; n bigint; composite text;
 completed public.s3_upload_results;
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'Result custody cannot be deleted' USING ERRCODE='23514'; END IF;
 IF TG_OP='UPDATE' AND (to_jsonb(NEW)-ARRAY['response','response_xid']) IS DISTINCT FROM
   (to_jsonb(OLD)-ARRAY['response','response_xid']) THEN
   RAISE EXCEPTION 'Result intent immutable' USING ERRCODE='23514';
 END IF;
 IF TG_OP='UPDATE' AND NEW.response_xid IS DISTINCT FROM OLD.response_xid THEN
   RAISE EXCEPTION 'Result marker server owned' USING ERRCODE='23514';
 END IF;
 SELECT * INTO pub FROM public.s3_publications WHERE id=NEW.publication_id AND org_id=NEW.org_id;
 SELECT * INTO b FROM public.backups WHERE id=pub.backup_id AND org_id=NEW.org_id;
 IF b.id IS NULL OR current_setting('app.current_org',true) IS DISTINCT FROM NEW.org_id THEN
   RAISE EXCEPTION 'Result owner unavailable' USING ERRCODE='23514';
 END IF;
"""
    + capacity.AUTHORITY.replace(
        "b.status IN ('pending','running')",
        "b.status IN ('pending','running','uploading')",
    )
    + """
 PERFORM 1 FROM public.backups WHERE id=b.id FOR UPDATE;
 PERFORM 1 FROM public.vms WHERE id=b.vm_id AND org_id=b.org_id FOR UPDATE;
 PERFORM 1 FROM public.agents WHERE id=pub.expected_plan->'transaction'->>'agent_id' AND org_id=b.org_id FOR UPDATE;
 PERFORM 1 FROM public.encryption_keys WHERE id=split_part(pub.expected_plan->'transaction'->'plan'->'encryption'->>'key_ref',':',2) AND org_id=b.org_id FOR UPDATE;
 SELECT * INTO pub FROM public.s3_publications WHERE id=NEW.publication_id AND org_id=NEW.org_id FOR UPDATE;
 k:='provider_'||NEW.operation; v:=NEW.intent;
"""
    + COMMON
    + create.KEY_IDENTITY
    + """
 IF NEW.operation NOT IN ('complete','head') OR pub.provider_control IS NOT NULL
   OR pub.receipt_verification_intent IS NOT NULL OR pub.finalize_intent IS NOT NULL OR pub.checkpoint_proof IS NOT NULL
   OR pub.wrapped_attempt_key IS NULL OR pub.wrapped_attempt_key_xid IS NULL
   OR pub.wrapped_attempt_key_xid=txid_current() OR plan->>'provider' IS DISTINCT FROM 'kubevirt' THEN
   RAISE EXCEPTION 'Result original custody unavailable' USING ERRCODE='23514';
 END IF;
 entry:=pub.provider_create->NEW.artifact_key;
 IF entry IS NULL OR jsonb_typeof(entry->'response') IS DISTINCT FROM 'object'
   OR (entry->>'xid')::bigint=txid_current()
   OR EXISTS(SELECT 1 FROM public.s3_publications WHERE id=pub.id AND xmin::text::bigint=mod(txid_current(),4294967296))
   OR EXISTS(SELECT 1 FROM jsonb_each(pub.provider_create) e WHERE e.value->'response'='null'::jsonb)
   OR EXISTS(SELECT 1 FROM public.s3_upload_parts WHERE publication_id=pub.id AND acknowledgment IS NULL) THEN
   RAISE EXCEPTION 'Result requires committed predecessor custody' USING ERRCODE='23514';
 END IF;
 SELECT a INTO artifact FROM jsonb_array_elements(plan->'artifacts') a WHERE a->>'key'=NEW.artifact_key;
 SELECT jsonb_agg(jsonb_build_object('number',number,'bytes',byte_count,'sha256',sha256,'etag',acknowledgment->>'etag') ORDER BY number),
   sum(byte_count),count(*),replace(encode(sha256(string_agg(decode(sha256,'hex'),''::bytea ORDER BY number)),'base64'),E'\n','')||'-'||count(*)
 INTO partset,total,n,composite FROM public.s3_upload_parts WHERE publication_id=pub.id AND artifact_key=NEW.artifact_key;
 IF artifact IS NULL OR n NOT BETWEEN 1 AND 10000 OR total NOT BETWEEN (artifact->>'ciphertext_min')::bigint AND (artifact->>'ciphertext_max')::bigint
   OR EXISTS(SELECT 1 FROM public.s3_upload_parts WHERE publication_id=pub.id AND artifact_key=NEW.artifact_key
     AND (acknowledgment_xid IS NULL OR acknowledgment_xid=txid_current())) THEN
   RAISE EXCEPTION 'Result committed part set invalid' USING ERRCODE='23514';
 END IF;
 SELECT * INTO completed FROM public.s3_upload_results WHERE publication_id=pub.id AND artifact_key=NEW.artifact_key AND operation='complete';
 IF NEW.operation='head' AND (completed.response IS NULL OR completed.response_xid IS NULL OR completed.response_xid=txid_current()) THEN
   RAISE EXCEPTION 'HEAD requires committed completion' USING ERRCODE='23514';
 END IF;
 expected:=expected||jsonb_build_object('artifact_key',NEW.artifact_key,'upload_id',entry->'response'->'upload_id',
   'create_response_sha256',encode(sha256(convert_to((entry->'response')::text,'UTF8')),'hex'),
   'wrapped_key_sha256',encode(sha256(convert_to(pub.wrapped_attempt_key::jsonb::text,'UTF8')),'hex'),
   'parts_sha256',encode(sha256(convert_to(partset::text,'UTF8')),'hex'),'part_count',n,'total_bytes',total,
   'composite_sha256',composite,'completion_sha256',CASE WHEN NEW.operation='head' THEN encode(sha256(convert_to(completed.response::text,'UTF8')),'hex') ELSE NULL END);
 IF v IS DISTINCT FROM expected OR octet_length(v::text)>8192 THEN
   RAISE EXCEPTION 'Result intent binding invalid' USING ERRCODE='23514';
 END IF;
"""
    + capacity.READ
    + """
 IF (policy->>'maintenance')::boolean THEN RAISE EXCEPTION 'Capacity maintenance' USING ERRCODE='23514'; END IF;
 IF TG_OP='INSERT' THEN
   IF NEW.id !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
     OR NEW.intent_xid IS NOT NULL OR NEW.response IS NOT NULL OR NEW.response_xid IS NOT NULL THEN
     RAISE EXCEPTION 'Result first admission only' USING ERRCODE='23514';
   END IF;
   IF EXISTS(SELECT 1 FROM public.s3_upload_results WHERE publication_id=pub.id AND response IS NULL) THEN
     RAISE EXCEPTION 'Result attempt effect-held' USING ERRCODE='23514';
   END IF;
"""
    + create.LIFETIME
    + """
   NEW.intent_xid:=txid_current();
 ELSIF NEW.response IS DISTINCT FROM OLD.response THEN
   IF OLD.response IS NOT NULL OR OLD.intent_xid IS NULL OR OLD.intent_xid=txid_current() THEN
     RAISE EXCEPTION 'Result requires committed intent' USING ERRCODE='23514';
   END IF;
   obj:=NEW.response;
   IF jsonb_typeof(obj) IS DISTINCT FROM 'object' OR octet_length(obj::text)>16384
     OR NOT obj ?& ARRAY['schema','kind','bucket','key','etag','version_id','checksum_algorithm','checksum_type','checksum_value','request_id','host_id','body_sha256','bytes','metadata']
     OR obj-ARRAY['schema','kind','bucket','key','etag','version_id','checksum_algorithm','checksum_type','checksum_value','request_id','host_id','body_sha256','bytes','metadata']<>'{}'::jsonb
     OR obj->'schema' IS DISTINCT FROM '1'::jsonb
     OR obj->>'kind' IS DISTINCT FROM NEW.operation
     OR obj->'bucket' IS DISTINCT FROM plan->'target'->'bucket'
     OR obj->>'key' IS DISTINCT FROM NEW.artifact_key
     OR jsonb_typeof(obj->'etag') IS DISTINCT FROM 'string' OR octet_length(obj->>'etag') NOT BETWEEN 3 AND 1024
     OR obj->>'etag' !~ '^"[^"[:cntrl:]]+"$'
     OR jsonb_typeof(obj->'body_sha256') IS DISTINCT FROM 'string' OR obj->>'body_sha256' !~ '^[0-9a-f]{64}$' THEN
     RAISE EXCEPTION 'Result response shape invalid' USING ERRCODE='23514';
   END IF;
   FOREACH field IN ARRAY ARRAY['version_id','request_id','host_id'] LOOP
     IF obj->field='null'::jsonb THEN CONTINUE; END IF;
     IF jsonb_typeof(obj->field) IS DISTINCT FROM 'string' OR octet_length(obj->>field) NOT BETWEEN 1 AND 1024 OR obj->>field ~ '[[:cntrl:]]' THEN
       RAISE EXCEPTION 'Result identifier invalid' USING ERRCODE='23514';
     END IF;
   END LOOP;
   IF NEW.operation='complete' THEN
     IF obj->'bytes' IS DISTINCT FROM 'null'::jsonb OR obj->'metadata' IS DISTINCT FROM 'null'::jsonb THEN
       RAISE EXCEPTION 'Completion is not verified HEAD' USING ERRCODE='23514';
     END IF;
     IF jsonb_build_array(obj->'checksum_algorithm',obj->'checksum_type',obj->'checksum_value')<>'[null,null,null]'::jsonb
       AND jsonb_build_array(obj->'checksum_algorithm',obj->'checksum_type',obj->'checksum_value') IS DISTINCT FROM jsonb_build_array('SHA256'::text,'COMPOSITE'::text,composite) THEN
       RAISE EXCEPTION 'Completion checksum invalid' USING ERRCODE='23514';
     END IF;
   ELSE
     IF obj->'etag' IS DISTINCT FROM completed.response->'etag' OR obj->'version_id' IS DISTINCT FROM completed.response->'version_id'
       OR obj->'bytes' IS DISTINCT FROM to_jsonb(total)
       OR obj->>'body_sha256' IS DISTINCT FROM encode(sha256(''::bytea),'hex')
       OR jsonb_build_array(obj->'checksum_algorithm',obj->'checksum_type',obj->'checksum_value') IS DISTINCT FROM jsonb_build_array('SHA256'::text,'COMPOSITE'::text,composite)
       OR obj->'metadata' IS DISTINCT FROM jsonb_build_object('vnbui-protocol','1','vnbui-org-id',pub.org_id,
         'vnbui-backup-id',pub.backup_id,'vnbui-reservation-id',pub.id,
         'vnbui-plan-sha256',doc->>'plan_sha256','vnbui-artifact-id',encode(sha256(convert_to((artifact->>'volume_id')||':'||(artifact->>'role'),'UTF8')),'hex')) THEN
       RAISE EXCEPTION 'HEAD exact integrity evidence invalid' USING ERRCODE='23514';
     END IF;
   END IF;
   NEW.response_xid:=txid_current();
 END IF;
 RETURN NEW;
END $$"""
)


def upgrade():
    op.create_table(
        "s3_upload_results",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column(
            "org_id", sa.String(), sa.ForeignKey("organizations.id"), nullable=False
        ),
        sa.Column("publication_id", sa.String(), nullable=False),
        sa.Column("artifact_key", sa.String(), nullable=False),
        sa.Column("operation", sa.String(), nullable=False),
        sa.Column("intent", JSONB(), nullable=False),
        sa.Column("intent_xid", sa.BigInteger()),
        sa.Column("response", JSONB()),
        sa.Column("response_xid", sa.BigInteger()),
        sa.ForeignKeyConstraint(
            ["org_id", "publication_id"],
            ["s3_publications.org_id", "s3_publications.id"],
            name="fk_upload_result_publication",
            ondelete="RESTRICT",
        ),
        sa.UniqueConstraint(
            "publication_id", "artifact_key", "operation", name="uq_upload_result"
        ),
        sa.CheckConstraint(
            "operation IN ('complete','head')", name="ck_upload_result_operation"
        ),
    )
    op.create_index("idx_s3_upload_results_org_id", "s3_upload_results", ["org_id"])
    op.execute("ALTER TABLE s3_upload_results ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE s3_upload_results FORCE ROW LEVEL SECURITY")
    op.execute(
        "CREATE POLICY tenant_isolation_s3_upload_results ON s3_upload_results USING (org_id=NULLIF(current_setting('app.current_org',true),'')) WITH CHECK (org_id=NULLIF(current_setting('app.current_org',true),''))"
    )
    op.execute("REVOKE ALL ON s3_upload_results FROM PUBLIC")
    for sql in (SQL, PART_SQL, PARENT_SQL):
        op.execute(sql)
    for function in (
        "vnbui_provider_result",
        "vnbui_provider_part",
        "vnbui_callback_intent",
    ):
        op.execute(f"REVOKE ALL ON FUNCTION {function}() FROM PUBLIC")
    op.execute(
        "CREATE TRIGGER provider_result BEFORE INSERT OR UPDATE OR DELETE ON s3_upload_results FOR EACH ROW EXECUTE FUNCTION vnbui_provider_result()"
    )
    op.execute(
        "CREATE TRIGGER audit_upload_result AFTER INSERT OR UPDATE ON s3_upload_results FOR EACH ROW EXECUTE FUNCTION audit_access()"
    )


def downgrade():
    raise RuntimeError("Provider result custody requires reviewed rollback")
