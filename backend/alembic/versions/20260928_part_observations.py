"""Unmounted ListParts observations; quotas are deliberately non-final."""

import importlib.util
from pathlib import Path
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = "part_observations"
down_revision = "provider_results"
branch_labels = None
depends_on = None
spec = importlib.util.spec_from_file_location(
    "result_predecessor", Path(__file__).with_name("20260928_provider_results.py")
)
previous = importlib.util.module_from_spec(spec)
spec.loader.exec_module(previous)
capacity = previous.capacity
create = previous.create

# Used independently by admission and each page, under publication serialization.
PART_SET = """SELECT encode(sha256(convert_to(COALESCE(jsonb_agg(jsonb_build_object(
 'id',id,'number',number,'bytes',byte_count,'sha256',sha256,'intent_xid',intent_xid,
 'signing_result',signing_result,'signing_xid',signing_xid,
 'acknowledgment',acknowledgment,'acknowledgment_xid',acknowledgment_xid) ORDER BY number),'[]'::jsonb)::text,'UTF8')),'hex')
 FROM public.s3_upload_parts WHERE publication_id=:publication AND artifact_key=:key"""

SQL = (
    """CREATE FUNCTION vnbui_part_observation() RETURNS trigger
LANGUAGE plpgsql VOLATILE SET search_path=pg_catalog,public AS $$
DECLARE
 pub public.s3_publications; b public.backups; o public.organizations; u public.users;
 s public.schedules; g public.scheduler_grants; c public.schedule_occurrences; q public.backup_queue;
 callback_agent public.agents; cert public.agent_certificates; keyrow public.encryption_keys;
 v jsonb; expected jsonb; doc jsonb; plan jsonb; obj jsonb; artifact jsonb; entry jsonb;
 k text; field text; cert_ids text[]; nowsec bigint; policy jsonb; previous_platform text;
 occupied bigint; same_vm bigint; part_hash text; actual_part_hash text; profile jsonb; profile_hash text;
 scan public.s3_part_observation_scans; prior public.s3_part_observation_pages;
 localpart public.s3_upload_parts; item jsonb; classification text; last_number integer;
 tenant_count bigint; attempt_count bigint; tenant_bytes bigint; attempt_bytes bigint; last_scan bigint;
BEGIN
 IF TG_OP='DELETE' OR (TG_TABLE_NAME='s3_part_observation_scans' AND TG_OP<>'INSERT') THEN
   RAISE EXCEPTION 'Observation custody immutable' USING ERRCODE='23514';
 END IF;
 IF TG_OP='UPDATE' THEN
   IF (to_jsonb(NEW)-ARRAY['observation','observation_xid','retained_bytes']) IS DISTINCT FROM
      (to_jsonb(OLD)-ARRAY['observation','observation_xid','retained_bytes'])
      OR NEW.observation_xid IS DISTINCT FROM OLD.observation_xid
      OR NEW.retained_bytes IS DISTINCT FROM OLD.retained_bytes THEN
     RAISE EXCEPTION 'Observation intent and markers immutable' USING ERRCODE='23514';
   END IF;
 END IF;
 SELECT * INTO pub FROM public.s3_publications WHERE id=NEW.publication_id AND org_id=NEW.org_id;
 SELECT * INTO b FROM public.backups WHERE id=pub.backup_id AND org_id=NEW.org_id;
 IF pub.id IS NULL OR b.id IS NULL OR current_setting('app.current_org',true) IS DISTINCT FROM NEW.org_id THEN
   RAISE EXCEPTION 'Observation owner unavailable' USING ERRCODE='23514';
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
 v:=NEW.intent;
 k:=CASE WHEN TG_TABLE_NAME='s3_part_observation_scans' THEN 'provider_listparts_scan' ELSE 'provider_listparts_page' END;
"""
    + previous.COMMON
    + create.KEY_IDENTITY
    + """
 IF pub.provider_control IS NOT NULL OR pub.receipt_verification_intent IS NOT NULL
   OR pub.finalize_intent IS NOT NULL OR pub.checkpoint_proof IS NOT NULL
   OR pub.wrapped_attempt_key IS NULL OR pub.wrapped_attempt_key_xid IS NULL
   OR pub.wrapped_attempt_key_xid=txid_current() OR plan->>'provider' IS DISTINCT FROM 'kubevirt' THEN
   RAISE EXCEPTION 'Observation original custody unavailable' USING ERRCODE='23514';
 END IF;
 entry:=pub.provider_create->NEW.artifact_key;
 SELECT a INTO artifact FROM jsonb_array_elements(plan->'artifacts') a WHERE a->>'key'=NEW.artifact_key;
 IF artifact IS NULL OR jsonb_typeof(entry->'response') IS DISTINCT FROM 'object'
   OR (entry->>'xid')::bigint=txid_current()
   OR EXISTS(SELECT 1 FROM public.s3_publications WHERE id=pub.id AND xmin::text::bigint=mod(txid_current(),4294967296)) THEN
   RAISE EXCEPTION 'Observation requires committed exact create' USING ERRCODE='23514';
 END IF;
"""
    + PART_SET.replace(":publication", "pub.id")
    .replace(":key", "NEW.artifact_key")
    .replace(
        " FROM public.s3_upload_parts", " INTO part_hash FROM public.s3_upload_parts"
    )
    + ";\n"
    + capacity.READ
    + """
 actual_part_hash:=part_hash;
 IF TG_OP='UPDATE' THEN part_hash:=OLD.intent->>'parts_sha256'; END IF;
 IF (policy->>'maintenance')::boolean THEN RAISE EXCEPTION 'Capacity maintenance' USING ERRCODE='23514'; END IF;
 -- Fixed installation read only after tenant-visible owner validation. Restore
 -- context on success and exception; never a function-entry platform SET.
 previous_platform:=current_setting('app.platform_admin',true);
 BEGIN
   PERFORM set_config('app.platform_admin','true',true);
   SELECT value::jsonb INTO profile FROM public.settings_v3 WHERE key='storage.s3.listparts_profile';
   PERFORM set_config('app.platform_admin',COALESCE(previous_platform,''),true);
 EXCEPTION WHEN OTHERS THEN
   PERFORM set_config('app.platform_admin',COALESCE(previous_platform,''),true); RAISE;
 END;
 IF profile IS NULL OR profile IS DISTINCT FROM jsonb_build_object('schema',1,'profile','listparts-sha256-composite/1',
   'target_sha256',expected->'target_sha256','evidence_sha256',profile->'evidence_sha256','limits',profile->'limits')
   OR jsonb_typeof(profile->'evidence_sha256') IS DISTINCT FROM 'string'
   OR profile->>'evidence_sha256' !~ '^[0-9a-f]{64}$' THEN
   RAISE EXCEPTION 'Verified ListParts profile required' USING ERRCODE='23514';
 END IF;
 IF jsonb_typeof(profile->'limits') IS DISTINCT FROM 'object'
   OR profile->'limits' IS DISTINCT FROM jsonb_build_object('attempt_scans',profile->'limits'->'attempt_scans','tenant_scans',profile->'limits'->'tenant_scans',
       'attempt_bytes',profile->'limits'->'attempt_bytes','tenant_bytes',profile->'limits'->'tenant_bytes') THEN
   RAISE EXCEPTION 'Invalid ListParts limits' USING ERRCODE='23514'; END IF;
 FOREACH field IN ARRAY ARRAY['attempt_scans','tenant_scans','attempt_bytes','tenant_bytes'] LOOP
   IF jsonb_typeof(profile->'limits'->field) IS DISTINCT FROM 'number' OR profile->'limits'->>field !~ '^[0-9]{1,10}$'
     OR (profile->'limits'->>field)::bigint NOT BETWEEN (CASE WHEN field LIKE '%bytes' THEN 8421376 ELSE 1 END)
       AND (CASE field WHEN 'attempt_scans' THEN 4 WHEN 'tenant_scans' THEN 64 WHEN 'attempt_bytes' THEN 1073741824 ELSE 4294967296 END) THEN
     RAISE EXCEPTION 'Invalid ListParts limits' USING ERRCODE='23514'; END IF;
 END LOOP;
 profile_hash:=encode(sha256(convert_to(profile::text,'UTF8')),'hex');
 expected:=expected||jsonb_build_object('artifact_key',NEW.artifact_key,'upload_id',entry->'response'->'upload_id',
   'create_response_sha256',encode(sha256(convert_to((entry->'response')::text,'UTF8')),'hex'),
   'wrapped_key_sha256',encode(sha256(convert_to(pub.wrapped_attempt_key::jsonb::text,'UTF8')),'hex'),
   'parts_sha256',part_hash,'profile_sha256',profile_hash);
 IF TG_TABLE_NAME='s3_part_observation_pages' THEN
   SELECT * INTO scan FROM public.s3_part_observation_scans WHERE id=NEW.scan_id AND org_id=NEW.org_id;
   IF scan.id IS NULL OR scan.intent_xid IS NULL OR scan.intent_xid=txid_current()
     OR scan.publication_id IS DISTINCT FROM NEW.publication_id OR scan.artifact_key IS DISTINCT FROM NEW.artifact_key
     OR scan.intent->>'parts_sha256' IS DISTINCT FROM part_hash
     OR scan.intent->>'profile_sha256' IS DISTINCT FROM profile_hash THEN
     RAISE EXCEPTION 'Observation scan binding changed' USING ERRCODE='23514';
   END IF;
   SELECT * INTO prior FROM public.s3_part_observation_pages WHERE scan_id=scan.id AND number=NEW.number-1;
   IF NEW.number=1 THEN
     IF NEW.marker<>0 THEN RAISE EXCEPTION 'First observation marker invalid' USING ERRCODE='23514'; END IF;
   ELSIF prior.id IS NULL OR prior.observation IS NULL OR prior.observation_xid IS NULL OR prior.observation_xid=txid_current()
     OR prior.observation->>'outcome' IS DISTINCT FROM 'page'
     OR prior.observation->'truncated' IS DISTINCT FROM 'true'::jsonb
     OR prior.observation->'conflict' IS DISTINCT FROM 'false'::jsonb
     OR prior.observation->'comparison_stale' IS DISTINCT FROM 'false'::jsonb
     OR prior.observation->'next_marker' IS DISTINCT FROM to_jsonb(NEW.marker) THEN
     RAISE EXCEPTION 'Committed observation predecessor required' USING ERRCODE='23514';
   END IF;
   expected:=expected||jsonb_build_object('scan_id',scan.id,'number',NEW.number,'marker',NEW.marker,
     'previous_sha256',CASE WHEN prior.id IS NULL THEN NULL ELSE encode(sha256(convert_to(prior.observation::text,'UTF8')),'hex') END);
 END IF;
 IF v IS DISTINCT FROM expected OR octet_length(v::text)>8192
   OR NEW.id !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$' THEN
   RAISE EXCEPTION 'Observation intent binding invalid' USING ERRCODE='23514';
 END IF;
 IF TG_OP='INSERT' THEN
   IF NEW.intent_xid IS NOT NULL THEN RAISE EXCEPTION 'Observation marker server owned' USING ERRCODE='23514'; END IF;
"""
    + create.LIFETIME
    + """
   -- The locked organization serializes these fresh READ COMMITTED statements.
   -- Temporary lifetime quotas: never advertised as mounted recovery liveness.
   SELECT count(*),count(*) FILTER(WHERE publication_id=pub.id),max(admitted_at)
     INTO tenant_count,attempt_count,last_scan FROM public.s3_part_observation_scans WHERE org_id=NEW.org_id;
   SELECT COALESCE(sum(retained_bytes),0),COALESCE(sum(retained_bytes) FILTER(WHERE publication_id=pub.id),0)
     INTO tenant_bytes,attempt_bytes FROM public.s3_part_observation_pages WHERE org_id=NEW.org_id;
   tenant_bytes:=tenant_bytes+tenant_count*32768; attempt_bytes:=attempt_bytes+attempt_count*32768;
   IF TG_TABLE_NAME='s3_part_observation_scans' THEN
     IF NEW.admitted_at IS NOT NULL THEN RAISE EXCEPTION 'Scan time server owned' USING ERRCODE='23514'; END IF;
     NEW.admitted_at:=nowsec;
     IF tenant_count>=(profile->'limits'->>'tenant_scans')::bigint OR attempt_count>=(profile->'limits'->>'attempt_scans')::bigint OR last_scan>nowsec-60
       OR tenant_bytes+32768>(profile->'limits'->>'tenant_bytes')::bigint OR attempt_bytes+32768>(profile->'limits'->>'attempt_bytes')::bigint THEN
       RAISE LOG 'ListParts quota refusal org=% publication=% role=%',NEW.org_id,pub.id,current_user;
       RAISE EXCEPTION 'Observation quota exhausted' USING ERRCODE='23514';
     END IF;
   ELSE
     IF NEW.observation IS NOT NULL OR NEW.observation_xid IS NOT NULL OR NEW.retained_bytes IS DISTINCT FROM 8388608 THEN
       RAISE EXCEPTION 'Observation first intent only' USING ERRCODE='23514';
     END IF;
     IF tenant_bytes+8388608>(profile->'limits'->>'tenant_bytes')::bigint OR attempt_bytes+8388608>(profile->'limits'->>'attempt_bytes')::bigint THEN
       RAISE LOG 'ListParts byte quota refusal org=% publication=% role=%',NEW.org_id,pub.id,current_user;
       RAISE EXCEPTION 'Observation quota exhausted' USING ERRCODE='23514';
     END IF;
   END IF;
   NEW.intent_xid:=txid_current();
 ELSE
   IF NEW.observation IS NOT DISTINCT FROM OLD.observation THEN RAISE EXCEPTION 'Observation no-op mutation refused' USING ERRCODE='23514'; END IF;
   IF OLD.observation IS NOT NULL OR OLD.intent_xid IS NULL OR OLD.intent_xid=txid_current() THEN
     RAISE EXCEPTION 'Observation requires committed intent' USING ERRCODE='23514';
   END IF;
   obj:=NEW.observation;
   IF jsonb_typeof(obj) IS DISTINCT FROM 'object' OR octet_length(obj::text)>2097152
     OR NOT obj ?& ARRAY['schema','outcome','status','code','bucket','key','upload_id','marker','truncated','next_marker','parts','conflict','request_id','host_id','body_sha256','comparison_stale','observed_at','checksum_algorithm','checksum_type']
     OR obj-ARRAY['schema','outcome','status','code','bucket','key','upload_id','marker','truncated','next_marker','parts','conflict','request_id','host_id','body_sha256','comparison_stale','observed_at','checksum_algorithm','checksum_type']<>'{}'::jsonb
     OR obj->'schema' IS DISTINCT FROM '1'::jsonb OR obj->'bucket' IS DISTINCT FROM plan->'target'->'bucket'
     OR obj->>'key' IS DISTINCT FROM NEW.artifact_key OR obj->'upload_id' IS DISTINCT FROM v->'upload_id'
     OR obj->'marker' IS DISTINCT FROM to_jsonb(NEW.marker)
     OR jsonb_typeof(obj->'body_sha256') IS DISTINCT FROM 'string' OR obj->>'body_sha256' !~ '^[0-9a-f]{64}$'
     OR jsonb_typeof(obj->'parts') IS DISTINCT FROM 'array' OR jsonb_array_length(obj->'parts')>1000
     OR jsonb_typeof(obj->'conflict') IS DISTINCT FROM 'boolean'
     OR obj->'comparison_stale' IS DISTINCT FROM to_jsonb(actual_part_hash IS DISTINCT FROM part_hash)
     OR jsonb_typeof(obj->'observed_at') IS DISTINCT FROM 'number' OR obj->>'observed_at' !~ '^[0-9]{1,12}$'
     OR (obj->>'observed_at')::bigint NOT BETWEEN (v->>'created_at')::bigint AND floor(extract(epoch FROM clock_timestamp()))::bigint+5 THEN
     RAISE EXCEPTION 'Observation shape invalid' USING ERRCODE='23514';
   END IF;
   FOREACH field IN ARRAY ARRAY['request_id','host_id'] LOOP
     IF obj->field='null'::jsonb THEN CONTINUE; END IF;
     IF jsonb_typeof(obj->field) IS DISTINCT FROM 'string' OR octet_length(obj->>field) NOT BETWEEN 1 AND 1024
       OR obj->>field ~ '[[:cntrl:]]' THEN RAISE EXCEPTION 'Observation identifier invalid' USING ERRCODE='23514'; END IF;
   END LOOP;
   IF obj->>'outcome'='page' THEN
     IF obj->>'checksum_algorithm' IS DISTINCT FROM 'SHA256' OR obj->>'checksum_type' IS DISTINCT FROM 'COMPOSITE'
       OR obj->'status' IS DISTINCT FROM '200'::jsonb OR obj->'code' IS DISTINCT FROM 'null'::jsonb
       OR jsonb_typeof(obj->'truncated') IS DISTINCT FROM 'boolean' THEN
       RAISE EXCEPTION 'Observation page invalid' USING ERRCODE='23514'; END IF;
     last_number:=NEW.marker;
     FOR item IN SELECT * FROM jsonb_array_elements(obj->'parts') LOOP
       IF item IS DISTINCT FROM jsonb_build_object('number',item->'number','bytes',item->'bytes','etag',item->'etag','sha256',item->'sha256','classification',item->'classification')
         OR jsonb_typeof(item->'number') IS DISTINCT FROM 'number' OR item->>'number' !~ '^[0-9]{1,5}$'
         OR jsonb_typeof(item->'bytes') IS DISTINCT FROM 'number' OR item->>'bytes' !~ '^[0-9]{1,12}$'
         OR (item->>'number')::integer NOT BETWEEN last_number+1 AND 10000
         OR (item->>'bytes')::bigint NOT BETWEEN 0 AND 5368709120
         OR jsonb_typeof(item->'sha256') IS DISTINCT FROM 'string' OR item->>'sha256' !~ '^[0-9a-f]{64}$'
         OR jsonb_typeof(item->'etag') IS DISTINCT FROM 'string' OR octet_length(item->>'etag') NOT BETWEEN 3 AND 1024
         OR item->>'etag' !~ '^"[^"[:cntrl:]]+"$' THEN
         RAISE EXCEPTION 'Observation tuple invalid' USING ERRCODE='23514'; END IF;
       last_number:=(item->>'number')::integer;
       SELECT * INTO localpart FROM public.s3_upload_parts WHERE publication_id=pub.id AND artifact_key=NEW.artifact_key AND number=last_number;
       classification:=CASE WHEN actual_part_hash IS DISTINCT FROM part_hash THEN 'unclassified' ELSE 'conflict' END;
       IF actual_part_hash IS NOT DISTINCT FROM part_hash AND localpart.id IS NOT NULL AND item->'bytes'=to_jsonb(localpart.byte_count) AND item->>'sha256'=localpart.sha256 THEN
         IF localpart.acknowledgment IS NULL THEN classification:='unacknowledged_intent_match';
         ELSIF item->>'etag'='"'||(localpart.acknowledgment->>'etag')||'"' THEN classification:='committed_ack_match'; END IF;
       END IF;
       IF item->>'classification' IS DISTINCT FROM classification THEN
         RAISE EXCEPTION 'Observation classification invalid' USING ERRCODE='23514'; END IF;
     END LOOP;
     IF obj->'conflict' IS DISTINCT FROM to_jsonb(EXISTS(SELECT 1 FROM jsonb_array_elements(obj->'parts') i WHERE i->>'classification'='conflict'))
       OR (obj->'truncated'='true'::jsonb AND (jsonb_array_length(obj->'parts')=0 OR obj->'next_marker' IS DISTINCT FROM to_jsonb(last_number)))
       OR (obj->'truncated'='false'::jsonb AND obj->'next_marker' IS DISTINCT FROM 'null'::jsonb) THEN
       RAISE EXCEPTION 'Observation pagination invalid' USING ERRCODE='23514'; END IF;
   ELSIF obj->>'outcome' IN ('no_such_upload','provider_refusal') THEN
     IF obj->'checksum_algorithm' IS DISTINCT FROM 'null'::jsonb OR obj->'checksum_type' IS DISTINCT FROM 'null'::jsonb
       OR obj->'parts'<>'[]'::jsonb OR obj->'conflict'<>'false'::jsonb OR obj->'truncated'<>'false'::jsonb OR obj->'next_marker'<>'null'::jsonb
       OR jsonb_typeof(obj->'status') IS DISTINCT FROM 'number' OR obj->>'status' !~ '^[45][0-9]{2}$'
       OR jsonb_typeof(obj->'code') IS DISTINCT FROM 'string' OR obj->>'code' !~ '^[A-Za-z][A-Za-z0-9]{0,127}$'
       OR ((obj->>'outcome'='no_such_upload') IS DISTINCT FROM (obj->'status'='404'::jsonb AND obj->>'code'='NoSuchUpload')) THEN
       RAISE EXCEPTION 'Observation refusal invalid' USING ERRCODE='23514'; END IF;
   ELSE RAISE EXCEPTION 'Observation outcome invalid' USING ERRCODE='23514'; END IF;
   NEW.observation_xid:=txid_current();
   -- Conservative encoded custody multiplier and metadata-only audit/row allowance.
   NEW.retained_bytes:=16384+3*octet_length(NEW.intent::text)+3*octet_length(obj::text);
   IF NEW.retained_bytes>OLD.retained_bytes THEN RAISE EXCEPTION 'Observation reservation exceeded' USING ERRCODE='23514'; END IF;
 END IF;
 RETURN NEW;
END $$"""
)


def upgrade():
    for table, page in (
        ("s3_part_observation_scans", False),
        ("s3_part_observation_pages", True),
    ):
        columns = [
            sa.Column("id", sa.String(), primary_key=True),
            sa.Column(
                "org_id", sa.String(), sa.ForeignKey("organizations.id"), nullable=False
            ),
            sa.Column("publication_id", sa.String(), nullable=False),
            sa.Column("artifact_key", sa.String(), nullable=False),
            sa.Column("intent", JSONB(), nullable=False),
            sa.Column("intent_xid", sa.BigInteger()),
            sa.ForeignKeyConstraint(
                ["org_id", "publication_id"],
                ["s3_publications.org_id", "s3_publications.id"],
                name="fk_part_page_publication" if page else "fk_part_scan_publication",
                ondelete="RESTRICT",
            ),
        ]
        if page:
            columns += [
                sa.Column("scan_id", sa.String(), nullable=False),
                sa.Column("number", sa.Integer(), nullable=False),
                sa.Column("marker", sa.Integer(), nullable=False),
                sa.Column("observation", JSONB()),
                sa.Column("observation_xid", sa.BigInteger()),
                sa.Column("retained_bytes", sa.BigInteger(), nullable=False),
                sa.ForeignKeyConstraint(
                    ["org_id", "scan_id"],
                    [
                        "s3_part_observation_scans.org_id",
                        "s3_part_observation_scans.id",
                    ],
                    name="fk_part_page_scan",
                    ondelete="RESTRICT",
                ),
                sa.UniqueConstraint("scan_id", "number", name="uq_part_page_number"),
                sa.UniqueConstraint("scan_id", "marker", name="uq_part_page_marker"),
                sa.CheckConstraint(
                    "number BETWEEN 1 AND 10001 AND marker BETWEEN 0 AND 10000",
                    name="ck_part_page_bounds",
                ),
            ]
        else:
            columns += [
                sa.Column("admitted_at", sa.BigInteger(), nullable=False),
                sa.UniqueConstraint("org_id", "id", name="uq_part_scan_org_id"),
            ]
        op.create_table(table, *columns)
        op.create_index("idx_" + table + "_org_id", table, ["org_id"])
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
        op.execute(
            f"CREATE POLICY tenant_isolation_{table} ON {table} USING (org_id=NULLIF(current_setting('app.current_org',true),'')) WITH CHECK (org_id=NULLIF(current_setting('app.current_org',true),''))"
        )
        op.execute(f"REVOKE ALL ON {table} FROM PUBLIC")
    op.execute(SQL)
    op.execute("REVOKE ALL ON FUNCTION vnbui_part_observation() FROM PUBLIC")
    for table in ("s3_part_observation_scans", "s3_part_observation_pages"):
        op.execute(
            f"CREATE TRIGGER part_observation BEFORE INSERT OR UPDATE OR DELETE ON {table} FOR EACH ROW EXECUTE FUNCTION vnbui_part_observation()"
        )
        op.execute(
            f"CREATE TRIGGER audit_part_observation AFTER INSERT OR UPDATE ON {table} FOR EACH ROW EXECUTE FUNCTION audit_access()"
        )


def downgrade():
    raise RuntimeError("Immutable observation custody requires reviewed disposition")
