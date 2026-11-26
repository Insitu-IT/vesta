"""Unmounted immutable evidence, explicit qualification and separate revocation."""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = "capability_evidence"
down_revision = "result_profiles"
branch_labels = None
depends_on = None

OPERATIONS = "'create','part_sign','complete','head','list_parts','normal_publication','uncertain_recovery'"

REGISTRY = """CREATE FUNCTION vnbui_capability_registry() RETURNS trigger
LANGUAGE plpgsql VOLATILE SET search_path=pg_catalog,public AS $$
DECLARE f jsonb; item jsonb; field text; ev public.storage_capability_evidence;
BEGIN
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'Capability custody immutable' USING ERRCODE='23514'; END IF;
 IF TG_TABLE_NAME='storage_capability_evidence' THEN
   f:=NEW.facts;
   IF NEW.id !~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
     OR jsonb_typeof(f) IS DISTINCT FROM 'object' OR octet_length(f::text)>65536
     OR NOT f ?& ARRAY['schema','target','profile','adapter','wire','provider','observed_utc','requalification','capabilities','artifacts']
     OR f-ARRAY['schema','target','profile','adapter','wire','provider','observed_utc','requalification','capabilities','artifacts']<>'{}'::jsonb
     OR f->'schema' IS DISTINCT FROM '1'::jsonb
     OR f->>'adapter' IS DISTINCT FROM 'vnbui-callback-provider/1'
     OR f->>'wire' IS DISTINCT FROM 'vnbui-storage-transaction/1'
     OR (f->>'profile' IN ('checksum-enforced/1','consumer-verified/1','db-rooted-consumer-verified/1')) IS NOT TRUE
     OR NEW.sha256 IS DISTINCT FROM encode(sha256(convert_to(f::text,'UTF8')),'hex') THEN
     RAISE EXCEPTION 'Capability facts invalid' USING ERRCODE='23514';
   END IF;
   IF jsonb_typeof(f->'target') IS DISTINCT FROM 'object'
     OR NOT (f->'target') ?& ARRAY['endpoint','bucket','region','configuration_prefix']
     OR (f->'target')-ARRAY['endpoint','bucket','region','configuration_prefix']<>'{}'::jsonb THEN
     RAISE EXCEPTION 'Capability target invalid' USING ERRCODE='23514'; END IF;
   FOREACH field IN ARRAY ARRAY['endpoint','bucket','region','configuration_prefix'] LOOP
     IF jsonb_typeof(f->'target'->field) IS DISTINCT FROM 'string' OR octet_length(f->'target'->>field)>1024 THEN
       RAISE EXCEPTION 'Capability target invalid' USING ERRCODE='23514'; END IF;
   END LOOP;
   FOREACH field IN ARRAY ARRAY['provider','observed_utc','requalification'] LOOP
     IF jsonb_typeof(f->field) IS DISTINCT FROM 'string' OR octet_length(f->>field) NOT BETWEEN 1 AND 2048 THEN
       RAISE EXCEPTION 'Capability provenance invalid' USING ERRCODE='23514'; END IF;
   END LOOP;
   IF jsonb_typeof(f->'artifacts') IS DISTINCT FROM 'array' OR jsonb_array_length(f->'artifacts') NOT BETWEEN 1 AND 32 THEN
     RAISE EXCEPTION 'Capability artifacts invalid' USING ERRCODE='23514'; END IF;
   FOR item IN SELECT * FROM jsonb_array_elements(f->'artifacts') LOOP
     IF jsonb_typeof(item) IS DISTINCT FROM 'string' OR item#>>'{}' !~ '^[0-9a-f]{64}$' THEN
       RAISE EXCEPTION 'Capability artifact digest invalid' USING ERRCODE='23514'; END IF;
   END LOOP;
   IF jsonb_typeof(f->'capabilities') IS DISTINCT FROM 'object'
     OR NOT (f->'capabilities') ?& ARRAY['create','part_sign','complete','head','list_parts','normal_publication','uncertain_recovery','checksum','complete_precondition']
     OR (f->'capabilities')-ARRAY['create','part_sign','complete','head','list_parts','normal_publication','uncertain_recovery','checksum','complete_precondition']<>'{}'::jsonb THEN
     RAISE EXCEPTION 'Capability map invalid' USING ERRCODE='23514'; END IF;
   FOR field,item IN SELECT * FROM jsonb_each(f->'capabilities') LOOP
     IF (item#>>'{}' IN ('enforced','ignored','unsupported','unestablished')) IS NOT TRUE THEN
       RAISE EXCEPTION 'Capability status invalid' USING ERRCODE='23514'; END IF;
   END LOOP;
 ELSE
   SELECT * INTO ev FROM public.storage_capability_evidence WHERE id=NEW.evidence_id AND org_id=NEW.org_id;
   IF ev.id IS NULL THEN RAISE EXCEPTION 'Capability owner unavailable' USING ERRCODE='23514'; END IF;
   PERFORM pg_advisory_xact_lock(1447977558,hashtext(NEW.evidence_id));
   IF TG_TABLE_NAME='storage_capability_qualifications' THEN
     IF (NEW.operation IN (OPERATIONS)) IS NOT TRUE
       OR ev.facts->'capabilities'->>NEW.operation IS DISTINCT FROM 'enforced'
       OR (ev.facts->>'profile'='checksum-enforced/1' AND NEW.operation IN ('complete','head') AND ev.facts->'capabilities'->>'checksum' IS DISTINCT FROM 'enforced')
       OR jsonb_typeof(NEW.approval) IS DISTINCT FROM 'object'
       OR NOT NEW.approval ?& ARRAY['reviewer','reference','approved_utc','evidence_sha256']
       OR NEW.approval-ARRAY['reviewer','reference','approved_utc','evidence_sha256']<>'{}'::jsonb
       OR NEW.approval->>'evidence_sha256' IS DISTINCT FROM ev.sha256 THEN
       RAISE EXCEPTION 'Explicit operation qualification invalid' USING ERRCODE='23514'; END IF;
     FOREACH field IN ARRAY ARRAY['reviewer','reference','approved_utc'] LOOP
       IF jsonb_typeof(NEW.approval->field) IS DISTINCT FROM 'string' OR octet_length(NEW.approval->>field) NOT BETWEEN 1 AND 2048 THEN
         RAISE EXCEPTION 'Approval provenance invalid' USING ERRCODE='23514'; END IF;
     END LOOP;
   ELSIF (NEW.operation IN ('all',OPERATIONS)) IS NOT TRUE OR octet_length(NEW.reason) NOT BETWEEN 1 AND 2048 THEN
     RAISE EXCEPTION 'Revocation invalid' USING ERRCODE='23514';
   END IF;
 END IF;
 RETURN NEW;
END $$""".replace("OPERATIONS", OPERATIONS)

GUARD = """CREATE FUNCTION vnbui_capability_effect() RETURNS trigger
LANGUAGE plpgsql VOLATILE SET search_path=pg_catalog,public AS $$
DECLARE pub public.s3_publications; doc jsonb; plan jsonb; ref jsonb;
 ev public.storage_capability_evidence; operations text[]:='{}'; selected_operation text; entry record;
BEGIN
 IF TG_TABLE_NAME='s3_publications' THEN
   pub:=NEW;
   IF TG_OP='UPDATE' AND NEW.provider_create IS DISTINCT FROM OLD.provider_create THEN
     FOR entry IN SELECT * FROM jsonb_each(NEW.provider_create) LOOP
       IF NOT COALESCE(OLD.provider_create,'{}'::jsonb) ? entry.key THEN operations:=array_append(operations,'create'); END IF;
     END LOOP;
   END IF;
 ELSE
   SELECT * INTO pub FROM public.s3_publications WHERE id=NEW.publication_id AND org_id=NEW.org_id;
   IF TG_OP='INSERT' THEN
     IF TG_TABLE_NAME='s3_upload_parts' THEN operations:=ARRAY['part_sign'];
     ELSIF TG_TABLE_NAME IN ('s3_part_observation_scans','s3_part_observation_pages') THEN operations:=ARRAY['list_parts'];
     ELSE operations:=ARRAY[NEW.operation]; END IF;
   END IF;
 END IF;
 doc:=pub.expected_plan::jsonb->'transaction'; plan:=doc->'plan'; ref:=plan->'capability_evidence';
 -- Historical custody is not reinterpreted; only new IO requires the new plan.
 IF ref IS NULL AND cardinality(operations)=0 THEN RETURN NEW; END IF;
 IF pub.org_id IS DISTINCT FROM NULLIF(current_setting('app.current_org',true),'')
   OR jsonb_typeof(ref) IS DISTINCT FROM 'object' OR plan->'evidence_schema' IS DISTINCT FROM '1'::jsonb
   OR NOT ref ?& ARRAY['id','revision','sha256','adapter','wire'] OR ref-ARRAY['id','revision','sha256','adapter','wire']<>'{}'::jsonb THEN
   RAISE EXCEPTION 'Committed capability evidence required' USING ERRCODE='23514'; END IF;
 SELECT * INTO ev FROM public.storage_capability_evidence WHERE id=ref->>'id' AND org_id=pub.org_id;
 IF ev.id IS NULL OR ref IS DISTINCT FROM jsonb_build_object('id',ev.id,'revision',ev.revision,'sha256',ev.sha256,
     'adapter',ev.facts->'adapter','wire',ev.facts->'wire')
   OR ev.facts->'profile' IS DISTINCT FROM plan->'capability_profile'
   OR ev.facts->'target' IS DISTINCT FROM plan->'target'
   OR pub.endpoint IS DISTINCT FROM plan->'target'->>'endpoint' OR pub.bucket IS DISTINCT FROM plan->'target'->>'bucket' THEN
   RAISE EXCEPTION 'Capability evidence binding differs' USING ERRCODE='23514'; END IF;
 IF TG_TABLE_NAME='s3_publications' AND TG_OP='UPDATE' THEN
   IF jsonb_build_array(NEW.provider_control,NEW.prepared_receipt,NEW.finalize_intent,NEW.checkpoint_proof,NEW.state)
      IS DISTINCT FROM jsonb_build_array(OLD.provider_control,OLD.prepared_receipt,OLD.finalize_intent,OLD.checkpoint_proof,OLD.state) THEN
     RAISE EXCEPTION 'Qualified publication remains dormant' USING ERRCODE='23514'; END IF;
 END IF;
 IF cardinality(operations)>0 THEN
   IF current_setting('transaction_isolation')<>'read committed' THEN
     RAISE EXCEPTION 'Capability admission requires READ COMMITTED' USING ERRCODE='23514'; END IF;
   PERFORM pg_advisory_xact_lock(1447977558,hashtext(ev.id));
   FOREACH selected_operation IN ARRAY operations LOOP
     IF NOT EXISTS(SELECT 1 FROM public.storage_capability_qualifications q WHERE q.org_id=pub.org_id AND q.evidence_id=ev.id AND q.operation=selected_operation)
       OR EXISTS(SELECT 1 FROM public.storage_capability_revocations r WHERE r.org_id=pub.org_id AND r.evidence_id=ev.id AND r.operation IN (selected_operation,'all')) THEN
       RAISE EXCEPTION 'Capability operation unqualified or revoked' USING ERRCODE='23514'; END IF;
   END LOOP;
 END IF;
 RETURN NEW;
END $$"""


def upgrade():
    op.create_table(
        "storage_capability_evidence",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column(
            "org_id", sa.String(), sa.ForeignKey("organizations.id"), nullable=False
        ),
        sa.Column("revision", sa.BigInteger(), nullable=False),
        sa.Column("facts", JSONB(), nullable=False),
        sa.Column("sha256", sa.String(), nullable=False),
        sa.UniqueConstraint("org_id", "id", name="uq_storage_evidence_org"),
        sa.CheckConstraint("revision > 0", name="ck_storage_evidence_revision"),
    )
    for suffix, field, kind in [
        ("qualifications", "approval", JSONB()),
        ("revocations", "reason", sa.String()),
    ]:
        op.create_table(
            "storage_capability_" + suffix,
            sa.Column(
                "org_id", sa.String(), sa.ForeignKey("organizations.id"), nullable=False
            ),
            sa.Column("evidence_id", sa.String(), primary_key=True),
            sa.Column("operation", sa.String(), primary_key=True),
            sa.Column(field, kind, nullable=False),
            sa.ForeignKeyConstraint(
                ["org_id", "evidence_id"],
                [
                    "storage_capability_evidence.org_id",
                    "storage_capability_evidence.id",
                ],
                name="fk_storage_"
                + ("qualification" if suffix == "qualifications" else "revocation")
                + "_evidence",
                ondelete="RESTRICT",
            ),
        )
    op.execute(REGISTRY)
    op.execute(GUARD)
    for name in ("vnbui_capability_registry", "vnbui_capability_effect"):
        op.execute(f"REVOKE ALL ON FUNCTION {name}() FROM PUBLIC")
    for table in (
        "storage_capability_evidence",
        "storage_capability_qualifications",
        "storage_capability_revocations",
    ):
        op.create_index("idx_" + table + "_org_id", table, ["org_id"])
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
        op.execute(
            f"CREATE POLICY tenant_isolation_{table} ON {table} USING (org_id=NULLIF(current_setting('app.current_org',true),'')) WITH CHECK (org_id=NULLIF(current_setting('app.current_org',true),''))"
        )
        op.execute(f"REVOKE ALL ON {table} FROM PUBLIC")
        op.execute(
            f"CREATE TRIGGER capability_registry BEFORE INSERT OR UPDATE OR DELETE ON {table} FOR EACH ROW EXECUTE FUNCTION vnbui_capability_registry()"
        )
    for table in (
        "s3_publications",
        "s3_upload_parts",
        "s3_upload_results",
        "s3_part_observation_scans",
        "s3_part_observation_pages",
    ):
        op.execute(
            f"CREATE TRIGGER z_capability_effect BEFORE INSERT OR UPDATE ON {table} FOR EACH ROW EXECUTE FUNCTION vnbui_capability_effect()"
        )


def downgrade():
    raise RuntimeError("Capability custody requires reviewed disposition")
