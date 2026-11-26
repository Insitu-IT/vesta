"""Owner-bound part admissions; signed bearer capabilities stay memory-only."""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB
import importlib.util
from pathlib import Path

revision = "provider_parts"
down_revision = "provider_result_custody"
branch_labels = None
depends_on = None
spec = importlib.util.spec_from_file_location(
    "result_predecessor",
    Path(__file__).with_name("20260928_provider_result_custody.py"),
)
previous = importlib.util.module_from_spec(spec)
spec.loader.exec_module(previous)
create = previous.previous
capacity = create.intents.capacity

# Reuse the exact original owner/key/credential binding contract against the
# locked publication, never reinterpret a part row as a publication record.
COMMON = create.COMMON.replace("OLD.", "pub.").replace("NEW.state", "pub.state")
credential = previous.credential
COMMON = COMMON.replace(
    credential,
    "IF TG_OP='INSERT' OR NEW.acknowledgment IS DISTINCT FROM OLD.acknowledgment THEN\n"
    + credential
    + "END IF;\n",
)
SQL = (
    """CREATE FUNCTION vnbui_provider_part() RETURNS trigger
LANGUAGE plpgsql VOLATILE SET search_path=pg_catalog,public AS $$
DECLARE
 pub public.s3_publications; b public.backups; o public.organizations; u public.users;
 s public.schedules; g public.scheduler_grants; c public.schedule_occurrences; q public.backup_queue;
 callback_agent public.agents; cert public.agent_certificates; keyrow public.encryption_keys;
 v jsonb; expected jsonb; doc jsonb; plan jsonb; obj jsonb; artifact jsonb; entry jsonb;
 k text:='provider_part'; field text; cert_ids text[]; nowsec bigint; unit bigint;
 prior public.s3_upload_parts; policy jsonb; previous_platform text; occupied bigint; same_vm bigint;
BEGIN
 IF TG_OP='DELETE' THEN
   RAISE EXCEPTION 'Part custody cannot be deleted' USING ERRCODE='23514';
 END IF;
 IF TG_OP='UPDATE' AND (to_jsonb(NEW)-ARRAY['signing_result','signing_xid','acknowledgment','acknowledgment_xid'])
   IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['signing_result','signing_xid','acknowledgment','acknowledgment_xid']) THEN
   RAISE EXCEPTION 'Part admission is immutable' USING ERRCODE='23514';
 END IF;
 IF TG_OP='UPDATE' AND (NEW.signing_xid IS DISTINCT FROM OLD.signing_xid OR NEW.acknowledgment_xid IS DISTINCT FROM OLD.acknowledgment_xid) THEN
   RAISE EXCEPTION 'Part markers are server owned' USING ERRCODE='23514';
 END IF;
 -- Discover IDs without locks, then follow supported owner-first lock order.
 SELECT * INTO pub FROM public.s3_publications WHERE id=NEW.publication_id AND org_id=NEW.org_id;
 SELECT * INTO b FROM public.backups WHERE id=pub.backup_id AND org_id=NEW.org_id;
 IF pub.id IS NULL OR b.id IS NULL OR current_setting('app.current_org',true) IS DISTINCT FROM NEW.org_id THEN
   RAISE EXCEPTION 'Part owner unavailable' USING ERRCODE='23514';
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
 IF TG_OP='UPDATE' AND NEW.acknowledgment IS DISTINCT FROM OLD.acknowledgment THEN
   -- A new authenticated report can use a current replacement credential. The
   -- original intent remains immutable; only this validation view is replaced.
   v:=v||jsonb_build_object('credential_kind',NEW.acknowledgment->'credential_kind','credential_id',NEW.acknowledgment->'credential_id');
 END IF;
"""
    + COMMON
    + create.KEY_IDENTITY
    + """
 IF pub.provider_control IS NOT NULL OR pub.receipt_verification_intent IS NOT NULL OR pub.prepared_receipt IS NOT NULL
   OR pub.finalize_intent IS NOT NULL OR pub.checkpoint_proof IS NOT NULL
   OR pub.wrapped_attempt_key IS NULL OR pub.wrapped_attempt_key_xid IS NULL OR pub.wrapped_attempt_key_xid=txid_current()
   OR plan->>'provider' IS DISTINCT FROM 'kubevirt' THEN
   RAISE EXCEPTION 'Part original custody unavailable' USING ERRCODE='23514';
 END IF;
 entry:=pub.provider_create->NEW.artifact_key;
 IF entry IS NULL OR jsonb_typeof(entry->'response') IS DISTINCT FROM 'object'
   OR (entry->>'xid')::bigint=txid_current()
   OR EXISTS(SELECT 1 FROM public.s3_publications WHERE id=pub.id AND xmin::text::bigint=mod(txid_current(),4294967296))
   OR EXISTS(SELECT 1 FROM jsonb_each(pub.provider_create) e WHERE e.value->'response'='null'::jsonb) THEN
   RAISE EXCEPTION 'Part requires committed exact create' USING ERRCODE='23514';
 END IF;
 SELECT a INTO artifact FROM jsonb_array_elements(plan->'artifacts') a WHERE a->>'key'=NEW.artifact_key;
 IF artifact IS NULL OR NEW.number NOT BETWEEN 1 AND 10000 OR NEW.byte_count<0 OR NEW.sha256 !~ '^[0-9a-f]{64}$' THEN
   RAISE EXCEPTION 'Part tuple invalid' USING ERRCODE='23514';
 END IF;
 unit:=greatest(8388608, (((artifact->>'ciphertext_max')::bigint+9999)/10000+8388607)/8388608*8388608);
 IF NEW.byte_count>unit THEN RAISE EXCEPTION 'Part size invalid' USING ERRCODE='23514'; END IF;
 expected:=expected||jsonb_build_object('artifact_key',NEW.artifact_key,'number',NEW.number,'bytes',NEW.byte_count,'sha256',NEW.sha256,
   'upload_id',entry->'response'->'upload_id','create_response_sha256',encode(sha256(convert_to((entry->'response')::text,'UTF8')),'hex'),
   'wrapped_key_sha256',encode(sha256(convert_to(pub.wrapped_attempt_key::jsonb::text,'UTF8')),'hex'));
 IF v IS DISTINCT FROM expected OR octet_length(NEW.intent::text)>8192 THEN
   RAISE EXCEPTION 'Part intent binding invalid' USING ERRCODE='23514';
 END IF;
 -- Parent Backup remains locked against release. The only global context is
 -- this fixed platform READ after tenant-owner validation; exceptions restore it.
"""
    + capacity.READ
    + """
 IF (policy->>'maintenance')::boolean THEN RAISE EXCEPTION 'Capacity maintenance' USING ERRCODE='23514'; END IF;
 IF TG_OP='INSERT' THEN
   IF NEW.id !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$' THEN
     RAISE EXCEPTION 'Part ID invalid' USING ERRCODE='23514';
   END IF;
   IF NEW.intent_xid IS NOT NULL OR NEW.signing_result IS NOT NULL OR NEW.signing_xid IS NOT NULL
     OR NEW.acknowledgment IS NOT NULL OR NEW.acknowledgment_xid IS NOT NULL THEN
     RAISE EXCEPTION 'Part first admission only' USING ERRCODE='23514';
   END IF;
"""
    + create.LIFETIME
    + """
   IF EXISTS(SELECT 1 FROM public.s3_upload_parts WHERE publication_id=pub.id AND acknowledgment IS NULL) THEN
     RAISE EXCEPTION 'Part attempt effect-held' USING ERRCODE='23514';
   END IF;
   SELECT * INTO prior FROM public.s3_upload_parts WHERE publication_id=pub.id AND artifact_key=NEW.artifact_key ORDER BY number DESC LIMIT 1;
   IF NEW.number IS DISTINCT FROM COALESCE(prior.number,0)+1 OR (prior.id IS NOT NULL AND (prior.acknowledgment IS NULL OR prior.acknowledgment_xid=txid_current() OR prior.byte_count<>unit)) THEN
     RAISE EXCEPTION 'Part predecessor unavailable' USING ERRCODE='23514';
   END IF;
   -- Immutable sequential predecessors must all be full-sized. This exact
   -- total follows by induction, without rescanning/materializing old parts.
   IF (NEW.number::bigint-1)*unit+NEW.byte_count>(artifact->>'ciphertext_max')::bigint THEN
     RAISE EXCEPTION 'Part total exceeds artifact' USING ERRCODE='23514';
   END IF;
   NEW.intent_xid:=txid_current();
 ELSE
   IF NEW.signing_result IS DISTINCT FROM OLD.signing_result THEN
     obj:=NEW.signing_result;
     nowsec:=floor(extract(epoch FROM clock_timestamp()));
     IF OLD.signing_result IS NOT NULL OR OLD.intent_xid IS NULL OR OLD.intent_xid=txid_current()
       OR NEW.acknowledgment IS DISTINCT FROM OLD.acknowledgment
       OR jsonb_typeof(obj) IS DISTINCT FROM 'object'
       OR NOT obj ?& ARRAY['schema','sha256','expires_at'] OR obj-ARRAY['schema','sha256','expires_at']<>'{}'::jsonb
       OR obj->'schema' IS DISTINCT FROM '1'::jsonb OR jsonb_typeof(obj->'sha256') IS DISTINCT FROM 'string'
       OR obj->>'sha256' !~ '^[0-9a-f]{64}$'
       OR jsonb_typeof(obj->'expires_at') IS DISTINCT FROM 'number' OR obj->>'expires_at' !~ '^[0-9]{1,12}$' THEN
       RAISE EXCEPTION 'Part signing result invalid' USING ERRCODE='23514';
     END IF;
     IF (obj->>'expires_at')::bigint NOT BETWEEN (v->>'created_at')::bigint AND (v->>'expires_at')::bigint+60
       OR (obj->>'expires_at')::bigint>nowsec+60 THEN
       RAISE EXCEPTION 'Part signing expiry invalid' USING ERRCODE='23514';
     END IF;
     NEW.signing_xid:=txid_current();
   ELSIF NEW.acknowledgment IS DISTINCT FROM OLD.acknowledgment THEN
     obj:=NEW.acknowledgment;
     IF OLD.acknowledgment IS NOT NULL OR OLD.signing_result IS NULL OR OLD.signing_xid IS NULL OR OLD.signing_xid=txid_current()
       OR jsonb_typeof(obj) IS DISTINCT FROM 'object'
       OR NOT obj ?& ARRAY['schema','etag','credential_kind','credential_id']
       OR obj-ARRAY['schema','etag','credential_kind','credential_id']<>'{}'::jsonb
       OR obj->'schema' IS DISTINCT FROM '1'::jsonb
       OR jsonb_typeof(obj->'etag') IS DISTINCT FROM 'string' OR octet_length(obj->>'etag') NOT BETWEEN 1 AND 1022
       OR obj->>'etag' ~ '[[:cntrl:]\"]' THEN
       RAISE EXCEPTION 'Part acknowledgment invalid' USING ERRCODE='23514';
     END IF;
     NEW.acknowledgment_xid:=txid_current();
   END IF;
 END IF;
 RETURN NEW;
END $$"""
)

# Keep effect holds bidirectional: neither a new create nor a parent alteration
# may race an unresolved part. Existing result readback stays available.
PARENT = previous.SQL.replace(
    "BEGIN\n",
    """BEGIN
 IF TG_OP='UPDATE' AND EXISTS(SELECT 1 FROM public.s3_upload_parts WHERE publication_id=OLD.id) THEN
   IF (to_jsonb(NEW)-'provider_create') IS DISTINCT FROM (to_jsonb(OLD)-'provider_create') THEN
     RAISE EXCEPTION 'Part successor remains dormant' USING ERRCODE='23514';
   END IF;
   IF NEW.provider_create IS DISTINCT FROM OLD.provider_create AND EXISTS(
       SELECT 1 FROM public.s3_upload_parts WHERE publication_id=OLD.id AND acknowledgment IS NULL) THEN
     RAISE EXCEPTION 'Part attempt effect-held' USING ERRCODE='23514';
   END IF;
 END IF;
""",
    1,
)


def upgrade():
    op.create_unique_constraint(
        "uq_s3_publication_org", "s3_publications", ["org_id", "id"]
    )
    op.create_table(
        "s3_upload_parts",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column(
            "org_id", sa.String(), sa.ForeignKey("organizations.id"), nullable=False
        ),
        sa.Column("publication_id", sa.String(), nullable=False),
        sa.Column("artifact_key", sa.String(), nullable=False),
        sa.Column("number", sa.Integer(), nullable=False),
        sa.Column("byte_count", sa.BigInteger(), nullable=False),
        sa.Column("sha256", sa.String(), nullable=False),
        sa.Column("intent", JSONB(), nullable=False),
        sa.Column("intent_xid", sa.BigInteger()),
        sa.Column("signing_result", JSONB()),
        sa.Column("signing_xid", sa.BigInteger()),
        sa.Column("acknowledgment", JSONB()),
        sa.Column("acknowledgment_xid", sa.BigInteger()),
        sa.ForeignKeyConstraint(
            ["org_id", "publication_id"],
            ["s3_publications.org_id", "s3_publications.id"],
            name="fk_upload_part_publication",
            ondelete="RESTRICT",
        ),
        sa.UniqueConstraint(
            "publication_id", "artifact_key", "number", name="uq_upload_part"
        ),
        sa.CheckConstraint(
            "number BETWEEN 1 AND 10000 AND byte_count >= 0",
            name="ck_upload_part_bounds",
        ),
        sa.CheckConstraint("length(sha256) = 64", name="ck_upload_part_hash"),
    )
    op.create_index("idx_s3_upload_parts_org_id", "s3_upload_parts", ["org_id"])
    op.create_index(
        "idx_upload_part_unacknowledged",
        "s3_upload_parts",
        ["publication_id"],
        postgresql_where=sa.text("acknowledgment IS NULL"),
    )
    op.execute("ALTER TABLE s3_upload_parts ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE s3_upload_parts FORCE ROW LEVEL SECURITY")
    op.execute(
        "CREATE POLICY tenant_isolation_s3_upload_parts ON s3_upload_parts USING (org_id=NULLIF(current_setting('app.current_org',true),'')) WITH CHECK (org_id=NULLIF(current_setting('app.current_org',true),''))"
    )
    op.execute("REVOKE ALL ON s3_upload_parts FROM PUBLIC")
    op.execute(SQL)
    op.execute(PARENT)
    op.execute("REVOKE ALL ON FUNCTION vnbui_provider_part() FROM PUBLIC")
    op.execute("REVOKE ALL ON FUNCTION vnbui_callback_intent() FROM PUBLIC")
    op.execute(
        "CREATE TRIGGER provider_part BEFORE INSERT OR UPDATE OR DELETE ON s3_upload_parts FOR EACH ROW EXECUTE FUNCTION vnbui_provider_part()"
    )

    op.execute(
        "CREATE TRIGGER audit_upload_part AFTER INSERT OR UPDATE ON s3_upload_parts FOR EACH ROW EXECUTE FUNCTION audit_access()"
    )


def downgrade():
    raise RuntimeError("Part custody requires reviewed rollback")
