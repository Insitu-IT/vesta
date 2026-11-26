"""Unmounted database-backed configuration generations and per-request fences.

No environment enrollment, provider qualification or installation activation.
"""

from alembic.script import ScriptDirectory
from alembic import op
import sqlalchemy as sa
import uuid
from sqlalchemy.dialects.postgresql import JSONB

revision = "configuration_generation"
down_revision = "capability_evidence_v2"
branch_labels = None
depends_on = None

CLOCK = r"""CREATE FUNCTION vnbui_configuration_clock() RETURNS trigger
LANGUAGE plpgsql VOLATILE SET search_path=pg_catalog,public AS $$
BEGIN
 IF TG_TABLE_NAME='storage_configuration_clock' THEN
  IF TG_OP<>'UPDATE' THEN RAISE EXCEPTION 'Configuration clock immutable' USING ERRCODE='23514'; END IF;
  IF NEW.slot IS DISTINCT FROM OLD.slot OR NEW.installation_id IS DISTINCT FROM OLD.installation_id OR NEW.revision IS DISTINCT FROM OLD.revision+1 THEN
   RAISE EXCEPTION 'Configuration clock must advance once' USING ERRCODE='23514'; END IF;
  PERFORM pg_advisory_xact_lock(1447977559,1);
  RETURN NEW;
 END IF;
 IF TG_LEVEL='STATEMENT' THEN
  PERFORM pg_advisory_xact_lock(1447977559,1);
  IF TG_OP='TRUNCATE' THEN UPDATE public.storage_configuration_clock SET revision=revision+1 WHERE slot=1; END IF;
  RETURN NULL;
 END IF;
 IF (TG_OP<>'INSERT' AND OLD.key=ANY(ARRAY['storage.type','storage.s3.endpoint','storage.s3.bucket','storage.s3.region','storage.s3.prefix','storage.s3.capability_profile','storage.s3.trust_pem','storage.s3.access_key','storage.s3.secret_key'])) OR (TG_OP<>'DELETE' AND NEW.key=ANY(ARRAY['storage.type','storage.s3.endpoint','storage.s3.bucket','storage.s3.region','storage.s3.prefix','storage.s3.capability_profile','storage.s3.trust_pem','storage.s3.access_key','storage.s3.secret_key'])) THEN
  UPDATE public.storage_configuration_clock SET revision=revision+1 WHERE slot=1;
  IF NOT FOUND THEN RAISE EXCEPTION 'Configuration clock unavailable' USING ERRCODE='23514'; END IF;
 END IF;
 RETURN NULL;
END $$"""

REGISTRY = r"""CREATE FUNCTION vnbui_configuration_registry() RETURNS trigger
LANGUAGE plpgsql VOLATILE SET search_path=pg_catalog,public AS $$
DECLARE d jsonb; target jsonb; rev bigint; item text; g public.storage_configuration_generations;
BEGIN
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'Configuration custody immutable' USING ERRCODE='23514'; END IF;
 PERFORM pg_advisory_xact_lock(1447977559,1);
 SELECT revision INTO rev FROM public.storage_configuration_clock WHERE slot=1;
 IF TG_TABLE_NAME='storage_configuration_generations' THEN
  d:=NEW.descriptor;
  IF (jsonb_typeof(d)='object' AND d ?& ARRAY['schema','id','installation_id','revision','target','profile','adapter','wire','credential_version','trust_sha256'] AND
      d-ARRAY['schema','id','installation_id','revision','target','profile','adapter','wire','credential_version','trust_sha256']='{}'::jsonb AND
      d->'schema'='1'::jsonb AND d->>'id'=NEW.id AND d->'revision'=to_jsonb(NEW.revision) AND
      NEW.revision=rev AND d->>'installation_id'=(SELECT installation_id FROM public.storage_configuration_clock WHERE slot=1) AND d->>'adapter'='vnbui-callback-provider/1' AND d->>'wire'='vnbui-storage-transaction/1' AND
      jsonb_typeof(d->'trust_sha256')='string' AND d->>'trust_sha256' ~ '^[0-9a-f]{64}$' AND
      jsonb_typeof(d->'target')='object' AND
      d->>'profile' IN ('checksum-enforced/1','consumer-verified/1','db-rooted-consumer-verified/1') AND
      NEW.sha256=encode(sha256(convert_to(d::text,'UTF8')),'hex') AND octet_length(d::text)<16384) IS NOT TRUE THEN
    RAISE EXCEPTION 'Configuration descriptor invalid' USING ERRCODE='23514'; END IF;
  FOREACH item IN ARRAY ARRAY['id','installation_id','credential_version'] LOOP
   IF (jsonb_typeof(d->item)='string' AND d->>item ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$') IS NOT TRUE THEN
    RAISE EXCEPTION 'Configuration identity invalid' USING ERRCODE='23514'; END IF;
  END LOOP;
  FOREACH item IN ARRAY ARRAY['endpoint','bucket','region','configuration_prefix'] LOOP
   IF (jsonb_typeof(d->'target'->item)='string' AND octet_length(d->'target'->>item)<=4096) IS NOT TRUE THEN
    RAISE EXCEPTION 'Configuration target invalid' USING ERRCODE='23514'; END IF;
  END LOOP;
  SELECT jsonb_build_object('endpoint',max(value) FILTER(WHERE key='storage.s3.endpoint'),
   'bucket',max(value) FILTER(WHERE key='storage.s3.bucket'), 'region',max(value) FILTER(WHERE key='storage.s3.region'),
   'configuration_prefix',max(value) FILTER(WHERE key='storage.s3.prefix')) INTO target FROM public.settings_v3;
  IF d->'target' IS DISTINCT FROM target OR
    (SELECT value FROM public.settings_v3 WHERE key='storage.type') IS DISTINCT FROM 's3' OR
    (SELECT value FROM public.settings_v3 WHERE key='storage.s3.capability_profile') IS DISTINCT FROM d->>'profile' OR
    (SELECT encode(sha256(convert_to(value,'UTF8')),'hex') FROM public.settings_v3 WHERE key='storage.s3.trust_pem') IS DISTINCT FROM d->>'trust_sha256' OR
    (SELECT count(*) FROM public.secrets_v3 WHERE key IN ('storage.s3.access_key','storage.s3.secret_key') AND encrypted_value IS NOT NULL AND encrypted_value<>'')<>2 THEN
   RAISE EXCEPTION 'Persisted configuration differs' USING ERRCODE='23514'; END IF;
 ELSE
  NEW.id:=nextval(pg_get_serial_sequence('public.storage_configuration_activations','id'));
  IF NEW.reason IS NULL OR octet_length(NEW.reason) NOT BETWEEN 1 AND 2048 THEN
   RAISE EXCEPTION 'Configuration fence reason required' USING ERRCODE='23514'; END IF;
  IF NEW.generation_id IS NOT NULL THEN
   SELECT * INTO g FROM public.storage_configuration_generations WHERE id=NEW.generation_id AND org_id=NEW.org_id;
   IF g.id IS NULL OR g.revision IS DISTINCT FROM rev THEN
    RAISE EXCEPTION 'Configuration generation unavailable' USING ERRCODE='23514'; END IF;
  END IF;
 END IF;
 RETURN NEW;
END $$"""

ADMISSION = """
   PERFORM pg_advisory_xact_lock(1447977559,1);
   SELECT * INTO configuration FROM public.storage_configuration_generations
     WHERE org_id=pub.org_id AND sha256=ev.facts->'provider_identity'->>'configuration_sha256';
   IF configuration.id IS NULL OR configuration.revision IS DISTINCT FROM
      (SELECT revision FROM public.storage_configuration_clock WHERE slot=1) OR
      configuration.id IS DISTINCT FROM (SELECT generation_id FROM public.storage_configuration_activations
        WHERE org_id=pub.org_id ORDER BY id DESC LIMIT 1) OR
      configuration.descriptor->'target' IS DISTINCT FROM plan->'target' OR
      configuration.descriptor->'profile' IS DISTINCT FROM plan->'capability_profile' OR
      configuration.descriptor->'adapter' IS DISTINCT FROM ev.facts->'adapter' OR
      configuration.descriptor->'wire' IS DISTINCT FROM ev.facts->'wire' THEN
     RAISE EXCEPTION 'Configuration generation fenced' USING ERRCODE='23514'; END IF;
"""


def upgrade():
    op.create_table(
        "storage_configuration_clock",
        sa.Column("slot", sa.Integer(), primary_key=True, autoincrement=False),
        sa.Column("installation_id", sa.String(), nullable=False),
        sa.Column("revision", sa.BigInteger(), nullable=False),
        sa.CheckConstraint(
            "slot = 1 AND revision > 0", name="ck_storage_configuration_clock"
        ),
    )
    op.execute(
        sa.text(
            "INSERT INTO storage_configuration_clock(slot,installation_id,revision) VALUES(1,:id,1)"
        ).bindparams(id=str(uuid.uuid4()))
    )
    op.create_table(
        "storage_configuration_generations",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column(
            "org_id", sa.String(), sa.ForeignKey("organizations.id"), nullable=False
        ),
        sa.Column("revision", sa.BigInteger(), nullable=False),
        sa.Column("descriptor", JSONB(), nullable=False),
        sa.Column("sha256", sa.String(), nullable=False),
        sa.UniqueConstraint("org_id", "id", name="uq_storage_configuration_org"),
        sa.UniqueConstraint("org_id", "sha256", name="uq_storage_configuration_digest"),
        sa.CheckConstraint("revision > 0", name="ck_storage_configuration_revision"),
    )
    op.create_table(
        "storage_configuration_activations",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column(
            "org_id", sa.String(), sa.ForeignKey("organizations.id"), nullable=False
        ),
        sa.Column("generation_id", sa.String(), nullable=True),
        sa.Column("reason", sa.String(), nullable=False),
        sa.ForeignKeyConstraint(
            ["org_id", "generation_id"],
            [
                "storage_configuration_generations.org_id",
                "storage_configuration_generations.id",
            ],
            name="fk_storage_configuration_activation",
        ),
        sa.UniqueConstraint(
            "generation_id", name="uq_storage_configuration_activation"
        ),
    )
    op.execute(CLOCK)
    op.execute(REGISTRY)
    previous = (
        ScriptDirectory.from_config(op.get_context().config)
        .get_revision(down_revision)
        .module
    )
    guard = previous.GUARD.replace(
        "admission_now timestamptz;",
        "admission_now timestamptz; configuration public.storage_configuration_generations;",
    )
    guard = guard.replace(
        "   PERFORM pg_advisory_xact_lock(1447977558,hashtext(ev.id));",
        ADMISSION + "   PERFORM pg_advisory_xact_lock(1447977558,hashtext(ev.id));",
    )
    assert ADMISSION in guard
    op.execute(guard)
    for name in ("vnbui_configuration_clock", "vnbui_configuration_registry"):
        op.execute(f"REVOKE ALL ON FUNCTION {name}() FROM PUBLIC")
    for table in (
        "storage_configuration_generations",
        "storage_configuration_activations",
    ):
        op.create_index("idx_" + table + "_org_id", table, ["org_id"])
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
        op.execute(
            f"CREATE POLICY tenant_isolation_{table} ON {table} USING (org_id=NULLIF(current_setting('app.current_org',true),'')) WITH CHECK (org_id=NULLIF(current_setting('app.current_org',true),''))"
        )
        op.execute(f"REVOKE ALL ON {table} FROM PUBLIC")
        op.execute(
            f"CREATE TRIGGER configuration_registry BEFORE INSERT OR UPDATE OR DELETE ON {table} FOR EACH ROW EXECUTE FUNCTION vnbui_configuration_registry()"
        )
    op.execute("ALTER TABLE storage_configuration_clock ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE storage_configuration_clock FORCE ROW LEVEL SECURITY")
    op.execute(
        "CREATE POLICY configuration_clock_read ON storage_configuration_clock FOR SELECT USING (true)"
    )
    op.execute(
        "CREATE POLICY configuration_clock_write ON storage_configuration_clock FOR UPDATE USING (current_setting('app.platform_admin',true)='true') WITH CHECK (current_setting('app.platform_admin',true)='true')"
    )
    op.execute("REVOKE ALL ON storage_configuration_clock FROM PUBLIC")
    op.execute(
        "CREATE TRIGGER configuration_clock BEFORE INSERT OR UPDATE OR DELETE ON storage_configuration_clock FOR EACH ROW EXECUTE FUNCTION vnbui_configuration_clock()"
    )
    for table in ("settings_v3", "secrets_v3"):
        op.execute(
            f"CREATE TRIGGER configuration_lock BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON {table} FOR EACH STATEMENT EXECUTE FUNCTION vnbui_configuration_clock()"
        )
        op.execute(
            f"CREATE TRIGGER configuration_change AFTER INSERT OR UPDATE OR DELETE ON {table} FOR EACH ROW EXECUTE FUNCTION vnbui_configuration_clock()"
        )


def downgrade():
    raise RuntimeError("Configuration custody requires reviewed disposition")
