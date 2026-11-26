"""Closed installation source descriptors; no enrollment or activation."""

from alembic import op
from alembic.script import ScriptDirectory

revision = "installation_source"
down_revision = "configuration_generation"
branch_labels = None
depends_on = None

SOURCE = r"""
  IF d->'schema'='2'::jsonb THEN
   s:=d->'source';
   IF (jsonb_typeof(s)='object' AND s ?& ARRAY['kind','api_origin','api_ca_sha256','namespace','name','uid','immutable','access_key','secret_key','trust_key'] AND
      s-ARRAY['kind','api_origin','api_ca_sha256','namespace','name','uid','immutable','access_key','secret_key','trust_key']='{}'::jsonb AND
      s->>'kind'='kubernetes_immutable_secret' AND s->'immutable'='true'::jsonb AND
      s->>'api_origin' ~ '^https://[A-Za-z0-9.-]+(:[0-9]{1,5})?$' AND
      s->>'api_ca_sha256' ~ '^[0-9a-f]{64}$' AND
      s->>'namespace' ~ '^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$' AND octet_length(s->>'namespace')<=63 AND
      s->>'name' ~ '^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$' AND octet_length(s->>'name')<=253 AND
      s->>'uid' ~ '^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$' AND
      s->>'access_key' ~ '^[A-Za-z0-9._-]{1,253}$' AND
      s->>'secret_key' ~ '^[A-Za-z0-9._-]{1,253}$' AND
      s->>'trust_key' ~ '^[A-Za-z0-9._-]{1,253}$' AND
      s->>'access_key'<>s->>'secret_key' AND s->>'access_key'<>s->>'trust_key' AND s->>'secret_key'<>s->>'trust_key') IS NOT TRUE THEN
    RAISE EXCEPTION 'Installation source descriptor invalid' USING ERRCODE='23514'; END IF;
   FOREACH item IN ARRAY ARRAY['kind','api_origin','api_ca_sha256','namespace','name','uid','access_key','secret_key','trust_key'] LOOP
    IF jsonb_typeof(s->item) IS DISTINCT FROM 'string' OR octet_length(s->>item) NOT BETWEEN 1 AND 2048 THEN
     RAISE EXCEPTION 'Installation source string required' USING ERRCODE='23514'; END IF;
   END LOOP;
   IF s->>'api_origin' ~ ':[0-9]+$' AND split_part(regexp_replace(s->>'api_origin','^https://',''),':',2)::integer NOT BETWEEN 1 AND 65535 THEN
    RAISE EXCEPTION 'Installation source port invalid' USING ERRCODE='23514'; END IF;
  END IF;
"""


def upgrade():
    previous = (
        ScriptDirectory.from_config(op.get_context().config)
        .get_revision(down_revision)
        .module
    )
    sql = previous.REGISTRY.replace("CREATE FUNCTION", "CREATE OR REPLACE FUNCTION", 1)
    sql = sql.replace("DECLARE d jsonb;", "DECLARE d jsonb; s jsonb;")
    old = "d-ARRAY['schema','id','installation_id','revision','target','profile','adapter','wire','credential_version','trust_sha256']='{}'::jsonb AND\n      d->'schema'='1'::jsonb"
    new = "((d->'schema'='1'::jsonb AND d-ARRAY['schema','id','installation_id','revision','target','profile','adapter','wire','credential_version','trust_sha256']='{}'::jsonb) OR (d->'schema'='2'::jsonb AND d ? 'source' AND d-ARRAY['schema','id','installation_id','revision','target','profile','adapter','wire','credential_version','trust_sha256','source']='{}'::jsonb))"
    assert old in sql
    sql = sql.replace(old, new)
    marker = "  FOREACH item IN ARRAY ARRAY['id','installation_id','credential_version'] LOOP"
    assert marker in sql
    sql = sql.replace(marker, SOURCE + marker)
    start = "    (SELECT encode(sha256(convert_to(value,'UTF8')),'hex') FROM public.settings_v3 WHERE key='storage.s3.trust_pem')"
    end = "AND encrypted_value<>'')<>2 THEN"
    assert start in sql and end in sql
    sql = sql.replace(start, "    (d->'schema'='1'::jsonb AND (" + start.strip())
    sql = sql.replace(end, "AND encrypted_value<>'')<>2)) THEN")
    op.execute(sql)
    op.execute("REVOKE ALL ON FUNCTION vnbui_configuration_registry() FROM PUBLIC")


def downgrade():
    raise RuntimeError("Installation-source custody requires reviewed disposition")
