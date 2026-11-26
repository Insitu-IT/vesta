"""Profile-bound Complete/HEAD evidence; no publication or recovery authority."""

import importlib.util
from pathlib import Path

from alembic import op

revision = "result_profiles"
down_revision = "part_observations"
branch_labels = None
depends_on = None

spec = importlib.util.spec_from_file_location(
    "result_predecessor", Path(__file__).with_name("20260928_provider_results.py")
)
previous = importlib.util.module_from_spec(spec)
spec.loader.exec_module(previous)


def replace_once(sql, old, new):
    if sql.count(old) != 1:
        raise RuntimeError("Provider result predecessor contract differs")
    return sql.replace(old, new, 1)


SQL = replace_once(previous.SQL, "CREATE FUNCTION", "CREATE OR REPLACE FUNCTION")
fields = "'body_sha256','bytes','metadata'"
assert SQL.count(fields) == 2
SQL = SQL.replace(
    fields,
    fields
    + ",'profile','checksum_comparison','assurance','scrub_required','assurance_reason'",
)
SQL = replace_once(
    SQL,
    "obj->'schema' IS DISTINCT FROM '1'::jsonb",
    "obj->'schema' IS DISTINCT FROM '2'::jsonb",
)
SQL = replace_once(
    SQL,
    "   FOREACH field IN ARRAY ARRAY['version_id','request_id','host_id'] LOOP",
    """
   IF (plan->>'capability_profile' IN ('checksum-enforced/1','consumer-verified/1','db-rooted-consumer-verified/1')) IS NOT TRUE
     OR obj->'profile' IS DISTINCT FROM plan->'capability_profile'
     OR obj->'scrub_required' IS DISTINCT FROM 'true'::jsonb
     OR obj->>'assurance' IS DISTINCT FROM (CASE WHEN NEW.operation='complete' THEN 'completion_observed' ELSE 'identity_metadata_only' END)
     OR obj->>'checksum_comparison' IS DISTINCT FROM (CASE WHEN obj->'checksum_value'='null'::jsonb THEN 'absent' ELSE 'composite_match' END)
     OR obj->>'assurance_reason' IS DISTINCT FROM (CASE
       WHEN NEW.operation='complete' THEN 'object_verification_pending'
       WHEN obj->'checksum_value'='null'::jsonb THEN 'checksum_absent'
       WHEN plan->>'capability_profile'='checksum-enforced/1' THEN 'composite_not_full_object_sha256'
       ELSE 'provider_checksum_enforcement_unproven' END) THEN
     RAISE EXCEPTION 'Result profile assurance invalid' USING ERRCODE='23514';
   END IF;
   FOREACH field IN ARRAY ARRAY['version_id','request_id','host_id'] LOOP""",
)
SQL = replace_once(
    SQL,
    "       OR jsonb_build_array(obj->'checksum_algorithm',obj->'checksum_type',obj->'checksum_value') IS DISTINCT FROM jsonb_build_array('SHA256'::text,'COMPOSITE'::text,composite)",
    """       OR (jsonb_build_array(obj->'checksum_algorithm',obj->'checksum_type',obj->'checksum_value') IS DISTINCT FROM jsonb_build_array('SHA256'::text,'COMPOSITE'::text,composite)
         AND NOT (plan->>'capability_profile' IN ('consumer-verified/1','db-rooted-consumer-verified/1')
           AND jsonb_build_array(obj->'checksum_algorithm',obj->'checksum_type',obj->'checksum_value')='[null,null,null]'::jsonb))""",
)


def upgrade():
    # Old responses remain immutable in their original schema, without new claims.
    op.execute(SQL)
    op.execute("REVOKE ALL ON FUNCTION vnbui_provider_result() FROM PUBLIC")


def downgrade():
    raise RuntimeError("Profile-bound result custody requires reviewed disposition")
