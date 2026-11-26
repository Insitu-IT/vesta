"""Schema-2 unmounted facts and post-lock live-clock admission.

No existing custody is rewritten. The validity policy is fixture-only and does
not qualify installation, signer/wire mounting, or a provider deployment.
"""

from alembic import op

revision = "capability_evidence_v2"
down_revision = "capability_evidence"
branch_labels = None
depends_on = None

# Closed descriptor compiled inline at authoring time, never from mutable app imports.
REGISTRY = r"""CREATE OR REPLACE FUNCTION vnbui_capability_registry() RETURNS trigger
LANGUAGE plpgsql VOLATILE SET search_path=pg_catalog,public AS $$
DECLARE f jsonb; item jsonb; field text; ev public.storage_capability_evidence;
 t0 timestamptz; t1 timestamptz; t2 timestamptz; t3 timestamptz; ts timestamptz;
BEGIN
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'Capability custody immutable' USING ERRCODE='23514'; END IF;
 IF TG_TABLE_NAME='storage_capability_evidence' THEN
  f:=NEW.facts;
  IF NEW.id !~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
   OR octet_length(f::text)>65536 OR ((jsonb_typeof(f)='object' AND
    f ?& ARRAY['schema','target','profile','adapter','wire','provider_identity','observation','validity','behaviors','evidence_cases'] AND
    f-ARRAY['schema','target','profile','adapter','wire','provider_identity','observation','validity','behaviors','evidence_cases']='{}'::jsonb AND
    ((f->'schema')='2'::jsonb AND f->>'schema'='2') AND
    (jsonb_typeof((f->'target'))='object' AND
    (f->'target') ?& ARRAY['endpoint','bucket','region','configuration_prefix'] AND
    (f->'target')-ARRAY['endpoint','bucket','region','configuration_prefix']='{}'::jsonb AND
    (jsonb_typeof(((f->'target')->'endpoint'))='string' AND
    octet_length(((f->'target')->'endpoint')#>>'{}') BETWEEN 1 AND
    1024 AND
    (((f->'target')->'endpoint')#>>'{}') ~ '^https://[^/?#@]+$') AND
    (jsonb_typeof(((f->'target')->'bucket'))='string' AND
    octet_length(((f->'target')->'bucket')#>>'{}') BETWEEN 1 AND
    1024) AND
    (jsonb_typeof(((f->'target')->'region'))='string' AND
    octet_length(((f->'target')->'region')#>>'{}') BETWEEN 1 AND
    1024) AND
    (jsonb_typeof(((f->'target')->'configuration_prefix'))='string' AND
    octet_length(((f->'target')->'configuration_prefix')#>>'{}') BETWEEN 0 AND
    1024)) AND
    ((f->'profile')='"checksum-enforced/1"'::jsonb OR (f->'profile')='"consumer-verified/1"'::jsonb OR (f->'profile')='"db-rooted-consumer-verified/1"'::jsonb) AND
    ((f->'adapter')='"vnbui-callback-provider/1"'::jsonb) AND
    ((f->'wire')='"vnbui-storage-transaction/1"'::jsonb) AND
    ((jsonb_typeof((f->'provider_identity'))='object' AND
    (f->'provider_identity') ?& ARRAY['kind','product','product_version','deployment_identity','configuration_sha256'] AND
    (f->'provider_identity')-ARRAY['kind','product','product_version','deployment_identity','configuration_sha256']='{}'::jsonb AND
    (((f->'provider_identity')->'kind')='"versioned"'::jsonb) AND
    (jsonb_typeof(((f->'provider_identity')->'product'))='string' AND
    octet_length(((f->'provider_identity')->'product')#>>'{}') BETWEEN 1 AND
    128) AND
    (jsonb_typeof(((f->'provider_identity')->'product_version'))='string' AND
    octet_length(((f->'provider_identity')->'product_version')#>>'{}') BETWEEN 1 AND
    128 AND ((f->'provider_identity')->>'product_version') ~ '^[^*?]+$') AND
    (jsonb_typeof(((f->'provider_identity')->'deployment_identity'))='string' AND
    octet_length(((f->'provider_identity')->'deployment_identity')#>>'{}') BETWEEN 1 AND
    256) AND
    (jsonb_typeof(((f->'provider_identity')->'configuration_sha256'))='string' AND
    octet_length(((f->'provider_identity')->'configuration_sha256')#>>'{}') BETWEEN 64 AND
    64 AND
    (((f->'provider_identity')->'configuration_sha256')#>>'{}') ~ '^[0-9a-f]{64}$')) OR (jsonb_typeof((f->'provider_identity'))='object' AND
    (f->'provider_identity') ?& ARRAY['kind','service','observation_scope_id','configuration_sha256','build_version_exposed'] AND
    (f->'provider_identity')-ARRAY['kind','service','observation_scope_id','configuration_sha256','build_version_exposed']='{}'::jsonb AND
    (((f->'provider_identity')->'kind')='"managed_observation"'::jsonb) AND
    (jsonb_typeof(((f->'provider_identity')->'service'))='string' AND
    octet_length(((f->'provider_identity')->'service')#>>'{}') BETWEEN 1 AND
    128) AND
    (jsonb_typeof(((f->'provider_identity')->'observation_scope_id'))='string' AND
    octet_length(((f->'provider_identity')->'observation_scope_id')#>>'{}') BETWEEN 1 AND
    256) AND
    (jsonb_typeof(((f->'provider_identity')->'configuration_sha256'))='string' AND
    octet_length(((f->'provider_identity')->'configuration_sha256')#>>'{}') BETWEEN 64 AND
    64 AND
    (((f->'provider_identity')->'configuration_sha256')#>>'{}') ~ '^[0-9a-f]{64}$') AND
    (((f->'provider_identity')->'build_version_exposed')='false'::jsonb))) AND
    (jsonb_typeof((f->'observation'))='object' AND
    (f->'observation') ?& ARRAY['started_at_utc','completed_at_utc','test_contract_revision'] AND
    (f->'observation')-ARRAY['started_at_utc','completed_at_utc','test_contract_revision']='{}'::jsonb AND
    (jsonb_typeof(((f->'observation')->'started_at_utc'))='string' AND
    octet_length(((f->'observation')->'started_at_utc')#>>'{}') BETWEEN 27 AND
    27 AND
    (((f->'observation')->'started_at_utc')#>>'{}') ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z$') AND
    (jsonb_typeof(((f->'observation')->'completed_at_utc'))='string' AND
    octet_length(((f->'observation')->'completed_at_utc')#>>'{}') BETWEEN 27 AND
    27 AND
    (((f->'observation')->'completed_at_utc')#>>'{}') ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z$') AND
    (jsonb_typeof(((f->'observation')->'test_contract_revision'))='string' AND
    octet_length(((f->'observation')->'test_contract_revision')#>>'{}') BETWEEN 1 AND
    128)) AND
    (jsonb_typeof((f->'validity'))='object' AND
    (f->'validity') ?& ARRAY['not_before_utc','not_after_utc','invalidation_policy_revision'] AND
    (f->'validity')-ARRAY['not_before_utc','not_after_utc','invalidation_policy_revision']='{}'::jsonb AND
    (jsonb_typeof(((f->'validity')->'not_before_utc'))='string' AND
    octet_length(((f->'validity')->'not_before_utc')#>>'{}') BETWEEN 27 AND
    27 AND
    (((f->'validity')->'not_before_utc')#>>'{}') ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z$') AND
    (jsonb_typeof(((f->'validity')->'not_after_utc'))='string' AND
    octet_length(((f->'validity')->'not_after_utc')#>>'{}') BETWEEN 27 AND
    27 AND
    (((f->'validity')->'not_after_utc')#>>'{}') ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z$') AND
    (((f->'validity')->'invalidation_policy_revision')='"unmounted-fixture-86400s/1"'::jsonb)) AND
    (jsonb_typeof((f->'behaviors'))='object' AND
    (f->'behaviors') ?& ARRAY['mpu_create','upload_part','complete_manifest','head_identity','list_parts','checksum','complete_preconditions','conditional_generation_create','conditional_tombstone_create','version_readback','same_upload_post_complete'] AND
    (f->'behaviors')-ARRAY['mpu_create','upload_part','complete_manifest','head_identity','list_parts','checksum','complete_preconditions','conditional_generation_create','conditional_tombstone_create','version_readback','same_upload_post_complete']='{}'::jsonb AND
    (jsonb_typeof(((f->'behaviors')->'mpu_create'))='object' AND
    ((f->'behaviors')->'mpu_create') ?& ARRAY['status','semantics','case_ids'] AND
    ((f->'behaviors')->'mpu_create')-ARRAY['status','semantics','case_ids']='{}'::jsonb AND
    ((((f->'behaviors')->'mpu_create')->'status')='"enforced"'::jsonb OR (((f->'behaviors')->'mpu_create')->'status')='"ignored"'::jsonb OR (((f->'behaviors')->'mpu_create')->'status')='"unsupported"'::jsonb OR (((f->'behaviors')->'mpu_create')->'status')='"unestablished"'::jsonb) AND
    ((jsonb_typeof((((f->'behaviors')->'mpu_create')->'semantics'))='object' AND
    (((f->'behaviors')->'mpu_create')->'semantics') ?& ARRAY['key_binding','upload_id_attribution'] AND
    (((f->'behaviors')->'mpu_create')->'semantics')-ARRAY['key_binding','upload_id_attribution']='{}'::jsonb AND
    (((((f->'behaviors')->'mpu_create')->'semantics')->'key_binding')='"exact"'::jsonb OR ((((f->'behaviors')->'mpu_create')->'semantics')->'key_binding')='"not_exact"'::jsonb) AND
    (((((f->'behaviors')->'mpu_create')->'semantics')->'upload_id_attribution')='"response"'::jsonb OR ((((f->'behaviors')->'mpu_create')->'semantics')->'upload_id_attribution')='"not_attributable"'::jsonb)) OR ((((f->'behaviors')->'mpu_create')->'semantics')='null'::jsonb)) AND
    (CASE WHEN jsonb_typeof((((f->'behaviors')->'mpu_create')->'case_ids'))='array' THEN jsonb_array_length((((f->'behaviors')->'mpu_create')->'case_ids')) BETWEEN 0 AND
    128 AND
    NOT EXISTS(SELECT 1 FROM jsonb_array_elements((((f->'behaviors')->'mpu_create')->'case_ids')) element WHERE ((jsonb_typeof(element)='string' AND
    octet_length(element#>>'{}') BETWEEN 1 AND
    128 AND
    (element#>>'{}') ~ '^[A-Za-z0-9._:/-]+$')) IS NOT TRUE) ELSE false END)) AND
    (jsonb_typeof(((f->'behaviors')->'upload_part'))='object' AND
    ((f->'behaviors')->'upload_part') ?& ARRAY['status','semantics','case_ids'] AND
    ((f->'behaviors')->'upload_part')-ARRAY['status','semantics','case_ids']='{}'::jsonb AND
    ((((f->'behaviors')->'upload_part')->'status')='"enforced"'::jsonb OR (((f->'behaviors')->'upload_part')->'status')='"ignored"'::jsonb OR (((f->'behaviors')->'upload_part')->'status')='"unsupported"'::jsonb OR (((f->'behaviors')->'upload_part')->'status')='"unestablished"'::jsonb) AND
    ((jsonb_typeof((((f->'behaviors')->'upload_part')->'semantics'))='object' AND
    (((f->'behaviors')->'upload_part')->'semantics') ?& ARRAY['upload_part_binding','acknowledgment','same_number'] AND
    (((f->'behaviors')->'upload_part')->'semantics')-ARRAY['upload_part_binding','acknowledgment','same_number']='{}'::jsonb AND
    (((((f->'behaviors')->'upload_part')->'semantics')->'upload_part_binding')='"exact"'::jsonb OR ((((f->'behaviors')->'upload_part')->'semantics')->'upload_part_binding')='"not_exact"'::jsonb) AND
    (((((f->'behaviors')->'upload_part')->'semantics')->'acknowledgment')='"etag"'::jsonb OR ((((f->'behaviors')->'upload_part')->'semantics')->'acknowledgment')='"not_attributable"'::jsonb) AND
    (((((f->'behaviors')->'upload_part')->'semantics')->'same_number')='"replaces"'::jsonb OR ((((f->'behaviors')->'upload_part')->'semantics')->'same_number')='"refuses"'::jsonb OR ((((f->'behaviors')->'upload_part')->'semantics')->'same_number')='"unestablished"'::jsonb)) OR ((((f->'behaviors')->'upload_part')->'semantics')='null'::jsonb)) AND
    (CASE WHEN jsonb_typeof((((f->'behaviors')->'upload_part')->'case_ids'))='array' THEN jsonb_array_length((((f->'behaviors')->'upload_part')->'case_ids')) BETWEEN 0 AND
    128 AND
    NOT EXISTS(SELECT 1 FROM jsonb_array_elements((((f->'behaviors')->'upload_part')->'case_ids')) element WHERE ((jsonb_typeof(element)='string' AND
    octet_length(element#>>'{}') BETWEEN 1 AND
    128 AND
    (element#>>'{}') ~ '^[A-Za-z0-9._:/-]+$')) IS NOT TRUE) ELSE false END)) AND
    (jsonb_typeof(((f->'behaviors')->'complete_manifest'))='object' AND
    ((f->'behaviors')->'complete_manifest') ?& ARRAY['status','semantics','case_ids'] AND
    ((f->'behaviors')->'complete_manifest')-ARRAY['status','semantics','case_ids']='{}'::jsonb AND
    ((((f->'behaviors')->'complete_manifest')->'status')='"enforced"'::jsonb OR (((f->'behaviors')->'complete_manifest')->'status')='"ignored"'::jsonb OR (((f->'behaviors')->'complete_manifest')->'status')='"unsupported"'::jsonb OR (((f->'behaviors')->'complete_manifest')->'status')='"unestablished"'::jsonb) AND
    ((jsonb_typeof((((f->'behaviors')->'complete_manifest')->'semantics'))='object' AND
    (((f->'behaviors')->'complete_manifest')->'semantics') ?& ARRAY['selection','stale_etag','embedded_error','result_identity'] AND
    (((f->'behaviors')->'complete_manifest')->'semantics')-ARRAY['selection','stale_etag','embedded_error','result_identity']='{}'::jsonb AND
    (((((f->'behaviors')->'complete_manifest')->'semantics')->'selection')='"explicit_etags"'::jsonb OR ((((f->'behaviors')->'complete_manifest')->'semantics')->'selection')='"not_exact"'::jsonb) AND
    (((((f->'behaviors')->'complete_manifest')->'semantics')->'stale_etag')='"refuses"'::jsonb OR ((((f->'behaviors')->'complete_manifest')->'semantics')->'stale_etag')='"ignored"'::jsonb OR ((((f->'behaviors')->'complete_manifest')->'semantics')->'stale_etag')='"unestablished"'::jsonb) AND
    (((((f->'behaviors')->'complete_manifest')->'semantics')->'embedded_error')='"parsed"'::jsonb OR ((((f->'behaviors')->'complete_manifest')->'semantics')->'embedded_error')='"not_parsed"'::jsonb) AND
    (((((f->'behaviors')->'complete_manifest')->'semantics')->'result_identity')='"exact_key"'::jsonb OR ((((f->'behaviors')->'complete_manifest')->'semantics')->'result_identity')='"not_exact"'::jsonb)) OR ((((f->'behaviors')->'complete_manifest')->'semantics')='null'::jsonb)) AND
    (CASE WHEN jsonb_typeof((((f->'behaviors')->'complete_manifest')->'case_ids'))='array' THEN jsonb_array_length((((f->'behaviors')->'complete_manifest')->'case_ids')) BETWEEN 0 AND
    128 AND
    NOT EXISTS(SELECT 1 FROM jsonb_array_elements((((f->'behaviors')->'complete_manifest')->'case_ids')) element WHERE ((jsonb_typeof(element)='string' AND
    octet_length(element#>>'{}') BETWEEN 1 AND
    128 AND
    (element#>>'{}') ~ '^[A-Za-z0-9._:/-]+$')) IS NOT TRUE) ELSE false END)) AND
    (jsonb_typeof(((f->'behaviors')->'head_identity'))='object' AND
    ((f->'behaviors')->'head_identity') ?& ARRAY['status','semantics','case_ids'] AND
    ((f->'behaviors')->'head_identity')-ARRAY['status','semantics','case_ids']='{}'::jsonb AND
    ((((f->'behaviors')->'head_identity')->'status')='"enforced"'::jsonb OR (((f->'behaviors')->'head_identity')->'status')='"ignored"'::jsonb OR (((f->'behaviors')->'head_identity')->'status')='"unsupported"'::jsonb OR (((f->'behaviors')->'head_identity')->'status')='"unestablished"'::jsonb) AND
    ((jsonb_typeof((((f->'behaviors')->'head_identity')->'semantics'))='object' AND
    (((f->'behaviors')->'head_identity')->'semantics') ?& ARRAY['key_binding','fields','missing'] AND
    (((f->'behaviors')->'head_identity')->'semantics')-ARRAY['key_binding','fields','missing']='{}'::jsonb AND
    (((((f->'behaviors')->'head_identity')->'semantics')->'key_binding')='"exact"'::jsonb OR ((((f->'behaviors')->'head_identity')->'semantics')->'key_binding')='"not_exact"'::jsonb) AND
    (((((f->'behaviors')->'head_identity')->'semantics')->'fields')='"metadata_length"'::jsonb OR ((((f->'behaviors')->'head_identity')->'semantics')->'fields')='"insufficient"'::jsonb) AND
    (((((f->'behaviors')->'head_identity')->'semantics')->'missing')='"not_found"'::jsonb OR ((((f->'behaviors')->'head_identity')->'semantics')->'missing')='"unestablished"'::jsonb)) OR ((((f->'behaviors')->'head_identity')->'semantics')='null'::jsonb)) AND
    (CASE WHEN jsonb_typeof((((f->'behaviors')->'head_identity')->'case_ids'))='array' THEN jsonb_array_length((((f->'behaviors')->'head_identity')->'case_ids')) BETWEEN 0 AND
    128 AND
    NOT EXISTS(SELECT 1 FROM jsonb_array_elements((((f->'behaviors')->'head_identity')->'case_ids')) element WHERE ((jsonb_typeof(element)='string' AND
    octet_length(element#>>'{}') BETWEEN 1 AND
    128 AND
    (element#>>'{}') ~ '^[A-Za-z0-9._:/-]+$')) IS NOT TRUE) ELSE false END)) AND
    (jsonb_typeof(((f->'behaviors')->'list_parts'))='object' AND
    ((f->'behaviors')->'list_parts') ?& ARRAY['status','semantics','case_ids'] AND
    ((f->'behaviors')->'list_parts')-ARRAY['status','semantics','case_ids']='{}'::jsonb AND
    ((((f->'behaviors')->'list_parts')->'status')='"enforced"'::jsonb OR (((f->'behaviors')->'list_parts')->'status')='"ignored"'::jsonb OR (((f->'behaviors')->'list_parts')->'status')='"unsupported"'::jsonb OR (((f->'behaviors')->'list_parts')->'status')='"unestablished"'::jsonb) AND
    ((jsonb_typeof((((f->'behaviors')->'list_parts')->'semantics'))='object' AND
    (((f->'behaviors')->'list_parts')->'semantics') ?& ARRAY['pagination','unfinished','fields'] AND
    (((f->'behaviors')->'list_parts')->'semantics')-ARRAY['pagination','unfinished','fields']='{}'::jsonb AND
    (((((f->'behaviors')->'list_parts')->'semantics')->'pagination')='"monotonic_marker"'::jsonb OR ((((f->'behaviors')->'list_parts')->'semantics')->'pagination')='"not_exact"'::jsonb) AND
    (((((f->'behaviors')->'list_parts')->'semantics')->'unfinished')='"omitted"'::jsonb OR ((((f->'behaviors')->'list_parts')->'semantics')->'unfinished')='"unestablished"'::jsonb) AND
    (((((f->'behaviors')->'list_parts')->'semantics')->'fields')='"etag_size_checksum_optional"'::jsonb OR ((((f->'behaviors')->'list_parts')->'semantics')->'fields')='"insufficient"'::jsonb)) OR ((((f->'behaviors')->'list_parts')->'semantics')='null'::jsonb)) AND
    (CASE WHEN jsonb_typeof((((f->'behaviors')->'list_parts')->'case_ids'))='array' THEN jsonb_array_length((((f->'behaviors')->'list_parts')->'case_ids')) BETWEEN 0 AND
    128 AND
    NOT EXISTS(SELECT 1 FROM jsonb_array_elements((((f->'behaviors')->'list_parts')->'case_ids')) element WHERE ((jsonb_typeof(element)='string' AND
    octet_length(element#>>'{}') BETWEEN 1 AND
    128 AND
    (element#>>'{}') ~ '^[A-Za-z0-9._:/-]+$')) IS NOT TRUE) ELSE false END)) AND
    (jsonb_typeof(((f->'behaviors')->'checksum'))='object' AND
    ((f->'behaviors')->'checksum') ?& ARRAY['status','semantics','case_ids'] AND
    ((f->'behaviors')->'checksum')-ARRAY['status','semantics','case_ids']='{}'::jsonb AND
    ((((f->'behaviors')->'checksum')->'status')='"enforced"'::jsonb OR (((f->'behaviors')->'checksum')->'status')='"ignored"'::jsonb OR (((f->'behaviors')->'checksum')->'status')='"unsupported"'::jsonb OR (((f->'behaviors')->'checksum')->'status')='"unestablished"'::jsonb) AND
    ((jsonb_typeof((((f->'behaviors')->'checksum')->'semantics'))='object' AND
    (((f->'behaviors')->'checksum')->'semantics') ?& ARRAY['algorithm','checksum_type','assurance','mismatch'] AND
    (((f->'behaviors')->'checksum')->'semantics')-ARRAY['algorithm','checksum_type','assurance','mismatch']='{}'::jsonb AND
    (((((f->'behaviors')->'checksum')->'semantics')->'algorithm')='"sha256"'::jsonb) AND
    (((((f->'behaviors')->'checksum')->'semantics')->'checksum_type')='"composite"'::jsonb OR ((((f->'behaviors')->'checksum')->'semantics')->'checksum_type')='"full_object"'::jsonb OR ((((f->'behaviors')->'checksum')->'semantics')->'checksum_type')='"absent"'::jsonb) AND
    (((((f->'behaviors')->'checksum')->'semantics')->'assurance')='"enforced"'::jsonb OR ((((f->'behaviors')->'checksum')->'semantics')->'assurance')='"echoed"'::jsonb OR ((((f->'behaviors')->'checksum')->'semantics')->'assurance')='"absent"'::jsonb) AND
    (((((f->'behaviors')->'checksum')->'semantics')->'mismatch')='"refuses"'::jsonb OR ((((f->'behaviors')->'checksum')->'semantics')->'mismatch')='"ignored"'::jsonb OR ((((f->'behaviors')->'checksum')->'semantics')->'mismatch')='"unestablished"'::jsonb)) OR ((((f->'behaviors')->'checksum')->'semantics')='null'::jsonb)) AND
    (CASE WHEN jsonb_typeof((((f->'behaviors')->'checksum')->'case_ids'))='array' THEN jsonb_array_length((((f->'behaviors')->'checksum')->'case_ids')) BETWEEN 0 AND
    128 AND
    NOT EXISTS(SELECT 1 FROM jsonb_array_elements((((f->'behaviors')->'checksum')->'case_ids')) element WHERE ((jsonb_typeof(element)='string' AND
    octet_length(element#>>'{}') BETWEEN 1 AND
    128 AND
    (element#>>'{}') ~ '^[A-Za-z0-9._:/-]+$')) IS NOT TRUE) ELSE false END)) AND
    (jsonb_typeof(((f->'behaviors')->'complete_preconditions'))='object' AND
    ((f->'behaviors')->'complete_preconditions') ?& ARRAY['status','semantics','case_ids'] AND
    ((f->'behaviors')->'complete_preconditions')-ARRAY['status','semantics','case_ids']='{}'::jsonb AND
    ((((f->'behaviors')->'complete_preconditions')->'status')='"enforced"'::jsonb OR (((f->'behaviors')->'complete_preconditions')->'status')='"ignored"'::jsonb OR (((f->'behaviors')->'complete_preconditions')->'status')='"unsupported"'::jsonb OR (((f->'behaviors')->'complete_preconditions')->'status')='"unestablished"'::jsonb) AND
    ((jsonb_typeof((((f->'behaviors')->'complete_preconditions')->'semantics'))='object' AND
    (((f->'behaviors')->'complete_preconditions')->'semantics') ?& ARRAY['header','collision'] AND
    (((f->'behaviors')->'complete_preconditions')->'semantics')-ARRAY['header','collision']='{}'::jsonb AND
    (((((f->'behaviors')->'complete_preconditions')->'semantics')->'header')='"if-none-match-star"'::jsonb) AND
    (((((f->'behaviors')->'complete_preconditions')->'semantics')->'collision')='"refuses"'::jsonb OR ((((f->'behaviors')->'complete_preconditions')->'semantics')->'collision')='"ignored"'::jsonb OR ((((f->'behaviors')->'complete_preconditions')->'semantics')->'collision')='"unestablished"'::jsonb)) OR ((((f->'behaviors')->'complete_preconditions')->'semantics')='null'::jsonb)) AND
    (CASE WHEN jsonb_typeof((((f->'behaviors')->'complete_preconditions')->'case_ids'))='array' THEN jsonb_array_length((((f->'behaviors')->'complete_preconditions')->'case_ids')) BETWEEN 0 AND
    128 AND
    NOT EXISTS(SELECT 1 FROM jsonb_array_elements((((f->'behaviors')->'complete_preconditions')->'case_ids')) element WHERE ((jsonb_typeof(element)='string' AND
    octet_length(element#>>'{}') BETWEEN 1 AND
    128 AND
    (element#>>'{}') ~ '^[A-Za-z0-9._:/-]+$')) IS NOT TRUE) ELSE false END)) AND
    (jsonb_typeof(((f->'behaviors')->'conditional_generation_create'))='object' AND
    ((f->'behaviors')->'conditional_generation_create') ?& ARRAY['status','semantics','case_ids'] AND
    ((f->'behaviors')->'conditional_generation_create')-ARRAY['status','semantics','case_ids']='{}'::jsonb AND
    ((((f->'behaviors')->'conditional_generation_create')->'status')='"enforced"'::jsonb OR (((f->'behaviors')->'conditional_generation_create')->'status')='"ignored"'::jsonb OR (((f->'behaviors')->'conditional_generation_create')->'status')='"unsupported"'::jsonb OR (((f->'behaviors')->'conditional_generation_create')->'status')='"unestablished"'::jsonb) AND
    ((jsonb_typeof((((f->'behaviors')->'conditional_generation_create')->'semantics'))='object' AND
    (((f->'behaviors')->'conditional_generation_create')->'semantics') ?& ARRAY['condition','collision','identity'] AND
    (((f->'behaviors')->'conditional_generation_create')->'semantics')-ARRAY['condition','collision','identity']='{}'::jsonb AND
    (((((f->'behaviors')->'conditional_generation_create')->'semantics')->'condition')='"if-none-match-star"'::jsonb) AND
    (((((f->'behaviors')->'conditional_generation_create')->'semantics')->'collision')='"refuses"'::jsonb OR ((((f->'behaviors')->'conditional_generation_create')->'semantics')->'collision')='"ignored"'::jsonb OR ((((f->'behaviors')->'conditional_generation_create')->'semantics')->'collision')='"unestablished"'::jsonb) AND
    (((((f->'behaviors')->'conditional_generation_create')->'semantics')->'identity')='"etag"'::jsonb OR ((((f->'behaviors')->'conditional_generation_create')->'semantics')->'identity')='"version"'::jsonb OR ((((f->'behaviors')->'conditional_generation_create')->'semantics')->'identity')='"unestablished"'::jsonb)) OR ((((f->'behaviors')->'conditional_generation_create')->'semantics')='null'::jsonb)) AND
    (CASE WHEN jsonb_typeof((((f->'behaviors')->'conditional_generation_create')->'case_ids'))='array' THEN jsonb_array_length((((f->'behaviors')->'conditional_generation_create')->'case_ids')) BETWEEN 0 AND
    128 AND
    NOT EXISTS(SELECT 1 FROM jsonb_array_elements((((f->'behaviors')->'conditional_generation_create')->'case_ids')) element WHERE ((jsonb_typeof(element)='string' AND
    octet_length(element#>>'{}') BETWEEN 1 AND
    128 AND
    (element#>>'{}') ~ '^[A-Za-z0-9._:/-]+$')) IS NOT TRUE) ELSE false END)) AND
    (jsonb_typeof(((f->'behaviors')->'conditional_tombstone_create'))='object' AND
    ((f->'behaviors')->'conditional_tombstone_create') ?& ARRAY['status','semantics','case_ids'] AND
    ((f->'behaviors')->'conditional_tombstone_create')-ARRAY['status','semantics','case_ids']='{}'::jsonb AND
    ((((f->'behaviors')->'conditional_tombstone_create')->'status')='"enforced"'::jsonb OR (((f->'behaviors')->'conditional_tombstone_create')->'status')='"ignored"'::jsonb OR (((f->'behaviors')->'conditional_tombstone_create')->'status')='"unsupported"'::jsonb OR (((f->'behaviors')->'conditional_tombstone_create')->'status')='"unestablished"'::jsonb) AND
    ((jsonb_typeof((((f->'behaviors')->'conditional_tombstone_create')->'semantics'))='object' AND
    (((f->'behaviors')->'conditional_tombstone_create')->'semantics') ?& ARRAY['condition','collision','identity'] AND
    (((f->'behaviors')->'conditional_tombstone_create')->'semantics')-ARRAY['condition','collision','identity']='{}'::jsonb AND
    (((((f->'behaviors')->'conditional_tombstone_create')->'semantics')->'condition')='"if-none-match-star"'::jsonb) AND
    (((((f->'behaviors')->'conditional_tombstone_create')->'semantics')->'collision')='"refuses"'::jsonb OR ((((f->'behaviors')->'conditional_tombstone_create')->'semantics')->'collision')='"ignored"'::jsonb OR ((((f->'behaviors')->'conditional_tombstone_create')->'semantics')->'collision')='"unestablished"'::jsonb) AND
    (((((f->'behaviors')->'conditional_tombstone_create')->'semantics')->'identity')='"etag"'::jsonb OR ((((f->'behaviors')->'conditional_tombstone_create')->'semantics')->'identity')='"version"'::jsonb OR ((((f->'behaviors')->'conditional_tombstone_create')->'semantics')->'identity')='"unestablished"'::jsonb)) OR ((((f->'behaviors')->'conditional_tombstone_create')->'semantics')='null'::jsonb)) AND
    (CASE WHEN jsonb_typeof((((f->'behaviors')->'conditional_tombstone_create')->'case_ids'))='array' THEN jsonb_array_length((((f->'behaviors')->'conditional_tombstone_create')->'case_ids')) BETWEEN 0 AND
    128 AND
    NOT EXISTS(SELECT 1 FROM jsonb_array_elements((((f->'behaviors')->'conditional_tombstone_create')->'case_ids')) element WHERE ((jsonb_typeof(element)='string' AND
    octet_length(element#>>'{}') BETWEEN 1 AND
    128 AND
    (element#>>'{}') ~ '^[A-Za-z0-9._:/-]+$')) IS NOT TRUE) ELSE false END)) AND
    (jsonb_typeof(((f->'behaviors')->'version_readback'))='object' AND
    ((f->'behaviors')->'version_readback') ?& ARRAY['status','semantics','case_ids'] AND
    ((f->'behaviors')->'version_readback')-ARRAY['status','semantics','case_ids']='{}'::jsonb AND
    ((((f->'behaviors')->'version_readback')->'status')='"enforced"'::jsonb OR (((f->'behaviors')->'version_readback')->'status')='"ignored"'::jsonb OR (((f->'behaviors')->'version_readback')->'status')='"unsupported"'::jsonb OR (((f->'behaviors')->'version_readback')->'status')='"unestablished"'::jsonb) AND
    ((jsonb_typeof((((f->'behaviors')->'version_readback')->'semantics'))='object' AND
    (((f->'behaviors')->'version_readback')->'semantics') ?& ARRAY['identifier','exact_read','overwrite','delete_marker'] AND
    (((f->'behaviors')->'version_readback')->'semantics')-ARRAY['identifier','exact_read','overwrite','delete_marker']='{}'::jsonb AND
    (((((f->'behaviors')->'version_readback')->'semantics')->'identifier')='"available"'::jsonb OR ((((f->'behaviors')->'version_readback')->'semantics')->'identifier')='"unavailable"'::jsonb) AND
    (((((f->'behaviors')->'version_readback')->'semantics')->'exact_read')='"supported"'::jsonb OR ((((f->'behaviors')->'version_readback')->'semantics')->'exact_read')='"unsupported"'::jsonb) AND
    (((((f->'behaviors')->'version_readback')->'semantics')->'overwrite')='"new_version"'::jsonb OR ((((f->'behaviors')->'version_readback')->'semantics')->'overwrite')='"replaces"'::jsonb OR ((((f->'behaviors')->'version_readback')->'semantics')->'overwrite')='"unestablished"'::jsonb) AND
    (((((f->'behaviors')->'version_readback')->'semantics')->'delete_marker')='"supported"'::jsonb OR ((((f->'behaviors')->'version_readback')->'semantics')->'delete_marker')='"unsupported"'::jsonb OR ((((f->'behaviors')->'version_readback')->'semantics')->'delete_marker')='"unestablished"'::jsonb)) OR ((((f->'behaviors')->'version_readback')->'semantics')='null'::jsonb)) AND
    (CASE WHEN jsonb_typeof((((f->'behaviors')->'version_readback')->'case_ids'))='array' THEN jsonb_array_length((((f->'behaviors')->'version_readback')->'case_ids')) BETWEEN 0 AND
    128 AND
    NOT EXISTS(SELECT 1 FROM jsonb_array_elements((((f->'behaviors')->'version_readback')->'case_ids')) element WHERE ((jsonb_typeof(element)='string' AND
    octet_length(element#>>'{}') BETWEEN 1 AND
    128 AND
    (element#>>'{}') ~ '^[A-Za-z0-9._:/-]+$')) IS NOT TRUE) ELSE false END)) AND
    (jsonb_typeof(((f->'behaviors')->'same_upload_post_complete'))='object' AND
    ((f->'behaviors')->'same_upload_post_complete') ?& ARRAY['status','semantics','case_ids'] AND
    ((f->'behaviors')->'same_upload_post_complete')-ARRAY['status','semantics','case_ids']='{}'::jsonb AND
    ((((f->'behaviors')->'same_upload_post_complete')->'status')='"enforced"'::jsonb OR (((f->'behaviors')->'same_upload_post_complete')->'status')='"ignored"'::jsonb OR (((f->'behaviors')->'same_upload_post_complete')->'status')='"unsupported"'::jsonb OR (((f->'behaviors')->'same_upload_post_complete')->'status')='"unestablished"'::jsonb) AND
    ((jsonb_typeof((((f->'behaviors')->'same_upload_post_complete')->'semantics'))='object' AND
    (((f->'behaviors')->'same_upload_post_complete')->'semantics') ?& ARRAY['complete_before_put','put_before_complete','overlap_same_number'] AND
    (((f->'behaviors')->'same_upload_post_complete')->'semantics')-ARRAY['complete_before_put','put_before_complete','overlap_same_number']='{}'::jsonb AND
    (jsonb_typeof(((((f->'behaviors')->'same_upload_post_complete')->'semantics')->'complete_before_put'))='object' AND
    ((((f->'behaviors')->'same_upload_post_complete')->'semantics')->'complete_before_put') ?& ARRAY['request','selected_object'] AND
    ((((f->'behaviors')->'same_upload_post_complete')->'semantics')->'complete_before_put')-ARRAY['request','selected_object']='{}'::jsonb AND
    ((((((f->'behaviors')->'same_upload_post_complete')->'semantics')->'complete_before_put')->'request')='"rejected_no_such_upload"'::jsonb OR (((((f->'behaviors')->'same_upload_post_complete')->'semantics')->'complete_before_put')->'request')='"rejected_other"'::jsonb OR (((((f->'behaviors')->'same_upload_post_complete')->'semantics')->'complete_before_put')->'request')='"succeeds_without_selected_change"'::jsonb OR (((((f->'behaviors')->'same_upload_post_complete')->'semantics')->'complete_before_put')->'request')='"succeeds_with_selected_change"'::jsonb OR (((((f->'behaviors')->'same_upload_post_complete')->'semantics')->'complete_before_put')->'request')='"unestablished"'::jsonb) AND
    ((((((f->'behaviors')->'same_upload_post_complete')->'semantics')->'complete_before_put')->'selected_object')='"unchanged"'::jsonb OR (((((f->'behaviors')->'same_upload_post_complete')->'semantics')->'complete_before_put')->'selected_object')='"changed"'::jsonb OR (((((f->'behaviors')->'same_upload_post_complete')->'semantics')->'complete_before_put')->'selected_object')='"unestablished"'::jsonb)) AND
    (jsonb_typeof(((((f->'behaviors')->'same_upload_post_complete')->'semantics')->'put_before_complete'))='object' AND
    ((((f->'behaviors')->'same_upload_post_complete')->'semantics')->'put_before_complete') ?& ARRAY['request','selected_object'] AND
    ((((f->'behaviors')->'same_upload_post_complete')->'semantics')->'put_before_complete')-ARRAY['request','selected_object']='{}'::jsonb AND
    ((((((f->'behaviors')->'same_upload_post_complete')->'semantics')->'put_before_complete')->'request')='"rejected_no_such_upload"'::jsonb OR (((((f->'behaviors')->'same_upload_post_complete')->'semantics')->'put_before_complete')->'request')='"rejected_other"'::jsonb OR (((((f->'behaviors')->'same_upload_post_complete')->'semantics')->'put_before_complete')->'request')='"succeeds_without_selected_change"'::jsonb OR (((((f->'behaviors')->'same_upload_post_complete')->'semantics')->'put_before_complete')->'request')='"succeeds_with_selected_change"'::jsonb OR (((((f->'behaviors')->'same_upload_post_complete')->'semantics')->'put_before_complete')->'request')='"unestablished"'::jsonb) AND
    ((((((f->'behaviors')->'same_upload_post_complete')->'semantics')->'put_before_complete')->'selected_object')='"unchanged"'::jsonb OR (((((f->'behaviors')->'same_upload_post_complete')->'semantics')->'put_before_complete')->'selected_object')='"changed"'::jsonb OR (((((f->'behaviors')->'same_upload_post_complete')->'semantics')->'put_before_complete')->'selected_object')='"unestablished"'::jsonb)) AND
    (jsonb_typeof(((((f->'behaviors')->'same_upload_post_complete')->'semantics')->'overlap_same_number'))='object' AND
    ((((f->'behaviors')->'same_upload_post_complete')->'semantics')->'overlap_same_number') ?& ARRAY['request','selected_object'] AND
    ((((f->'behaviors')->'same_upload_post_complete')->'semantics')->'overlap_same_number')-ARRAY['request','selected_object']='{}'::jsonb AND
    ((((((f->'behaviors')->'same_upload_post_complete')->'semantics')->'overlap_same_number')->'request')='"rejected_no_such_upload"'::jsonb OR (((((f->'behaviors')->'same_upload_post_complete')->'semantics')->'overlap_same_number')->'request')='"rejected_other"'::jsonb OR (((((f->'behaviors')->'same_upload_post_complete')->'semantics')->'overlap_same_number')->'request')='"succeeds_without_selected_change"'::jsonb OR (((((f->'behaviors')->'same_upload_post_complete')->'semantics')->'overlap_same_number')->'request')='"succeeds_with_selected_change"'::jsonb OR (((((f->'behaviors')->'same_upload_post_complete')->'semantics')->'overlap_same_number')->'request')='"unestablished"'::jsonb) AND
    ((((((f->'behaviors')->'same_upload_post_complete')->'semantics')->'overlap_same_number')->'selected_object')='"unchanged"'::jsonb OR (((((f->'behaviors')->'same_upload_post_complete')->'semantics')->'overlap_same_number')->'selected_object')='"changed"'::jsonb OR (((((f->'behaviors')->'same_upload_post_complete')->'semantics')->'overlap_same_number')->'selected_object')='"unestablished"'::jsonb))) OR ((((f->'behaviors')->'same_upload_post_complete')->'semantics')='null'::jsonb)) AND
    (CASE WHEN jsonb_typeof((((f->'behaviors')->'same_upload_post_complete')->'case_ids'))='array' THEN jsonb_array_length((((f->'behaviors')->'same_upload_post_complete')->'case_ids')) BETWEEN 0 AND
    128 AND
    NOT EXISTS(SELECT 1 FROM jsonb_array_elements((((f->'behaviors')->'same_upload_post_complete')->'case_ids')) element WHERE ((jsonb_typeof(element)='string' AND
    octet_length(element#>>'{}') BETWEEN 1 AND
    128 AND
    (element#>>'{}') ~ '^[A-Za-z0-9._:/-]+$')) IS NOT TRUE) ELSE false END))) AND
    (CASE WHEN jsonb_typeof((f->'evidence_cases'))='array' THEN jsonb_array_length((f->'evidence_cases')) BETWEEN 1 AND
    128 AND
    NOT EXISTS(SELECT 1 FROM jsonb_array_elements((f->'evidence_cases')) element WHERE ((jsonb_typeof(element)='object' AND
    element ?& ARRAY['case_id','artifact_sha256'] AND
    element-ARRAY['case_id','artifact_sha256']='{}'::jsonb AND
    (jsonb_typeof((element->'case_id'))='string' AND
    octet_length((element->'case_id')#>>'{}') BETWEEN 1 AND
    128 AND
    ((element->'case_id')#>>'{}') ~ '^[A-Za-z0-9._:/-]+$') AND
    (jsonb_typeof((element->'artifact_sha256'))='string' AND
    octet_length((element->'artifact_sha256')#>>'{}') BETWEEN 64 AND
    64 AND
    ((element->'artifact_sha256')#>>'{}') ~ '^[0-9a-f]{64}$'))) IS NOT TRUE) ELSE false END))) IS NOT TRUE
   OR NEW.sha256 IS DISTINCT FROM encode(sha256(convert_to(f::text,'UTF8')),'hex') THEN
   RAISE EXCEPTION 'Capability facts invalid' USING ERRCODE='23514'; END IF;
  t0:=(f->'observation'->>'started_at_utc')::timestamptz;
  t1:=(f->'observation'->>'completed_at_utc')::timestamptz;
  t2:=(f->'validity'->>'not_before_utc')::timestamptz;
  t3:=(f->'validity'->>'not_after_utc')::timestamptz;
  IF to_char(t0 AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') IS DISTINCT FROM f->'observation'->>'started_at_utc'
   OR to_char(t1 AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') IS DISTINCT FROM f->'observation'->>'completed_at_utc'
   OR to_char(t2 AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') IS DISTINCT FROM f->'validity'->>'not_before_utc'
   OR to_char(t3 AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') IS DISTINCT FROM f->'validity'->>'not_after_utc' THEN
   RAISE EXCEPTION 'Capability timestamp noncanonical' USING ERRCODE='23514'; END IF;
  IF NOT(t0<=t1 AND
    t1<=t2 AND
    t2<t3 AND
    t3-t2<=interval '86400 seconds') THEN
   RAISE EXCEPTION 'Capability validity invalid' USING ERRCODE='23514'; END IF;
  IF (SELECT count(*)<>count(DISTINCT x->>'case_id') FROM jsonb_array_elements(f->'evidence_cases') x) THEN
   RAISE EXCEPTION 'Capability cases duplicated' USING ERRCODE='23514'; END IF;
  FOR field,item IN SELECT * FROM jsonb_each(f->'behaviors') LOOP
   IF (SELECT count(*)<>count(DISTINCT x) FROM jsonb_array_elements(item->'case_ids') x)
    OR EXISTS(SELECT 1 FROM jsonb_array_elements_text(item->'case_ids') x WHERE NOT EXISTS(SELECT 1 FROM jsonb_array_elements(f->'evidence_cases') c WHERE c->>'case_id'=x))
    OR (item->>'status'='unestablished' AND
    (item->'semantics'<>'null'::jsonb OR item->'case_ids'<>'[]'::jsonb))
    OR (item->>'status'<>'unestablished' AND
    (jsonb_array_length(item->'case_ids')=0 OR (item->>'status'<>'unsupported' AND
    item->'semantics'='null'::jsonb))) THEN
    RAISE EXCEPTION 'Capability case reference or assertion invalid' USING ERRCODE='23514'; END IF;

   -- A status is a summary of the closed outcomes, never an independent label.
   IF (item->>'status'='unsupported' AND item->'semantics'<>'null'::jsonb)
    OR (item->>'status' IN ('enforced','ignored') AND (
     (field='mpu_create' AND ((item->>'status'='enforced' AND (jsonb_typeof((item->'semantics'))='object' AND (item->'semantics') ?& ARRAY['key_binding','upload_id_attribution'] AND (item->'semantics')-ARRAY['key_binding','upload_id_attribution']='{}'::jsonb AND (((item->'semantics')->'key_binding')='"exact"'::jsonb) AND (((item->'semantics')->'upload_id_attribution')='"response"'::jsonb))) OR (item->>'status'='ignored' AND ((jsonb_typeof((item->'semantics'))='object' AND (item->'semantics') ?& ARRAY['key_binding','upload_id_attribution'] AND (item->'semantics')-ARRAY['key_binding','upload_id_attribution']='{}'::jsonb AND (((item->'semantics')->'key_binding')='"exact"'::jsonb OR ((item->'semantics')->'key_binding')='"not_exact"'::jsonb) AND (((item->'semantics')->'upload_id_attribution')='"response"'::jsonb OR ((item->'semantics')->'upload_id_attribution')='"not_attributable"'::jsonb)) AND (NOT (jsonb_typeof((item->'semantics'))='object' AND (item->'semantics') ?& ARRAY['key_binding','upload_id_attribution'] AND (item->'semantics')-ARRAY['key_binding','upload_id_attribution']='{}'::jsonb AND (((item->'semantics')->'key_binding')='"exact"'::jsonb) AND (((item->'semantics')->'upload_id_attribution')='"response"'::jsonb)))))))
     OR (field='upload_part' AND ((item->>'status'='enforced' AND (jsonb_typeof((item->'semantics'))='object' AND (item->'semantics') ?& ARRAY['upload_part_binding','acknowledgment','same_number'] AND (item->'semantics')-ARRAY['upload_part_binding','acknowledgment','same_number']='{}'::jsonb AND (((item->'semantics')->'upload_part_binding')='"exact"'::jsonb) AND (((item->'semantics')->'acknowledgment')='"etag"'::jsonb) AND (((item->'semantics')->'same_number')='"replaces"'::jsonb OR ((item->'semantics')->'same_number')='"refuses"'::jsonb))) OR (item->>'status'='ignored' AND ((jsonb_typeof((item->'semantics'))='object' AND (item->'semantics') ?& ARRAY['upload_part_binding','acknowledgment','same_number'] AND (item->'semantics')-ARRAY['upload_part_binding','acknowledgment','same_number']='{}'::jsonb AND (((item->'semantics')->'upload_part_binding')='"exact"'::jsonb OR ((item->'semantics')->'upload_part_binding')='"not_exact"'::jsonb) AND (((item->'semantics')->'acknowledgment')='"etag"'::jsonb OR ((item->'semantics')->'acknowledgment')='"not_attributable"'::jsonb) AND (((item->'semantics')->'same_number')='"replaces"'::jsonb OR ((item->'semantics')->'same_number')='"refuses"'::jsonb)) AND (NOT (jsonb_typeof((item->'semantics'))='object' AND (item->'semantics') ?& ARRAY['upload_part_binding','acknowledgment','same_number'] AND (item->'semantics')-ARRAY['upload_part_binding','acknowledgment','same_number']='{}'::jsonb AND (((item->'semantics')->'upload_part_binding')='"exact"'::jsonb) AND (((item->'semantics')->'acknowledgment')='"etag"'::jsonb) AND (((item->'semantics')->'same_number')='"replaces"'::jsonb OR ((item->'semantics')->'same_number')='"refuses"'::jsonb)))))))
     OR (field='complete_manifest' AND ((item->>'status'='enforced' AND (jsonb_typeof((item->'semantics'))='object' AND (item->'semantics') ?& ARRAY['selection','stale_etag','embedded_error','result_identity'] AND (item->'semantics')-ARRAY['selection','stale_etag','embedded_error','result_identity']='{}'::jsonb AND (((item->'semantics')->'selection')='"explicit_etags"'::jsonb) AND (((item->'semantics')->'stale_etag')='"refuses"'::jsonb) AND (((item->'semantics')->'embedded_error')='"parsed"'::jsonb) AND (((item->'semantics')->'result_identity')='"exact_key"'::jsonb))) OR (item->>'status'='ignored' AND ((jsonb_typeof((item->'semantics'))='object' AND (item->'semantics') ?& ARRAY['selection','stale_etag','embedded_error','result_identity'] AND (item->'semantics')-ARRAY['selection','stale_etag','embedded_error','result_identity']='{}'::jsonb AND (((item->'semantics')->'selection')='"explicit_etags"'::jsonb OR ((item->'semantics')->'selection')='"not_exact"'::jsonb) AND (((item->'semantics')->'stale_etag')='"refuses"'::jsonb OR ((item->'semantics')->'stale_etag')='"ignored"'::jsonb) AND (((item->'semantics')->'embedded_error')='"parsed"'::jsonb OR ((item->'semantics')->'embedded_error')='"not_parsed"'::jsonb) AND (((item->'semantics')->'result_identity')='"exact_key"'::jsonb OR ((item->'semantics')->'result_identity')='"not_exact"'::jsonb)) AND (NOT (jsonb_typeof((item->'semantics'))='object' AND (item->'semantics') ?& ARRAY['selection','stale_etag','embedded_error','result_identity'] AND (item->'semantics')-ARRAY['selection','stale_etag','embedded_error','result_identity']='{}'::jsonb AND (((item->'semantics')->'selection')='"explicit_etags"'::jsonb) AND (((item->'semantics')->'stale_etag')='"refuses"'::jsonb) AND (((item->'semantics')->'embedded_error')='"parsed"'::jsonb) AND (((item->'semantics')->'result_identity')='"exact_key"'::jsonb)))))))
     OR (field='head_identity' AND ((item->>'status'='enforced' AND (jsonb_typeof((item->'semantics'))='object' AND (item->'semantics') ?& ARRAY['key_binding','fields','missing'] AND (item->'semantics')-ARRAY['key_binding','fields','missing']='{}'::jsonb AND (((item->'semantics')->'key_binding')='"exact"'::jsonb) AND (((item->'semantics')->'fields')='"metadata_length"'::jsonb) AND (((item->'semantics')->'missing')='"not_found"'::jsonb))) OR (item->>'status'='ignored' AND ((jsonb_typeof((item->'semantics'))='object' AND (item->'semantics') ?& ARRAY['key_binding','fields','missing'] AND (item->'semantics')-ARRAY['key_binding','fields','missing']='{}'::jsonb AND (((item->'semantics')->'key_binding')='"exact"'::jsonb OR ((item->'semantics')->'key_binding')='"not_exact"'::jsonb) AND (((item->'semantics')->'fields')='"metadata_length"'::jsonb OR ((item->'semantics')->'fields')='"insufficient"'::jsonb) AND (((item->'semantics')->'missing')='"not_found"'::jsonb)) AND (NOT (jsonb_typeof((item->'semantics'))='object' AND (item->'semantics') ?& ARRAY['key_binding','fields','missing'] AND (item->'semantics')-ARRAY['key_binding','fields','missing']='{}'::jsonb AND (((item->'semantics')->'key_binding')='"exact"'::jsonb) AND (((item->'semantics')->'fields')='"metadata_length"'::jsonb) AND (((item->'semantics')->'missing')='"not_found"'::jsonb)))))))
     OR (field='list_parts' AND ((item->>'status'='enforced' AND (jsonb_typeof((item->'semantics'))='object' AND (item->'semantics') ?& ARRAY['pagination','unfinished','fields'] AND (item->'semantics')-ARRAY['pagination','unfinished','fields']='{}'::jsonb AND (((item->'semantics')->'pagination')='"monotonic_marker"'::jsonb) AND (((item->'semantics')->'unfinished')='"omitted"'::jsonb) AND (((item->'semantics')->'fields')='"etag_size_checksum_optional"'::jsonb))) OR (item->>'status'='ignored' AND ((jsonb_typeof((item->'semantics'))='object' AND (item->'semantics') ?& ARRAY['pagination','unfinished','fields'] AND (item->'semantics')-ARRAY['pagination','unfinished','fields']='{}'::jsonb AND (((item->'semantics')->'pagination')='"monotonic_marker"'::jsonb OR ((item->'semantics')->'pagination')='"not_exact"'::jsonb) AND (((item->'semantics')->'unfinished')='"omitted"'::jsonb) AND (((item->'semantics')->'fields')='"etag_size_checksum_optional"'::jsonb OR ((item->'semantics')->'fields')='"insufficient"'::jsonb)) AND (NOT (jsonb_typeof((item->'semantics'))='object' AND (item->'semantics') ?& ARRAY['pagination','unfinished','fields'] AND (item->'semantics')-ARRAY['pagination','unfinished','fields']='{}'::jsonb AND (((item->'semantics')->'pagination')='"monotonic_marker"'::jsonb) AND (((item->'semantics')->'unfinished')='"omitted"'::jsonb) AND (((item->'semantics')->'fields')='"etag_size_checksum_optional"'::jsonb)))))))
     OR (field='checksum' AND ((item->>'status'='enforced' AND (jsonb_typeof((item->'semantics'))='object' AND (item->'semantics') ?& ARRAY['algorithm','checksum_type','assurance','mismatch'] AND (item->'semantics')-ARRAY['algorithm','checksum_type','assurance','mismatch']='{}'::jsonb AND (((item->'semantics')->'algorithm')='"sha256"'::jsonb) AND (((item->'semantics')->'checksum_type')='"composite"'::jsonb OR ((item->'semantics')->'checksum_type')='"full_object"'::jsonb) AND (((item->'semantics')->'assurance')='"enforced"'::jsonb) AND (((item->'semantics')->'mismatch')='"refuses"'::jsonb))) OR (item->>'status'='ignored' AND ((jsonb_typeof((item->'semantics'))='object' AND (item->'semantics') ?& ARRAY['algorithm','checksum_type','assurance','mismatch'] AND (item->'semantics')-ARRAY['algorithm','checksum_type','assurance','mismatch']='{}'::jsonb AND (((item->'semantics')->'algorithm')='"sha256"'::jsonb) AND (((item->'semantics')->'checksum_type')='"composite"'::jsonb OR ((item->'semantics')->'checksum_type')='"full_object"'::jsonb) AND (((item->'semantics')->'assurance')='"echoed"'::jsonb) AND (((item->'semantics')->'mismatch')='"ignored"'::jsonb)) OR (jsonb_typeof((item->'semantics'))='object' AND (item->'semantics') ?& ARRAY['algorithm','checksum_type','assurance','mismatch'] AND (item->'semantics')-ARRAY['algorithm','checksum_type','assurance','mismatch']='{}'::jsonb AND (((item->'semantics')->'algorithm')='"sha256"'::jsonb) AND (((item->'semantics')->'checksum_type')='"absent"'::jsonb) AND (((item->'semantics')->'assurance')='"absent"'::jsonb) AND (((item->'semantics')->'mismatch')='"ignored"'::jsonb))))))
     OR (field='complete_preconditions' AND ((item->>'status'='enforced' AND (jsonb_typeof((item->'semantics'))='object' AND (item->'semantics') ?& ARRAY['header','collision'] AND (item->'semantics')-ARRAY['header','collision']='{}'::jsonb AND (((item->'semantics')->'header')='"if-none-match-star"'::jsonb) AND (((item->'semantics')->'collision')='"refuses"'::jsonb))) OR (item->>'status'='ignored' AND (jsonb_typeof((item->'semantics'))='object' AND (item->'semantics') ?& ARRAY['header','collision'] AND (item->'semantics')-ARRAY['header','collision']='{}'::jsonb AND (((item->'semantics')->'header')='"if-none-match-star"'::jsonb) AND (((item->'semantics')->'collision')='"ignored"'::jsonb)))))
     OR (field='conditional_generation_create' AND ((item->>'status'='enforced' AND (jsonb_typeof((item->'semantics'))='object' AND (item->'semantics') ?& ARRAY['condition','collision','identity'] AND (item->'semantics')-ARRAY['condition','collision','identity']='{}'::jsonb AND (((item->'semantics')->'condition')='"if-none-match-star"'::jsonb) AND (((item->'semantics')->'collision')='"refuses"'::jsonb) AND (((item->'semantics')->'identity')='"etag"'::jsonb OR ((item->'semantics')->'identity')='"version"'::jsonb))) OR (item->>'status'='ignored' AND (jsonb_typeof((item->'semantics'))='object' AND (item->'semantics') ?& ARRAY['condition','collision','identity'] AND (item->'semantics')-ARRAY['condition','collision','identity']='{}'::jsonb AND (((item->'semantics')->'condition')='"if-none-match-star"'::jsonb) AND (((item->'semantics')->'collision')='"ignored"'::jsonb) AND (((item->'semantics')->'identity')='"etag"'::jsonb OR ((item->'semantics')->'identity')='"version"'::jsonb)))))
     OR (field='conditional_tombstone_create' AND ((item->>'status'='enforced' AND (jsonb_typeof((item->'semantics'))='object' AND (item->'semantics') ?& ARRAY['condition','collision','identity'] AND (item->'semantics')-ARRAY['condition','collision','identity']='{}'::jsonb AND (((item->'semantics')->'condition')='"if-none-match-star"'::jsonb) AND (((item->'semantics')->'collision')='"refuses"'::jsonb) AND (((item->'semantics')->'identity')='"etag"'::jsonb OR ((item->'semantics')->'identity')='"version"'::jsonb))) OR (item->>'status'='ignored' AND (jsonb_typeof((item->'semantics'))='object' AND (item->'semantics') ?& ARRAY['condition','collision','identity'] AND (item->'semantics')-ARRAY['condition','collision','identity']='{}'::jsonb AND (((item->'semantics')->'condition')='"if-none-match-star"'::jsonb) AND (((item->'semantics')->'collision')='"ignored"'::jsonb) AND (((item->'semantics')->'identity')='"etag"'::jsonb OR ((item->'semantics')->'identity')='"version"'::jsonb)))))
     OR (field='version_readback' AND ((item->>'status'='enforced' AND (jsonb_typeof((item->'semantics'))='object' AND (item->'semantics') ?& ARRAY['identifier','exact_read','overwrite','delete_marker'] AND (item->'semantics')-ARRAY['identifier','exact_read','overwrite','delete_marker']='{}'::jsonb AND (((item->'semantics')->'identifier')='"available"'::jsonb) AND (((item->'semantics')->'exact_read')='"supported"'::jsonb) AND (((item->'semantics')->'overwrite')='"new_version"'::jsonb) AND (((item->'semantics')->'delete_marker')='"supported"'::jsonb))) OR (item->>'status'='ignored' AND (jsonb_typeof((item->'semantics'))='object' AND (item->'semantics') ?& ARRAY['identifier','exact_read','overwrite','delete_marker'] AND (item->'semantics')-ARRAY['identifier','exact_read','overwrite','delete_marker']='{}'::jsonb AND (((item->'semantics')->'identifier')='"unavailable"'::jsonb) AND (((item->'semantics')->'exact_read')='"unsupported"'::jsonb) AND (((item->'semantics')->'overwrite')='"replaces"'::jsonb) AND (((item->'semantics')->'delete_marker')='"unsupported"'::jsonb)))))
     OR (field='same_upload_post_complete' AND ((item->>'status'='enforced' AND (jsonb_typeof((item->'semantics'))='object' AND (item->'semantics') ?& ARRAY['complete_before_put','put_before_complete','overlap_same_number'] AND (item->'semantics')-ARRAY['complete_before_put','put_before_complete','overlap_same_number']='{}'::jsonb AND (jsonb_typeof(((item->'semantics')->'complete_before_put'))='object' AND ((item->'semantics')->'complete_before_put') ?& ARRAY['request','selected_object'] AND ((item->'semantics')->'complete_before_put')-ARRAY['request','selected_object']='{}'::jsonb AND ((((item->'semantics')->'complete_before_put')->'request')='"rejected_no_such_upload"'::jsonb OR (((item->'semantics')->'complete_before_put')->'request')='"rejected_other"'::jsonb OR (((item->'semantics')->'complete_before_put')->'request')='"succeeds_without_selected_change"'::jsonb) AND ((((item->'semantics')->'complete_before_put')->'selected_object')='"unchanged"'::jsonb)) AND (jsonb_typeof(((item->'semantics')->'put_before_complete'))='object' AND ((item->'semantics')->'put_before_complete') ?& ARRAY['request','selected_object'] AND ((item->'semantics')->'put_before_complete')-ARRAY['request','selected_object']='{}'::jsonb AND ((((item->'semantics')->'put_before_complete')->'request')='"rejected_no_such_upload"'::jsonb OR (((item->'semantics')->'put_before_complete')->'request')='"rejected_other"'::jsonb OR (((item->'semantics')->'put_before_complete')->'request')='"succeeds_without_selected_change"'::jsonb) AND ((((item->'semantics')->'put_before_complete')->'selected_object')='"unchanged"'::jsonb)) AND (jsonb_typeof(((item->'semantics')->'overlap_same_number'))='object' AND ((item->'semantics')->'overlap_same_number') ?& ARRAY['request','selected_object'] AND ((item->'semantics')->'overlap_same_number')-ARRAY['request','selected_object']='{}'::jsonb AND ((((item->'semantics')->'overlap_same_number')->'request')='"rejected_no_such_upload"'::jsonb OR (((item->'semantics')->'overlap_same_number')->'request')='"rejected_other"'::jsonb OR (((item->'semantics')->'overlap_same_number')->'request')='"succeeds_without_selected_change"'::jsonb) AND ((((item->'semantics')->'overlap_same_number')->'selected_object')='"unchanged"'::jsonb)))) OR (item->>'status'='ignored' AND ((jsonb_typeof((item->'semantics'))='object' AND (item->'semantics') ?& ARRAY['complete_before_put','put_before_complete','overlap_same_number'] AND (item->'semantics')-ARRAY['complete_before_put','put_before_complete','overlap_same_number']='{}'::jsonb AND ((jsonb_typeof(((item->'semantics')->'complete_before_put'))='object' AND ((item->'semantics')->'complete_before_put') ?& ARRAY['request','selected_object'] AND ((item->'semantics')->'complete_before_put')-ARRAY['request','selected_object']='{}'::jsonb AND ((((item->'semantics')->'complete_before_put')->'request')='"rejected_no_such_upload"'::jsonb OR (((item->'semantics')->'complete_before_put')->'request')='"rejected_other"'::jsonb OR (((item->'semantics')->'complete_before_put')->'request')='"succeeds_without_selected_change"'::jsonb) AND ((((item->'semantics')->'complete_before_put')->'selected_object')='"unchanged"'::jsonb)) OR (jsonb_typeof(((item->'semantics')->'complete_before_put'))='object' AND ((item->'semantics')->'complete_before_put') ?& ARRAY['request','selected_object'] AND ((item->'semantics')->'complete_before_put')-ARRAY['request','selected_object']='{}'::jsonb AND ((((item->'semantics')->'complete_before_put')->'request')='"succeeds_with_selected_change"'::jsonb) AND ((((item->'semantics')->'complete_before_put')->'selected_object')='"changed"'::jsonb))) AND ((jsonb_typeof(((item->'semantics')->'put_before_complete'))='object' AND ((item->'semantics')->'put_before_complete') ?& ARRAY['request','selected_object'] AND ((item->'semantics')->'put_before_complete')-ARRAY['request','selected_object']='{}'::jsonb AND ((((item->'semantics')->'put_before_complete')->'request')='"rejected_no_such_upload"'::jsonb OR (((item->'semantics')->'put_before_complete')->'request')='"rejected_other"'::jsonb OR (((item->'semantics')->'put_before_complete')->'request')='"succeeds_without_selected_change"'::jsonb) AND ((((item->'semantics')->'put_before_complete')->'selected_object')='"unchanged"'::jsonb)) OR (jsonb_typeof(((item->'semantics')->'put_before_complete'))='object' AND ((item->'semantics')->'put_before_complete') ?& ARRAY['request','selected_object'] AND ((item->'semantics')->'put_before_complete')-ARRAY['request','selected_object']='{}'::jsonb AND ((((item->'semantics')->'put_before_complete')->'request')='"succeeds_with_selected_change"'::jsonb) AND ((((item->'semantics')->'put_before_complete')->'selected_object')='"changed"'::jsonb))) AND ((jsonb_typeof(((item->'semantics')->'overlap_same_number'))='object' AND ((item->'semantics')->'overlap_same_number') ?& ARRAY['request','selected_object'] AND ((item->'semantics')->'overlap_same_number')-ARRAY['request','selected_object']='{}'::jsonb AND ((((item->'semantics')->'overlap_same_number')->'request')='"rejected_no_such_upload"'::jsonb OR (((item->'semantics')->'overlap_same_number')->'request')='"rejected_other"'::jsonb OR (((item->'semantics')->'overlap_same_number')->'request')='"succeeds_without_selected_change"'::jsonb) AND ((((item->'semantics')->'overlap_same_number')->'selected_object')='"unchanged"'::jsonb)) OR (jsonb_typeof(((item->'semantics')->'overlap_same_number'))='object' AND ((item->'semantics')->'overlap_same_number') ?& ARRAY['request','selected_object'] AND ((item->'semantics')->'overlap_same_number')-ARRAY['request','selected_object']='{}'::jsonb AND ((((item->'semantics')->'overlap_same_number')->'request')='"succeeds_with_selected_change"'::jsonb) AND ((((item->'semantics')->'overlap_same_number')->'selected_object')='"changed"'::jsonb)))) AND (NOT (jsonb_typeof((item->'semantics'))='object' AND (item->'semantics') ?& ARRAY['complete_before_put','put_before_complete','overlap_same_number'] AND (item->'semantics')-ARRAY['complete_before_put','put_before_complete','overlap_same_number']='{}'::jsonb AND (jsonb_typeof(((item->'semantics')->'complete_before_put'))='object' AND ((item->'semantics')->'complete_before_put') ?& ARRAY['request','selected_object'] AND ((item->'semantics')->'complete_before_put')-ARRAY['request','selected_object']='{}'::jsonb AND ((((item->'semantics')->'complete_before_put')->'request')='"rejected_no_such_upload"'::jsonb OR (((item->'semantics')->'complete_before_put')->'request')='"rejected_other"'::jsonb OR (((item->'semantics')->'complete_before_put')->'request')='"succeeds_without_selected_change"'::jsonb) AND ((((item->'semantics')->'complete_before_put')->'selected_object')='"unchanged"'::jsonb)) AND (jsonb_typeof(((item->'semantics')->'put_before_complete'))='object' AND ((item->'semantics')->'put_before_complete') ?& ARRAY['request','selected_object'] AND ((item->'semantics')->'put_before_complete')-ARRAY['request','selected_object']='{}'::jsonb AND ((((item->'semantics')->'put_before_complete')->'request')='"rejected_no_such_upload"'::jsonb OR (((item->'semantics')->'put_before_complete')->'request')='"rejected_other"'::jsonb OR (((item->'semantics')->'put_before_complete')->'request')='"succeeds_without_selected_change"'::jsonb) AND ((((item->'semantics')->'put_before_complete')->'selected_object')='"unchanged"'::jsonb)) AND (jsonb_typeof(((item->'semantics')->'overlap_same_number'))='object' AND ((item->'semantics')->'overlap_same_number') ?& ARRAY['request','selected_object'] AND ((item->'semantics')->'overlap_same_number')-ARRAY['request','selected_object']='{}'::jsonb AND ((((item->'semantics')->'overlap_same_number')->'request')='"rejected_no_such_upload"'::jsonb OR (((item->'semantics')->'overlap_same_number')->'request')='"rejected_other"'::jsonb OR (((item->'semantics')->'overlap_same_number')->'request')='"succeeds_without_selected_change"'::jsonb) AND ((((item->'semantics')->'overlap_same_number')->'selected_object')='"unchanged"'::jsonb))))))))) IS NOT TRUE) THEN
    RAISE EXCEPTION 'Capability status and outcomes inconsistent' USING ERRCODE='23514'; END IF;
  END LOOP;
 ELSE
  SELECT * INTO ev FROM public.storage_capability_evidence WHERE id=NEW.evidence_id AND
    org_id=NEW.org_id;
  IF ev.id IS NULL THEN RAISE EXCEPTION 'Capability owner unavailable' USING ERRCODE='23514'; END IF;
  PERFORM pg_advisory_xact_lock(1447977558,hashtext(NEW.evidence_id));
  IF TG_TABLE_NAME='storage_capability_qualifications' THEN
   IF ev.facts->'schema' IS DISTINCT FROM '2'::jsonb OR ((jsonb_typeof(NEW.approval)='object' AND
    NEW.approval ?& ARRAY['schema','evidence_schema','evidence_revision','evidence_sha256','dependency_policy_revision','validity_policy_revision','reviewer','reference','approved_utc'] AND
    NEW.approval-ARRAY['schema','evidence_schema','evidence_revision','evidence_sha256','dependency_policy_revision','validity_policy_revision','reviewer','reference','approved_utc']='{}'::jsonb AND
    ((NEW.approval->'schema')='2'::jsonb AND NEW.approval->>'schema'='2') AND
    ((NEW.approval->'evidence_schema')='2'::jsonb AND NEW.approval->>'evidence_schema'='2') AND
    (CASE WHEN jsonb_typeof((NEW.approval->'evidence_revision'))='number' THEN ((NEW.approval->'evidence_revision')#>>'{}')::numeric BETWEEN 1 AND
    9223372036854775807 AND
    ((NEW.approval->'evidence_revision')#>>'{}')::numeric=trunc(((NEW.approval->'evidence_revision')#>>'{}')::numeric) ELSE false END) AND
    (jsonb_typeof((NEW.approval->'evidence_sha256'))='string' AND
    octet_length((NEW.approval->'evidence_sha256')#>>'{}') BETWEEN 64 AND
    64 AND
    ((NEW.approval->'evidence_sha256')#>>'{}') ~ '^[0-9a-f]{64}$') AND
    ((NEW.approval->'dependency_policy_revision')='"unmounted-custody/2"'::jsonb) AND
    ((NEW.approval->'validity_policy_revision')='"unmounted-fixture-86400s/1"'::jsonb) AND
    (jsonb_typeof((NEW.approval->'reviewer'))='string' AND
    octet_length((NEW.approval->'reviewer')#>>'{}') BETWEEN 1 AND
    2048) AND
    (jsonb_typeof((NEW.approval->'reference'))='string' AND
    octet_length((NEW.approval->'reference')#>>'{}') BETWEEN 1 AND
    2048) AND
    (jsonb_typeof((NEW.approval->'approved_utc'))='string' AND
    octet_length((NEW.approval->'approved_utc')#>>'{}') BETWEEN 27 AND
    27 AND
    ((NEW.approval->'approved_utc')#>>'{}') ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z$'))) IS NOT TRUE
    OR NEW.approval->>'evidence_sha256' IS DISTINCT FROM ev.sha256
    OR NEW.approval->'evidence_revision' IS DISTINCT FROM to_jsonb(ev.revision)
    OR NEW.approval->>'evidence_revision' !~ '^[0-9]+$'
    OR ((((NEW.operation='create' AND
    ev.facts->'behaviors'->'mpu_create'->>'status'='enforced' AND
    ev.facts->'behaviors'->'mpu_create'->'semantics' @> '{"key_binding": "exact", "upload_id_attribution": "response"}'::jsonb) OR (NEW.operation='part_sign' AND
    ev.facts->'behaviors'->'upload_part'->>'status'='enforced' AND
    ev.facts->'behaviors'->'upload_part'->'semantics' @> '{"upload_part_binding": "exact", "acknowledgment": "etag"}'::jsonb) OR (NEW.operation='complete' AND
    ev.facts->'behaviors'->'complete_manifest'->>'status'='enforced' AND
    ev.facts->'behaviors'->'complete_manifest'->'semantics' @> '{"selection": "explicit_etags", "stale_etag": "refuses", "embedded_error": "parsed", "result_identity": "exact_key"}'::jsonb AND
    ev.facts->'behaviors'->'upload_part'->>'status'='enforced' AND
    ev.facts->'behaviors'->'upload_part'->'semantics' @> '{"upload_part_binding": "exact", "acknowledgment": "etag"}'::jsonb) OR (NEW.operation='head' AND
    ev.facts->'behaviors'->'head_identity'->>'status'='enforced' AND
    ev.facts->'behaviors'->'head_identity'->'semantics' @> '{"key_binding": "exact", "fields": "metadata_length", "missing": "not_found"}'::jsonb) OR (NEW.operation='list_parts' AND
    ev.facts->'behaviors'->'list_parts'->>'status'='enforced' AND
    ev.facts->'behaviors'->'list_parts'->'semantics' @> '{"pagination": "monotonic_marker", "unfinished": "omitted", "fields": "etag_size_checksum_optional"}'::jsonb)) AND
    (NEW.operation NOT IN ('complete','head') OR (ev.facts->'behaviors'->'checksum'->>'status'<>'unestablished' AND
    (CASE WHEN NEW.operation='complete' THEN ev.facts->'behaviors'->'complete_preconditions'->>'status' ELSE ev.facts->'behaviors'->'version_readback'->>'status' END)<>'unestablished' AND
    (ev.facts->>'profile'<>'checksum-enforced/1' OR (ev.facts->'behaviors'->'checksum'->>'status'='enforced' AND
    ev.facts->'behaviors'->'checksum'->'semantics'='{"algorithm": "sha256", "checksum_type": "composite", "assurance": "enforced", "mismatch": "refuses"}'::jsonb)))))) IS NOT TRUE THEN
    RAISE EXCEPTION 'Explicit operation qualification invalid' USING ERRCODE='23514'; END IF;
   ts:=(NEW.approval->>'approved_utc')::timestamptz;
   IF to_char(ts AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') IS DISTINCT FROM NEW.approval->>'approved_utc' THEN
    RAISE EXCEPTION 'Approval timestamp noncanonical' USING ERRCODE='23514'; END IF;
   IF ts<(ev.facts->'observation'->>'completed_at_utc')::timestamptz OR ts>clock_timestamp() THEN
    RAISE EXCEPTION 'Approval time invalid' USING ERRCODE='23514'; END IF;
  ELSIF (NEW.operation IN ('all','create','part_sign','complete','head','list_parts','normal_publication','uncertain_recovery')) IS NOT TRUE OR octet_length(NEW.reason) NOT BETWEEN 1 AND
    2048 THEN
   RAISE EXCEPTION 'Revocation invalid' USING ERRCODE='23514'; END IF;
 END IF;
 RETURN NEW;
 EXCEPTION WHEN invalid_datetime_format OR datetime_field_overflow THEN
 RAISE EXCEPTION 'Capability timestamp invalid' USING ERRCODE='23514';
END $$"""

GUARD = r"""CREATE OR REPLACE FUNCTION vnbui_capability_effect() RETURNS trigger
LANGUAGE plpgsql VOLATILE SET search_path=pg_catalog,public AS $$
DECLARE pub public.s3_publications; doc jsonb; plan jsonb; ref jsonb;
 ev public.storage_capability_evidence; operations text[]:='{}'; selected_operation text; entry record; expected_ref jsonb; admission_now timestamptz;
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
   OR jsonb_typeof(ref) IS DISTINCT FROM 'object' OR (plan->'evidence_schema' IN ('1'::jsonb,'2'::jsonb)) IS NOT TRUE THEN
   RAISE EXCEPTION 'Committed capability evidence required' USING ERRCODE='23514'; END IF;
 SELECT * INTO ev FROM public.storage_capability_evidence WHERE id=ref->>'id' AND org_id=pub.org_id;
 expected_ref:=jsonb_build_object('id',ev.id,'revision',ev.revision,'sha256',ev.sha256,'adapter',ev.facts->'adapter','wire',ev.facts->'wire');
 IF ev.facts->'schema'='2'::jsonb THEN expected_ref:=expected_ref || '{"schema": 2}'::jsonb; END IF;
 IF ev.id IS NULL OR plan->>'evidence_schema' IS DISTINCT FROM ev.facts->>'schema' OR (ref ? 'schema' AND ref->>'schema'<>'2') OR ref IS DISTINCT FROM expected_ref
   OR ev.facts->'profile' IS DISTINCT FROM plan->'capability_profile'
   OR ev.facts->'target' IS DISTINCT FROM plan->'target'
   OR pub.endpoint IS DISTINCT FROM plan->'target'->>'endpoint' OR pub.bucket IS DISTINCT FROM plan->'target'->>'bucket' THEN
   RAISE EXCEPTION 'Capability evidence binding differs' USING ERRCODE='23514'; END IF;
 -- Persist-only custody may arrive after expiry/revocation. Its immutable bound
 -- still applies; this is not a new qualification or permission to deliver.
 IF TG_TABLE_NAME='s3_upload_parts' AND TG_OP='UPDATE' AND ev.facts->'schema'='2'::jsonb THEN
   IF NEW.signing_result IS DISTINCT FROM OLD.signing_result THEN
     IF jsonb_typeof(NEW.signing_result->'expires_at') IS DISTINCT FROM 'number'
       OR (NEW.signing_result->>'expires_at' ~ '^[0-9]{1,12}$') IS NOT TRUE THEN
       RAISE EXCEPTION 'Part signing evidence deadline invalid' USING ERRCODE='23514'; END IF;
     IF (NEW.signing_result->>'expires_at')::bigint >
       floor(extract(epoch FROM (ev.facts->'validity'->>'not_after_utc')::timestamptz)) THEN
       RAISE EXCEPTION 'Part signing exceeds evidence deadline' USING ERRCODE='23514'; END IF;
   END IF;
 END IF;
 IF TG_TABLE_NAME='s3_publications' AND TG_OP='UPDATE' THEN
   IF jsonb_build_array(NEW.provider_control,NEW.prepared_receipt,NEW.finalize_intent,NEW.checkpoint_proof,NEW.state)
      IS DISTINCT FROM jsonb_build_array(OLD.provider_control,OLD.prepared_receipt,OLD.finalize_intent,OLD.checkpoint_proof,OLD.state) THEN
     RAISE EXCEPTION 'Qualified publication remains dormant' USING ERRCODE='23514'; END IF;
 END IF;
 IF cardinality(operations)>0 THEN
   IF ev.facts->'schema' IS DISTINCT FROM '2'::jsonb THEN RAISE EXCEPTION 'Schema 1 custody is read only' USING ERRCODE='23514'; END IF;
   IF current_setting('transaction_isolation')<>'read committed' THEN
     RAISE EXCEPTION 'Capability admission requires READ COMMITTED' USING ERRCODE='23514'; END IF;
   PERFORM pg_advisory_xact_lock(1447977558,hashtext(ev.id));
   FOREACH selected_operation IN ARRAY operations LOOP
     IF NOT EXISTS(SELECT 1 FROM public.storage_capability_qualifications q WHERE q.org_id=pub.org_id AND q.evidence_id=ev.id AND q.operation=selected_operation AND q.approval->>'dependency_policy_revision'='unmounted-custody/2' AND q.approval->>'validity_policy_revision'='unmounted-fixture-86400s/1')
       OR EXISTS(SELECT 1 FROM public.storage_capability_revocations r WHERE r.org_id=pub.org_id AND r.evidence_id=ev.id AND r.operation IN (selected_operation,'all')) THEN
       RAISE EXCEPTION 'Capability operation unqualified or revoked' USING ERRCODE='23514'; END IF;
   END LOOP;
   -- Fresh live clock AFTER lock and qualification/revocation read, never statement start.
   admission_now:=clock_timestamp();
   IF admission_now<(ev.facts->'validity'->>'not_before_utc')::timestamptz
      OR admission_now>=(ev.facts->'validity'->>'not_after_utc')::timestamptz THEN
     RAISE EXCEPTION 'Capability evidence outside validity window' USING ERRCODE='23514'; END IF;
 END IF;
 RETURN NEW;
END $$"""


def upgrade():
    op.execute(REGISTRY)
    op.execute(GUARD)
    for name in ("vnbui_capability_registry", "vnbui_capability_effect"):
        op.execute(f"REVOKE ALL ON FUNCTION {name}() FROM PUBLIC")


def downgrade():
    raise RuntimeError("Capability custody requires reviewed disposition")
