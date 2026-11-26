"""Complete current native push receipts through the existing atomic publisher."""

from alembic import op
from sqlalchemy import text

revision = "native_publication"
down_revision = "kubevirt_restore"
branch_labels = None
depends_on = None


NATIVE_CHECK = r"""
 IF plan->>'provider'='libvirt' THEN
  native_result:=b.native_inventory->'push_result';
  native_manifest:=native_result->'manifest';
  IF b.capacity_state IS DISTINCT FROM 'reserved'
    OR b.native_job_transaction_id IS NULL OR b.native_inventory_transaction_id IS NULL
    OR b.native_inventory_transaction_id=txid_current()
    OR b.native_inventory_transaction_id=b.native_job_transaction_id
    OR p.receipt_transaction_id IS NULL OR p.receipt_transaction_id=txid_current()
    OR b.native_job_intent->>'producer' IS DISTINCT FROM 'libvirt-push-qcow2/1'
    OR b.native_job_intent->>'backup_id' IS DISTINCT FROM b.id
    OR b.native_job_intent->>'org_id' IS DISTINCT FROM org
    OR b.native_job_intent->>'actor_id' IS DISTINCT FROM b.initiating_user_id
    OR b.native_job_intent->>'agent_id' IS DISTINCT FROM a.id
    OR b.native_job_intent->>'attempt_id' IS DISTINCT FROM p.id
    OR b.native_job_intent->>'checkpoint' IS DISTINCT FROM 'vnbui-'||p.id
    OR b.native_job_intent->'parent' IS DISTINCT FROM parent
    OR b.native_job_intent->'encryption' IS DISTINCT FROM plan->'encryption'
    OR b.native_job_intent->'target' IS DISTINCT FROM jsonb_build_object(
       'endpoint',plan->'target'->'endpoint','bucket',plan->'target'->'bucket',
       'region',plan->'target'->'region','prefix',plan->'target'->'configuration_prefix',
       'capability_profile',plan->'capability_profile')
    OR b.native_job_intent->'source'->>'backup_type' IS DISTINCT FROM plan->>'backup_type'
    OR plan->>'backup_type' IS DISTINCT FROM b.backup_type
    OR (plan->>'backup_type' IN ('full','incremental')) IS NOT TRUE
    OR (plan->>'backup_type'='full') IS DISTINCT FROM (parent='null'::jsonb)
    OR plan->'source'->>'representation' IS DISTINCT FROM 'libvirt-native-fileset/1'
    OR plan->'source'->>'agent_id' IS DISTINCT FROM a.id
    OR plan->'source'->'inventory' IS DISTINCT FROM b.native_inventory->'inventory'
    OR plan->'source'->>'inventory_sha256' IS DISTINCT FROM b.native_inventory->>'inventory_sha256'
    OR plan->'source'->'inventory'->>'domain_uuid' IS DISTINCT FROM v.uuid
    OR v.vm_uid IS DISTINCT FROM v.uuid
    OR b.native_job_intent->'source'->>'domain_uuid' IS DISTINCT FROM v.uuid
    OR b.native_job_intent->'source'->>'vm_id' IS DISTINCT FROM v.id
    OR b.native_job_intent->'source'->>'agent_id' IS DISTINCT FROM a.id
    OR b.native_job_intent->'source'->'disks' IS DISTINCT FROM
       (SELECT jsonb_agg(d ORDER BY d->>'target') FROM jsonb_array_elements(v.disks::jsonb) d)
    OR b.native_job_intent->'source'->'exclusions' IS DISTINCT FROM plan->'exclusions'
    OR plan->'exclusions' IS DISTINCT FROM (SELECT coalesce(jsonb_agg(x ORDER BY x),'[]'::jsonb) FROM jsonb_array_elements(b.exclude_disks::jsonb) x)
    OR b.native_inventory->'closed_job'->>'state' IS DISTINCT FROM 'exited'
    OR b.native_inventory->'closed_job'->>'exit_code' IS DISTINCT FROM '0'
    OR b.native_inventory->'closed_job'->>'job_id' IS DISTINCT FROM 'vnbui-native-'||p.id
    OR b.native_inventory->'closed_job'->>'attempt_id' IS DISTINCT FROM p.id
    OR (b.native_inventory->'closed_job'->>'invocation_id' ~ '^[0-9a-f]{32}$') IS NOT TRUE
    OR native_manifest->>'schema' IS DISTINCT FROM 'libvirt-push-qcow2/1'
    OR native_manifest->>'backup_id' IS DISTINCT FROM b.id
    OR native_manifest->>'attempt_id' IS DISTINCT FROM p.id
    OR native_manifest->>'domain_uuid' IS DISTINCT FROM v.uuid
    OR native_manifest->>'checkpoint' IS DISTINCT FROM 'vnbui-'||p.id
    OR native_manifest->'source' IS DISTINCT FROM b.native_job_intent->'source'->'disks'
    OR native_manifest->'exclusions' IS DISTINCT FROM plan->'exclusions'
    OR native_manifest IS DISTINCT FROM (b.native_inventory->>'push_manifest_canonical')::jsonb
    OR native_result->>'manifest_sha256' IS DISTINCT FROM
       encode(sha256(convert_to(b.native_inventory->>'push_manifest_canonical','UTF8')),'hex')
    OR native_manifest->>'parent_backup_id' IS DISTINCT FROM parent->>'backup_id'
    OR native_manifest->>'parent_manifest_sha256' IS DISTINCT FROM b.native_job_intent->'push_parent'->>'manifest_sha256'
    OR jsonb_array_length(plan->'source'->'inventory'->'files') IS DISTINCT FROM jsonb_array_length(native_manifest->'disks')+3
    OR jsonb_array_length(p.prepared_receipt::jsonb->'receipt'->'objects') IS DISTINCT FROM jsonb_array_length(plan->'artifacts')
    OR jsonb_array_length(plan->'artifacts') IS DISTINCT FROM jsonb_array_length(plan->'source'->'inventory'->'files') THEN
   RAISE EXCEPTION 'Native producer binding differs' USING ERRCODE='23514'; END IF;
  FOR native_file IN SELECT * FROM jsonb_array_elements(plan->'source'->'inventory'->'files') LOOP
   SELECT count(*) INTO native_count FROM jsonb_array_elements(p.prepared_receipt::jsonb->'receipt'->'objects') x
     WHERE x->>'artifact_id'=native_file->>'artifact_id';
   SELECT x INTO native_object FROM jsonb_array_elements(p.prepared_receipt::jsonb->'receipt'->'objects') x
     WHERE x->>'artifact_id'=native_file->>'artifact_id';
   SELECT x INTO native_artifact FROM jsonb_array_elements(plan->'artifacts') x
     WHERE x->>'artifact_id'=native_file->>'artifact_id';
   native_hash:=CASE native_file->>'role'
     WHEN 'backup_metadata' THEN native_result->>'manifest_sha256'
     WHEN 'domain_config' THEN native_manifest->>'domain_xml_sha256'
     WHEN 'checkpoint' THEN native_manifest->>'checkpoint_sha256'
     WHEN 'disk_payload' THEN (SELECT x->>'sha256' FROM jsonb_array_elements(native_manifest->'disks') x WHERE x->>'target'=native_file->>'disk_id')
     ELSE NULL END;
   IF native_count<>1 OR native_artifact IS NULL OR native_hash IS NULL OR native_hash !~ '^[0-9a-f]{64}$'
     OR native_object->>'plaintext_sha256' IS DISTINCT FROM native_hash
     OR native_object->>'plaintext_bytes' IS DISTINCT FROM native_file->>'size'
     OR native_object->>'key' IS DISTINCT FROM native_artifact->>'key'
     OR native_object->>'role' IS DISTINCT FROM native_file->>'role'
     OR native_object->'disk_id' IS DISTINCT FROM native_file->'disk_id'
     OR native_file->>'member_backup_id' IS DISTINCT FROM b.id
     OR native_file->>'member_checkpoint' IS DISTINCT FROM 'vnbui-'||p.id
     OR (native_file->>'role'='disk_payload' AND (
       native_file->>'path' IS DISTINCT FROM native_file->>'disk_id'||'.qcow2'
       OR native_file->>'size' IS DISTINCT FROM (SELECT x->>'size_bytes' FROM jsonb_array_elements(native_manifest->'disks') x WHERE x->>'target'=native_file->>'disk_id')))
     OR (native_file->>'role'<>'disk_payload' AND (native_file->'disk_id'<>'null'::jsonb OR
       native_file->>'path' IS DISTINCT FROM CASE native_file->>'role' WHEN 'backup_metadata' THEN 'manifest.json' WHEN 'domain_config' THEN 'domain.xml' WHEN 'checkpoint' THEN 'checkpoint.xml' END)) THEN
    RAISE EXCEPTION 'Native uploaded plaintext differs from sealed producer' USING ERRCODE='23514'; END IF;
  END LOOP;
 END IF;
"""


def definition(signature):
    return op.get_bind().scalar(
        text("SELECT pg_get_functiondef(CAST(:signature AS regprocedure))"),
        {"signature": signature},
    )


def replace(sql, old, new):
    assert old in sql, old
    return sql.replace(old, new)


def upgrade():
    sql = definition("public.vnbui_publish_storage_generation(text,text,text,text)")
    sql = replace(
        sql,
        " expected_key text; total_bytes bigint;",
        " expected_key text; total_bytes bigint; native_result jsonb; native_manifest jsonb; native_file jsonb; native_object jsonb; native_artifact jsonb; native_hash text; native_count bigint;",
    )
    sql = replace(
        sql,
        "OR v.provider IS DISTINCT FROM 'kubevirt'",
        "OR (v.provider IN ('kubevirt','libvirt')) IS NOT TRUE",
    )
    sql = replace(
        sql,
        "OR plan->>'provider' IS DISTINCT FROM 'kubevirt'",
        "OR plan->>'provider' IS DISTINCT FROM v.provider",
    )
    sql = replace(
        sql,
        "   OR plan->'source'->>'vm_uid' IS DISTINCT FROM v.vm_uid\n   OR plan->'source'->>'vmi_uid' IS DISTINCT FROM v.vmi_uid\n   OR plan->'source'->>'namespace' IS DISTINCT FROM v.namespace",
        "   OR (plan->>'provider'='kubevirt' AND (plan->'source'->>'vm_uid' IS DISTINCT FROM v.vm_uid\n   OR plan->'source'->>'vmi_uid' IS DISTINCT FROM v.vmi_uid\n   OR plan->'source'->>'namespace' IS DISTINCT FROM v.namespace))",
    )
    sql = replace(
        sql,
        "   OR p.checkpoint_proof IS NULL OR p.checkpoint_transaction_id IS NULL\n   OR p.checkpoint_transaction_id=txid_current()",
        "   OR (plan->>'provider'='kubevirt' AND (p.checkpoint_proof IS NULL OR p.checkpoint_transaction_id IS NULL\n   OR p.checkpoint_transaction_id=txid_current()))",
    )
    sql = replace(
        sql,
        " manifest:=(m.expected_plan->>'manifest_canonical')::jsonb;",
        NATIVE_CHECK + "\n manifest:=(m.expected_plan->>'manifest_canonical')::jsonb;",
    )
    sql = replace(
        sql,
        "   'checkpoint_proof',p.checkpoint_proof::jsonb);",
        "   'checkpoint_proof',p.checkpoint_proof::jsonb);\n IF plan->>'provider'='libvirt' THEN\n  entry:=entry||jsonb_build_object('checkpoint',NULL,'checkpoint_proof',NULL,'native_result',native_result);\n END IF;",
    )
    sql = replace(
        sql,
        "  expected_members:=(previous.expected_plan->>'manifest_canonical')::jsonb->'members';",
        """  expected_members:=(previous.expected_plan->>'manifest_canonical')::jsonb->'members';
  IF plan->>'provider'='libvirt' AND b.native_job_intent->'push_parent' IS DISTINCT FROM (expected_members->-1)->'native_result' THEN
   RAISE EXCEPTION 'Native producer parent differs from accepted generation' USING ERRCODE='23514'; END IF;""",
    )
    sql = sql.replace(
        "p.finalize_intent->'binding'->>'tracker_uid'",
        "CASE WHEN plan->>'provider'='libvirt' THEN native_manifest->>'domain_uuid' ELSE p.finalize_intent->'binding'->>'tracker_uid' END",
    )
    sql = sql.replace(
        "p.checkpoint_proof->>'checkpoint'",
        "CASE WHEN plan->>'provider'='libvirt' THEN native_manifest->>'checkpoint' ELSE p.checkpoint_proof->>'checkpoint' END",
    )
    sql = sql.replace(
        "p.finalize_intent->>'intent_id'",
        "CASE WHEN plan->>'provider'='libvirt' THEN p.id ELSE p.finalize_intent->>'intent_id' END",
    )
    sql = sql.replace(
        "p.checkpoint_proof->>'guest_consistency'",
        "CASE WHEN plan->>'provider'='libvirt' THEN 'crash-consistent' ELSE p.checkpoint_proof->>'guest_consistency' END",
    )
    op.execute(sql)
    native = definition("public.vnbui_native_inventory()")
    native = replace(
        native,
        "OR OLD.initiating_user_id IS NULL OR NEW.status NOT IN ('pending','running')",
        "OR (OLD.authority_kind IN ('human','scheduler')) IS NOT TRUE OR NEW.status NOT IN ('pending','running')",
    )
    native = replace(
        native,
        "      IF NEW.native_job_intent IS DISTINCT FROM OLD.native_job_intent THEN",
        """      IF ROW(NEW.native_job_intent,NEW.native_inventory) IS DISTINCT FROM
          ROW(OLD.native_job_intent,OLD.native_inventory) AND OLD.authority_kind='scheduler' THEN
        IF NULLIF(current_setting('app.user_id',true),'') IS NOT NULL OR NOT EXISTS(
          SELECT 1 FROM public.schedule_occurrences c
          JOIN public.organizations o ON o.id=c.org_id AND o.enabled=true
          JOIN public.schedules s ON s.id=c.schedule_id AND s.org_id=c.org_id
          JOIN public.scheduler_grants g ON g.id=c.grant_id AND g.org_id=c.org_id
          JOIN public.schedule_occurrence_members member ON member.occurrence_id=c.id
           AND member.org_id=c.org_id AND member.vm_id=OLD.vm_id
          JOIN public.backup_queue q ON q.scheduler_occurrence_id=c.id
           AND q.started_backup_id=OLD.id AND q.vm_id=OLD.vm_id
          WHERE c.id=OLD.scheduler_occurrence_id AND c.org_id=OLD.org_id
           AND g.state='active' AND g.org_epoch=o.scheduler_epoch
           AND g.schedule_id=s.id AND s.current_grant_id=g.id AND s.retired_at IS NULL
           AND s.authority_revision=g.schedule_revision AND c.schedule_revision=g.schedule_revision
           AND q.status='claimed' AND q.authority_kind='scheduler') THEN
          RAISE EXCEPTION 'Native original scheduler unavailable' USING ERRCODE='23514';
        END IF;
      END IF;
      IF NEW.native_job_intent IS DISTINCT FROM OLD.native_job_intent THEN""",
    )
    native = replace(
        native,
        "AND OLD.native_job_intent IS NOT NULL THEN",
        """AND OLD.native_job_intent IS NOT NULL AND NOT EXISTS(
          SELECT 1 FROM public.storage_lineage_generations g
          JOIN public.s3_publications p ON p.backup_id=g.backup_id AND p.kind='payload'
          JOIN public.s3_publications m ON m.id=g.id AND m.kind='chain_manifest'
          JOIN public.storage_lineage_heads h ON h.vm_id=g.vm_id AND h.generation_id=g.id
          WHERE g.backup_id=NEW.id AND g.org_id=NEW.org_id AND g.vm_id=NEW.vm_id
           AND g.state='accepted' AND h.state='current' AND p.state='published' AND m.state='published'
           AND p.org_id=g.org_id AND m.org_id=g.org_id AND h.org_id=g.org_id
           AND g.accepted_request=p.expected_plan::jsonb->'transaction'
           AND g.receipt_sha256=p.prepared_receipt->>'receipt_sha256'
           AND g.manifest_receipt_sha256=m.prepared_receipt->>'receipt_sha256') THEN""",
    )
    op.execute(native)
    finalize = definition("public.vnbui_storage_finalize()")
    finalize = replace(
        finalize,
        "AND OLD.expected_plan->>'schema'='3'\n        AND (OLD.checkpoint_proof",
        """AND OLD.expected_plan->>'schema'='3'
        AND NOT (OLD.expected_plan->'transaction'->'plan'->>'provider'='libvirt' AND EXISTS(
          SELECT 1 FROM public.storage_lineage_generations g
          WHERE g.backup_id=OLD.backup_id AND g.org_id=OLD.org_id AND g.state='accepted'
           AND g.accepted_request=OLD.expected_plan::jsonb->'transaction'
           AND g.receipt_sha256=OLD.prepared_receipt->>'receipt_sha256'))
        AND (OLD.checkpoint_proof""",
    )
    op.execute(finalize)


def downgrade():
    raise RuntimeError("Native accepted generations require reviewed rollback")
