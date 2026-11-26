"""Atomic DB-rooted generation selection after immutable S3 publication."""

from alembic import op
from alembic.script import ScriptDirectory
from sqlalchemy import text

revision = "storage_generation_publication"
down_revision = "installation_source"
branch_labels = None
depends_on = None

PUBLISH = r"""
CREATE FUNCTION public.vnbui_publish_storage_generation(
 generation text, caller_agent text, credential_kind text, credential_id text
) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,public SET row_security=on AS $$
DECLARE
 org text := nullif(current_setting('app.current_org',true),'');
 m public.s3_publications; p public.s3_publications; b public.backups;
 h public.storage_lineage_heads; previous public.s3_publications;
 ancestor public.storage_lineage_generations; existing public.storage_lineage_generations;
 a public.agents; u public.users; v public.vms;
 request jsonb; plan jsonb; manifest jsonb; entry jsonb; receipt jsonb;
 expected_members jsonb; parent jsonb; root text; root_hash text;
 expected_key text; total_bytes bigint;
BEGIN
 IF org IS NULL OR current_setting('app.platform_admin',true)='true'
   OR current_setting('app.demo',true)='true' THEN
  RAISE EXCEPTION 'Tenant publication context required' USING ERRCODE='23514'; END IF;
 PERFORM 1 FROM public.organizations WHERE id=org AND enabled=true FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'Publication organization unavailable' USING ERRCODE='23514'; END IF;
 SELECT * INTO m FROM public.s3_publications WHERE id=generation AND org_id=org;
 IF m.id IS NULL OR m.kind<>'chain_manifest' OR m.expected_plan->>'schema' IS DISTINCT FROM '4' THEN
  RAISE EXCEPTION 'Generation reservation unavailable' USING ERRCODE='23514'; END IF;
 SELECT * INTO b FROM public.backups WHERE id=m.backup_id AND org_id=org FOR UPDATE;
 SELECT * INTO v FROM public.vms WHERE id=b.vm_id AND org_id=org FOR UPDATE;
 SELECT * INTO h FROM public.storage_lineage_heads WHERE vm_id=v.id AND org_id=org FOR UPDATE;
 SELECT * INTO p FROM public.s3_publications WHERE backup_id=b.id AND org_id=org AND kind='payload' FOR UPDATE;
 SELECT * INTO m FROM public.s3_publications WHERE id=generation AND org_id=org FOR UPDATE;
 request:=p.expected_plan::jsonb->'transaction'; plan:=request->'plan'; parent:=plan->'parent';
 SELECT * INTO a FROM public.agents WHERE id=caller_agent AND org_id=org FOR UPDATE;
 IF b.id IS NULL OR v.id IS NULL OR p.id IS NULL OR a.id IS NULL
   OR request->>'agent_id' IS DISTINCT FROM caller_agent OR a.id IS DISTINCT FROM v.agent_id THEN
  RAISE EXCEPTION 'Publication source owner unavailable' USING ERRCODE='23514'; END IF;
 IF credential_kind='api-key' THEN
  IF credential_id IS NULL OR credential_id='' OR credential_id IS DISTINCT FROM a.api_key_hash THEN
   RAISE EXCEPTION 'Publication credential unavailable' USING ERRCODE='23514'; END IF;
 ELSE
  RAISE EXCEPTION 'Publication requires authenticated agent key' USING ERRCODE='23514';
 END IF;
 SELECT * INTO existing FROM public.storage_lineage_generations WHERE id=generation AND org_id=org;
 IF existing.id IS NOT NULL THEN
  IF b.status<>'completed' OR existing.backup_id<>b.id OR p.state<>'published' OR m.state<>'published' THEN
   RAISE EXCEPTION 'Conflicting accepted generation' USING ERRCODE='23514'; END IF;
  RETURN jsonb_build_object('intent_id',p.finalize_intent->>'intent_id','status','completed',
    'completed',true,'generation_id',generation);
 END IF;
 SELECT * INTO u FROM public.users WHERE id=b.initiating_user_id AND org_id=org FOR UPDATE;
 IF b.authority_kind IS DISTINCT FROM 'human' OR u.id IS NULL OR u.is_active IS DISTINCT FROM true
   OR u.role NOT IN ('admin','operator') OR b.status NOT IN ('pending','running')
   OR v.inventory_present IS DISTINCT FROM true OR v.provider IS DISTINCT FROM 'kubevirt'
   OR a.status IS DISTINCT FROM 'online'
   OR plan->>'provider' IS DISTINCT FROM 'kubevirt'
   OR plan->>'capability_profile' IS DISTINCT FROM 'db-rooted-consumer-verified/1'
   OR plan ? 'capability_evidence'
   OR request->>'org_id' IS DISTINCT FROM org OR request->>'backup_id' IS DISTINCT FROM b.id
   OR request->>'reservation_id' IS DISTINCT FROM p.id OR p.dispatch_token IS NULL
   OR plan->'source'->>'vm_id' IS DISTINCT FROM v.id
   OR plan->'source'->>'vm_uid' IS DISTINCT FROM v.vm_uid
   OR plan->'source'->>'vmi_uid' IS DISTINCT FROM v.vmi_uid
   OR plan->'source'->>'namespace' IS DISTINCT FROM v.namespace
   OR p.state<>'reserved' OR m.state<>'reserved'
   OR p.checkpoint_proof IS NULL OR p.checkpoint_transaction_id IS NULL
   OR p.checkpoint_transaction_id=txid_current()
   OR p.prepared_receipt::jsonb->'response'->'accepted' IS DISTINCT FROM 'true'::jsonb
   OR m.prepared_receipt IS NULL OR m.receipt_transaction_id IS NULL
   OR m.receipt_transaction_id=txid_current() THEN
  RAISE EXCEPTION 'Generation publication prerequisites unavailable' USING ERRCODE='23514'; END IF;
 manifest:=(m.expected_plan->>'manifest_canonical')::jsonb;
 receipt:=m.prepared_receipt::jsonb->'receipt';
 IF octet_length(m.expected_plan->>'manifest_canonical')>16777216
   OR m.expected_plan->>'generation_id' IS DISTINCT FROM generation
   OR manifest->>'generation_id' IS DISTINCT FROM generation
   OR manifest->>'protocol' IS DISTINCT FROM 'vnbui-storage-generation/1'
   OR manifest->>'org_id' IS DISTINCT FROM org
   OR manifest->>'backup_id' IS DISTINCT FROM b.id
   OR manifest->>'installation_id' IS DISTINCT FROM (SELECT installation_id FROM public.storage_configuration_clock WHERE slot=1)
   OR manifest->'source' IS DISTINCT FROM plan->'source'
   OR manifest->'target' IS DISTINCT FROM plan->'target'
   OR manifest->>'predecessor_id' IS DISTINCT FROM h.generation_id
   OR m.expected_plan->>'predecessor_id' IS DISTINCT FROM h.generation_id
   OR m.expected_plan->>'manifest_sha256' IS DISTINCT FROM encode(sha256(convert_to(m.expected_plan->>'manifest_canonical','UTF8')),'hex')
   OR jsonb_typeof(manifest->'members') IS DISTINCT FROM 'array'
   OR jsonb_array_length(manifest->'members') NOT BETWEEN 1 AND 256
   OR (m.prepared_receipt->>'receipt_canonical')::jsonb IS DISTINCT FROM receipt
   OR m.prepared_receipt->>'receipt_sha256' IS DISTINCT FROM encode(sha256(convert_to(m.prepared_receipt->>'receipt_canonical','UTF8')),'hex') THEN
  RAISE EXCEPTION 'Generation manifest or predecessor changed' USING ERRCODE='23514'; END IF;
 root:=CASE WHEN parent='null'::jsonb THEN b.id ELSE parent->>'root_backup_id' END;
 expected_key:='vnbui-owned/v1/'||encode(sha256(convert_to(org,'UTF8')),'hex')||'/'||
   encode(sha256(convert_to(root,'UTF8')),'hex')||'/generations/'||generation||'.json';
 IF root IS NULL OR manifest->>'root_backup_id' IS DISTINCT FROM root
   OR m.object_key IS DISTINCT FROM expected_key OR m.endpoint IS DISTINCT FROM p.endpoint
   OR m.bucket IS DISTINCT FROM p.bucket
   OR receipt IS DISTINCT FROM jsonb_build_object('schema',1,'generation_id',generation,
      'endpoint',m.endpoint,'bucket',m.bucket,'key',m.object_key,
      'version_id',receipt->'version_id','etag',receipt->'etag',
      'bytes',octet_length(m.expected_plan->>'manifest_canonical'),
      'sha256',m.expected_plan->>'manifest_sha256','assurance','consumer_sha256_verified')
   OR receipt->>'etag' IS NULL OR length(receipt->>'etag')>1024
   OR receipt->>'etag' !~ '^"[^"\r\n]+"$' THEN
  RAISE EXCEPTION 'Generation object receipt differs' USING ERRCODE='23514'; END IF;
 entry:=jsonb_build_object('request',request,'receipt',p.prepared_receipt::jsonb->'receipt',
   'receipt_sha256',p.prepared_receipt->>'receipt_sha256','acceptance',p.prepared_receipt::jsonb->'response',
   'wrapped_attempt_key',p.wrapped_attempt_key::jsonb,'checkpoint',p.finalize_intent::jsonb->'binding',
   'checkpoint_proof',p.checkpoint_proof::jsonb);
 expected_members:='[]'::jsonb;
 root_hash:=p.prepared_receipt->>'receipt_sha256';
 IF parent<>'null'::jsonb THEN
  SELECT * INTO ancestor FROM public.storage_lineage_generations WHERE id=parent->>'generation_id' AND org_id=org;
  SELECT * INTO previous FROM public.s3_publications WHERE id=ancestor.id AND org_id=org;
  IF ancestor.id IS NULL OR ancestor.id IS DISTINCT FROM h.generation_id OR h.state IS DISTINCT FROM 'current'
    OR ancestor.state IS DISTINCT FROM 'accepted' OR ancestor.vm_id IS DISTINCT FROM b.vm_id
    OR ancestor.backup_id IS DISTINCT FROM parent->>'backup_id'
    OR ancestor.root_backup_id IS DISTINCT FROM root
    OR ancestor.receipt_sha256 IS DISTINCT FROM parent->>'receipt_sha256'
    OR ancestor.tracker_uid IS DISTINCT FROM parent->>'tracker_uid'
    OR ancestor.checkpoint IS DISTINCT FROM parent->>'checkpoint'
    OR previous.state IS DISTINCT FROM 'published'
    OR NOT EXISTS(SELECT 1 FROM public.backups WHERE id=ancestor.backup_id AND org_id=org AND status='completed') THEN
   RAISE EXCEPTION 'Incremental generation no longer current' USING ERRCODE='23514'; END IF;
  expected_members:=(previous.expected_plan->>'manifest_canonical')::jsonb->'members';
  root_hash:=ancestor.root_receipt_sha256;
 END IF;
 IF manifest->'members' IS DISTINCT FROM expected_members||jsonb_build_array(entry) THEN
  RAISE EXCEPTION 'Generation members differ from accepted receipt ledger' USING ERRCODE='23514'; END IF;
 INSERT INTO public.storage_lineage_generations(id,org_id,vm_id,backup_id,root_backup_id,state,
    receipt_sha256,root_receipt_sha256,manifest_receipt_sha256,tracker_uid,checkpoint,accepted_request)
 VALUES(generation,org,b.vm_id,b.id,root,'accepted',p.prepared_receipt->>'receipt_sha256',root_hash,
    m.prepared_receipt->>'receipt_sha256',p.finalize_intent->'binding'->>'tracker_uid',
    p.checkpoint_proof->>'checkpoint',request);
 INSERT INTO public.storage_lineage_heads(vm_id,org_id,generation_id,state,manifest_receipt_sha256,root_backup_id,tracker_uid,checkpoint)
 VALUES(b.vm_id,org,generation,'current',m.prepared_receipt->>'receipt_sha256',root,
    p.finalize_intent->'binding'->>'tracker_uid',p.checkpoint_proof->>'checkpoint')
 ON CONFLICT(vm_id) DO UPDATE SET generation_id=EXCLUDED.generation_id,state=EXCLUDED.state,
    manifest_receipt_sha256=EXCLUDED.manifest_receipt_sha256,root_backup_id=EXCLUDED.root_backup_id,
    tracker_uid=EXCLUDED.tracker_uid,checkpoint=EXCLUDED.checkpoint;
 UPDATE public.s3_publications SET state='published' WHERE id IN (p.id,m.id) AND org_id=org;
 SELECT coalesce(sum((item->>'ciphertext_bytes')::bigint),0) INTO total_bytes
    FROM jsonb_array_elements(p.prepared_receipt::jsonb->'receipt'->'objects') item;
 UPDATE public.backups SET status='completed',progress=100,capacity_state='released',completed_at=timezone('UTC',clock_timestamp()),
    chain_id=root,parent_backup_id=CASE WHEN parent='null'::jsonb THEN NULL ELSE parent->>'backup_id' END,
    chain_position=jsonb_array_length(manifest->'members')-1,size_bytes=total_bytes,
    storage_path='s3://'||p.bucket||'/'||p.object_key,
    tags=coalesce(tags::jsonb,'{}'::jsonb)||jsonb_build_object('checkpoint_required',true,
      'checkpoint_committed',true,'generation_id',generation,
      'guest_consistency',p.checkpoint_proof->>'guest_consistency',
      'scrub_required',p.prepared_receipt::jsonb->'response'->'scrub_required')
 WHERE id=b.id AND org_id=org;
 RETURN jsonb_build_object('intent_id',p.finalize_intent->>'intent_id','status','completed',
    'completed',true,'generation_id',generation);
END $$;
REVOKE ALL ON FUNCTION public.vnbui_publish_storage_generation(text,text,text,text) FROM PUBLIC;
"""

COMPLETION = r"""
CREATE OR REPLACE FUNCTION public.vnbui_storage_completion_hold() RETURNS trigger
LANGUAGE plpgsql AS $$ BEGIN
 IF NEW.status='completed' AND OLD.status IS DISTINCT FROM NEW.status
  AND EXISTS(SELECT 1 FROM public.s3_publications p WHERE p.backup_id=NEW.id
    AND p.expected_plan->>'schema'='3' AND p.dispatch_token IS NOT NULL)
  AND NOT EXISTS(
   SELECT 1 FROM public.storage_lineage_generations g
    JOIN public.s3_publications p ON p.backup_id=g.backup_id AND p.kind='payload'
    JOIN public.s3_publications m ON m.id=g.id AND m.kind='chain_manifest'
    JOIN public.storage_lineage_heads h ON h.vm_id=g.vm_id AND h.generation_id=g.id
   WHERE g.backup_id=NEW.id AND g.org_id=NEW.org_id AND g.vm_id=NEW.vm_id
    AND g.state='accepted' AND h.state='current' AND h.org_id=g.org_id
    AND p.org_id=g.org_id AND m.org_id=g.org_id AND p.state='published' AND m.state='published'
    AND g.accepted_request=p.expected_plan::jsonb->'transaction'
    AND g.receipt_sha256=p.prepared_receipt->>'receipt_sha256'
    AND g.manifest_receipt_sha256=m.prepared_receipt->>'receipt_sha256') THEN
  RAISE EXCEPTION 'Transaction completion awaits generation publication acceptance' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
"""

CAPACITY_RELEASE = r"""
 IF OLD.capacity_state='reserved' AND NEW.capacity_state='released'
   AND NEW.status='completed' AND EXISTS(
    SELECT 1 FROM public.storage_lineage_generations publication_generation
    JOIN public.storage_lineage_heads publication_head ON publication_head.vm_id=publication_generation.vm_id AND publication_head.generation_id=publication_generation.id
    JOIN public.s3_publications publication_manifest ON publication_manifest.id=publication_generation.id
    JOIN public.s3_publications publication_payload ON publication_payload.backup_id=publication_generation.backup_id AND publication_payload.kind='payload'
    WHERE publication_generation.backup_id=OLD.id AND publication_generation.org_id=OLD.org_id AND publication_generation.vm_id=OLD.vm_id
      AND publication_generation.state='accepted' AND publication_head.state='current' AND publication_head.org_id=publication_generation.org_id
      AND publication_payload.org_id=publication_generation.org_id AND publication_manifest.org_id=publication_generation.org_id
      AND publication_payload.state='published' AND publication_manifest.state='published'
      AND publication_generation.manifest_receipt_sha256=publication_manifest.prepared_receipt->>'receipt_sha256') THEN
   PERFORM pg_advisory_xact_lock(1447977557,1);
   NEW.capacity_release:=jsonb_build_object('schema',1,'capacity_id',OLD.capacity_id,
     'reason','generation_committed','evidence_sha256',(
       SELECT publication_generation.manifest_receipt_sha256 FROM public.storage_lineage_generations publication_generation
       WHERE publication_generation.backup_id=OLD.id AND publication_generation.org_id=OLD.org_id),
     'released_at',to_char(clock_timestamp() AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'));
   RETURN NEW;
 END IF;
"""

OWNERSHIP_OLD = """encode(sha256(convert_to(NEW.backup_id, 'UTF8')), 'hex') || '/' ||
                CASE NEW.kind WHEN 'payload' THEN 'payload/' WHEN 'chain_manifest' THEN 'chain.json' END"""
OWNERSHIP_NEW = (
    """CASE WHEN NEW.kind='chain_manifest' AND NEW.expected_plan->>'schema'='4' THEN
                  encode(sha256(convert_to((NEW.expected_plan->>'manifest_canonical')::jsonb->>'root_backup_id', 'UTF8')), 'hex') ||
                  '/generations/' || NEW.id || '.json'
                ELSE """ + OWNERSHIP_OLD + " END"
)


def upgrade():
    op.execute(PUBLISH)
    op.execute(COMPLETION)
    predecessor = (
        ScriptDirectory.from_config(op.get_context().config)
        .get_revision("callback_provider_create")
        .module
    )
    sql = predecessor.OWNER
    # Preserve all subsequent effect-custody vetoes on never-effect release.
    for field in (
        "receipt_verification_intent",
        "attempt_key_preparation_intent",
        "attempt_key_disclosure_intent",
        "provider_create",
    ):
        assert field + " IS NOT NULL" in sql
    marker = " IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname=current_user AND (rolsuper OR rolbypassrls)) THEN"
    assert marker in sql
    op.execute(sql.replace(marker, CAPACITY_RELEASE + marker))
    ownership = op.get_bind().scalar(
        text(
            "SELECT pg_get_functiondef('public.vnbui_s3_publication_immutable()'::regprocedure)"
        )
    )
    assert OWNERSHIP_OLD in ownership
    op.execute(ownership.replace(OWNERSHIP_OLD, OWNERSHIP_NEW))


def downgrade():
    raise RuntimeError("Accepted storage generations require reviewed rollback")
