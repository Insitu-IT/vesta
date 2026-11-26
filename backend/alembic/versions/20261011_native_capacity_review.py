"""Permit owner-reviewed retirement of closed native upload holds.

No row is released by this migration. The existing exact review envelope,
maintenance, unpublished storage, no-lineage and owner-only rules remain.
Pre-capture/unknown native jobs are intentionally not reclassified here.
"""

from alembic import op
from alembic.script import ScriptDirectory

revision = "native_capacity_review"
down_revision = "kek_export_custody"
branch_labels = None
depends_on = None

OLD_ADMISSION = """     OR b.native_job_intent IS NOT NULL OR b.native_inventory IS NOT NULL
     OR NOT EXISTS(SELECT 1 FROM public.vms WHERE id=b.vm_id AND org_id=b.org_id
       AND provider='kubevirt')"""
NEW_ADMISSION = """     OR NOT (
       (b.native_job_intent IS NULL AND b.native_inventory IS NULL
        AND EXISTS(SELECT 1 FROM public.vms WHERE id=b.vm_id AND org_id=b.org_id
          AND provider='kubevirt'))
       OR COALESCE((
        b.native_job_intent->>'schema'='1'
        AND b.native_job_intent->>'producer'='libvirt-push-qcow2/1'
        AND b.native_job_intent->>'backup_id'=b.id
        AND b.native_job_intent->>'org_id'=b.org_id
        AND b.native_job_intent->'source'->>'vm_id'=b.vm_id
        AND b.native_inventory IS NOT NULL
        AND b.native_inventory_transaction_id IS NOT NULL
        AND EXISTS(SELECT 1 FROM public.vms v WHERE v.id=b.vm_id AND v.org_id=b.org_id
          AND v.provider='libvirt' AND v.agent_id=b.native_job_intent->>'agent_id')
        AND EXISTS(SELECT 1 FROM public.s3_publications p
          WHERE p.backup_id=b.id AND p.org_id=b.org_id AND p.kind='payload'
          AND p.id=b.native_job_intent->>'attempt_id'
          AND p.expected_plan->'transaction'->'plan'->>'provider'='libvirt'
          AND p.expected_plan::jsonb->'transaction'->'plan'->'source'->'inventory'
              =b.native_inventory->'inventory')
       ),false)
     )"""


def review_sql(original):
    if original.count(OLD_ADMISSION) != 1:
        raise RuntimeError("Reviewed capacity admission changed; inspect migration")
    return (
        original.replace("CREATE FUNCTION ", "CREATE OR REPLACE FUNCTION ", 1)
        .replace(OLD_ADMISSION, NEW_ADMISSION, 1)
        .replace(
            "Modern KubeVirt hold unavailable", "Modern held transaction unavailable"
        )
    )


def upgrade():
    revisions = ScriptDirectory.from_config(op.get_context().config)
    original = revisions.get_revision("modern_capacity_review").module.REVIEW_FUNCTION
    op.execute(review_sql(original))
    op.execute("REVOKE ALL ON FUNCTION vnbui_review_modern_capacity(jsonb) FROM PUBLIC")


def downgrade():
    raise RuntimeError("Native capacity reviews require reviewed rollback")
