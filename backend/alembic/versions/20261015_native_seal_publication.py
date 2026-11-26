"""Publish exact positively sealed native custody as well as observed exit zero."""

from alembic import op
import sqlalchemy as sa

revision = "native_seal_publication"
down_revision = "compensation_retirement"
branch_labels = None
depends_on = None


def upgrade():
    definition = op.get_bind().scalar(
        sa.text(
            "SELECT pg_get_functiondef("
            "'public.vnbui_publish_storage_generation(text,text,text,text)'::regprocedure)"
        )
    )
    replacements = [
        (
            "b.native_inventory->'closed_job'->>'state' IS DISTINCT FROM 'exited'",
            "(b.native_inventory->'closed_job'->>'state' IN ('exited','sealed')) IS NOT TRUE",
        ),
        (
            "b.native_inventory->'closed_job'->>'exit_code' IS DISTINCT FROM '0'",
            """b.native_inventory->'closed_job'->>'exit_code' IS DISTINCT FROM '0'
    OR jsonb_typeof(b.native_inventory->'closed_job'->'exit_code') IS DISTINCT FROM 'number'""",
        ),
    ]
    for original, replacement in replacements:
        if definition.count(original) != 1:
            raise RuntimeError(
                "Native closure publication guard changed; review migration"
            )
        definition = definition.replace(original, replacement, 1)
    # Retain all original identity, transaction, receipt and parent guards/ACLs.
    # A sealed closure reserves exit_code=0; it does not assert observed OS exit.
    op.execute(definition)


def downgrade():
    raise RuntimeError(
        "Native seal publication requires reviewed database/image rollback"
    )
