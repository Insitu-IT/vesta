"""Remove historical export/import claims made before custody was attested.

Generating an encrypted response was previously enough to set backed_up. It
cannot prove that an operator received, saved, or can import the file. Retain
other independently recorded locations, but require old file-only exports to
be confirmed again under the new explicit custody workflow.
"""

from alembic import op

revision = "kek_export_custody"
down_revision = "agent_registration_scope"
branch_labels = None
depends_on = None


def upgrade():
    op.execute("SELECT set_config('app.platform_admin', 'true', true)")
    op.execute("""
        WITH affected AS (
          SELECT id,
            COALESCE((
              SELECT jsonb_agg(value)
              FROM jsonb_array_elements_text(backed_up_locations) AS entry(value)
              WHERE value NOT IN ('file-export', 'imported')
            ), '[]'::jsonb) AS retained_locations
          FROM encryption_keys
          WHERE backed_up_locations ?| ARRAY['file-export', 'imported']
        )
        UPDATE encryption_keys AS target
        SET backed_up_locations = affected.retained_locations,
            backed_up = jsonb_array_length(affected.retained_locations) > 0,
            backed_up_at = CASE
              WHEN jsonb_array_length(affected.retained_locations) > 0
              THEN target.backed_up_at ELSE NULL END
        FROM affected
        WHERE target.id = affected.id
        """)
    op.execute("SELECT set_config('app.platform_admin', '', true)")


def downgrade():
    # A false historical custody claim must never be restored by rollback.
    pass
