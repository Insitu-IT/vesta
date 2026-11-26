"""Allow settled compensation to use the existing owner-reviewed retirement."""

from alembic import op
import sqlalchemy as sa

revision = "compensation_retirement"
down_revision = "storage_compensation"
branch_labels = None
depends_on = None


def replace_function(name, replacements, arguments=""):
    definition = op.get_bind().scalar(
        sa.text(
            f"SELECT pg_get_functiondef('public.{name}({arguments})'::regprocedure)"
        )
    )
    for original, replacement in replacements:
        if definition.count(original) != 1:
            raise RuntimeError(f"{name} guard changed; review retirement integration")
        definition = definition.replace(original, replacement, 1)
    op.execute(definition)


def upgrade():
    replace_function(
        "vnbui_storage_compensation",
        [
            (
                "\n          OR NEW.state IS DISTINCT FROM 'cleanup_required'",
                """
          OR OLD.state NOT IN ('cleanup_required','deleted')
          OR (NEW.state IS DISTINCT FROM OLD.state AND (
            OLD.state='cleanup_required' AND NEW.state='deleted'
            AND OLD.cleanup_result::jsonb=jsonb_build_object('schema',1,'s3_absent',true)
            AND current_user=pg_get_userbyid((SELECT relowner FROM pg_class
              WHERE oid='public.backups'::regclass))
            AND coalesce(current_setting('app.modern_capacity_review',true),'')
              ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
          ) IS NOT TRUE)""",
            )
        ],
    )
    # The review function writes publication state before the bound release.
    # Check its complete result at commit; a GUC alone is not a review.
    op.execute("""CREATE FUNCTION vnbui_compensation_retirement() RETURNS trigger
    LANGUAGE plpgsql AS $$
    DECLARE b public.backups; r jsonb;
      prior_org text:=current_setting('app.current_org',true);
      prior_platform text:=current_setting('app.platform_admin',true);
    BEGIN
      PERFORM set_config('app.current_org',NEW.org_id,true);
      PERFORM set_config('app.platform_admin','',true);
      SELECT * INTO b FROM public.backups WHERE id=NEW.backup_id AND org_id=NEW.org_id;
      r:=b.capacity_modern_reviews->-1;
      IF b.id IS NULL OR b.status IS DISTINCT FROM 'failed'
        OR b.capacity_state IS DISTINCT FROM 'released'
        OR b.capacity_id::text IS DISTINCT FROM NEW.cleanup_intent->>'capacity_id'
        OR b.capacity_release->>'reason' IS DISTINCT FROM 'reviewed_modern_quiescence'
        OR b.capacity_release->>'capacity_id' IS DISTINCT FROM b.capacity_id::text
        OR r->>'classification' IS DISTINCT FROM 'released'
        OR r->>'backup_id' IS DISTINCT FROM b.id
        OR r->>'org_id' IS DISTINCT FROM b.org_id
        OR r->>'vm_id' IS DISTINCT FROM b.vm_id
        OR r->>'capacity_id' IS DISTINCT FROM b.capacity_id::text
        OR r->>'operation_id' IS DISTINCT FROM b.capacity_release->>'operation_id'
        OR r->>'journal_sha256' IS DISTINCT FROM b.capacity_release->>'journal_sha256'
        OR (r->'publication_ids' @> jsonb_build_array(NEW.id)) IS NOT TRUE
        OR NEW.cleanup_result::jsonb IS DISTINCT FROM jsonb_build_object('schema',1,'s3_absent',true)
        OR NEW.finalize_intent IS NOT NULL OR NEW.checkpoint_proof IS NOT NULL THEN
        RAISE EXCEPTION 'Compensated retirement requires completed owner review' USING ERRCODE='23514';
      END IF;
      PERFORM set_config('app.current_org',coalesce(prior_org,''),true);
      PERFORM set_config('app.platform_admin',coalesce(prior_platform,''),true);
      RETURN NULL;
    EXCEPTION WHEN OTHERS THEN
      PERFORM set_config('app.current_org',coalesce(prior_org,''),true);
      PERFORM set_config('app.platform_admin',coalesce(prior_platform,''),true);
      RAISE;
    END $$""")
    op.execute("REVOKE ALL ON FUNCTION vnbui_compensation_retirement() FROM PUBLIC")
    op.execute("""CREATE CONSTRAINT TRIGGER compensation_retirement
      AFTER UPDATE ON s3_publications DEFERRABLE INITIALLY DEFERRED
      FOR EACH ROW WHEN (OLD.cleanup_intent IS NOT NULL
        AND OLD.state IS DISTINCT FROM NEW.state AND NEW.state='deleted')
      EXECUTE FUNCTION vnbui_compensation_retirement()""")
    replace_function(
        "vnbui_scheduler_complete",
        [
            (
                "b.status='cleanup_required' AND b.capacity_state='reserved'\n"
                "      AND b.capacity_id IS NOT NULL AND b.capacity_release IS NULL",
                """((b.status='cleanup_required' AND b.capacity_state='reserved' AND b.capacity_release IS NULL)
        OR (b.status='failed' AND b.capacity_state='released' AND q.status='held_claimed'
          AND b.capacity_release->>'reason'='reviewed_modern_quiescence'
          AND b.capacity_release->>'capacity_id'=b.capacity_id::text
          AND b.capacity_modern_reviews->-1->>'classification'='released'
          AND b.capacity_modern_reviews->-1->>'operation_id'=b.capacity_release->>'operation_id'))
      AND b.capacity_id IS NOT NULL""",
            ),
            (
                "cleanup.state='cleanup_required' AND cleanup.cleanup_transaction_id IS NOT NULL",
                """((cleanup.state='cleanup_required' AND b.capacity_state='reserved')
            OR (cleanup.state='deleted' AND b.capacity_state='released'
              AND cleanup.cleanup_result::jsonb=jsonb_build_object('schema',1,'s3_absent',true)
              AND b.capacity_modern_reviews->-1->'publication_ids' @> jsonb_build_array(cleanup.id)))
          AND cleanup.cleanup_transaction_id IS NOT NULL""",
            ),
        ],
    )
    # A non-bypass owner must validate scheduler custody while this review's
    # tenant context is still installed. The review restores that context on
    # return; deferring this check until after return would hide the occurrence.
    release_hash = (
        "release_hash:=encode(sha256(convert_to(release_record::text,'UTF8')),'hex');"
    )
    replace_function(
        "vnbui_review_modern_capacity",
        [
            (
                release_hash,
                release_hash + """
     IF b.authority_kind='scheduler' THEN
       SET CONSTRAINTS scheduler_complete IMMEDIATE;
       SET CONSTRAINTS scheduler_complete DEFERRED;
     END IF;
""",
            )
        ],
        arguments="jsonb",
    )


def downgrade():
    raise RuntimeError(
        "Compensated retirement requires reviewed database/image rollback"
    )
