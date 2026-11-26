"""Retained attempt provider operation intent, never signed request custody."""

from alembic import op
import sqlalchemy as sa

revision = "storage_control"
down_revision = "storage_attempt_key"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("s3_publications", sa.Column("provider_control", sa.JSON()))
    op.execute("""CREATE FUNCTION vnbui_storage_control() RETURNS trigger
    LANGUAGE plpgsql AS $$
    DECLARE previous jsonb; current jsonb; entry record; old_item jsonb; new_item jsonb;
    BEGIN
      IF TG_OP='INSERT' THEN
        IF NEW.provider_control IS NOT NULL THEN
          RAISE EXCEPTION 'Control requires durable custody' USING ERRCODE='23514';
        END IF;
        RETURN NEW;
      END IF;
      IF NEW.provider_control::jsonb IS NOT DISTINCT FROM OLD.provider_control::jsonb THEN RETURN NEW; END IF;
      previous := COALESCE(OLD.provider_control::jsonb, '{}'::jsonb);
      current := NEW.provider_control::jsonb;
      IF current IS NULL OR jsonb_typeof(current) IS DISTINCT FROM 'object'
        OR octet_length(current::text)>16777216
        OR OLD.dispatch_token IS NULL OR OLD.dispatch_transaction_id=txid_current()
        OR OLD.expected_plan->>'schema' IS DISTINCT FROM '3'
        OR OLD.state <> 'reserved' OR NEW.state <> 'reserved'
        OR OLD.prepared_receipt IS NOT NULL OR NEW.prepared_receipt IS NOT NULL THEN
        RAISE EXCEPTION 'Invalid control transition' USING ERRCODE='23514';
      END IF;
      FOR entry IN SELECT * FROM jsonb_each(previous) LOOP
        old_item := entry.value; new_item := current->entry.key;
        IF new_item IS NULL
          OR (old_item->>'upload_id' IS NOT NULL AND old_item->'upload_id' IS DISTINCT FROM new_item->'upload_id')
          OR (old_item->>'phase'='create_intent' AND COALESCE(new_item->>'phase','') NOT IN ('create_intent','uploading'))
          OR (old_item->>'phase'='complete_intent' AND COALESCE(new_item->>'phase','') NOT IN ('complete_intent','completed'))
          OR (old_item->>'phase'='completed' AND old_item IS DISTINCT FROM new_item)
          OR (old_item->>'phase'='uploading' AND COALESCE(new_item->>'phase','') NOT IN ('uploading','complete_intent')) THEN
          RAISE EXCEPTION 'Control custody cannot reset' USING ERRCODE='23514';
        END IF;
      END LOOP;
      FOR entry IN SELECT * FROM jsonb_each(current) LOOP
        IF NOT EXISTS (SELECT 1 FROM jsonb_array_elements(OLD.expected_plan::jsonb->'transaction'->'plan'->'artifacts') a WHERE a->>'key'=entry.key)
          OR jsonb_typeof(entry.value) IS DISTINCT FROM 'object'
          OR COALESCE(entry.value->>'phase','') NOT IN ('create_intent','uploading','complete_intent','completed')
          OR (NOT previous ? entry.key AND entry.value->>'phase' <> 'create_intent') THEN
          RAISE EXCEPTION 'Control artifact not authorized' USING ERRCODE='23514';
        END IF;
      END LOOP;
      RETURN NEW;
    END $$""")
    op.execute(
        """CREATE TRIGGER storage_control BEFORE INSERT OR UPDATE ON s3_publications
        FOR EACH ROW EXECUTE FUNCTION vnbui_storage_control()"""
    )


def downgrade():
    raise RuntimeError("Provider custody requires reviewed database/image rollback")
