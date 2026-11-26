"""Immutable attempt-bound wrapped DEK; never plaintext recovery custody."""

from alembic import op
import sqlalchemy as sa

revision = "storage_attempt_key"
down_revision = "storage_lineage"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("s3_publications", sa.Column("wrapped_attempt_key", sa.JSON()))
    op.execute("""CREATE FUNCTION vnbui_storage_attempt_key() RETURNS trigger
        LANGUAGE plpgsql AS $$
        DECLARE binding jsonb; plan jsonb;
        BEGIN
        IF TG_OP='INSERT' THEN
            IF NEW.wrapped_attempt_key IS NOT NULL THEN
                RAISE EXCEPTION 'Key requires committed producer custody' USING ERRCODE='23514';
            END IF;
            RETURN NEW;
        END IF;
        IF OLD.wrapped_attempt_key IS NOT NULL THEN
            IF NEW.wrapped_attempt_key::jsonb IS DISTINCT FROM OLD.wrapped_attempt_key::jsonb THEN
                RAISE EXCEPTION 'Attempt key cannot be replaced or cleared' USING ERRCODE='23514';
            END IF;
            RETURN NEW;
        END IF;
        IF NEW.wrapped_attempt_key IS NULL THEN RETURN NEW; END IF;
        binding := NEW.wrapped_attempt_key::jsonb;
        plan := OLD.expected_plan::jsonb->'transaction';
        IF OLD.expected_plan->>'schema' IS DISTINCT FROM '3'
           OR OLD.dispatch_token IS NULL OR OLD.dispatch_transaction_id IS NULL
           OR OLD.dispatch_transaction_id=txid_current()
           OR OLD.state <> 'reserved' OR NEW.state <> 'reserved'
           OR OLD.prepared_receipt IS NOT NULL OR NEW.prepared_receipt IS NOT NULL
           OR jsonb_typeof(binding) IS DISTINCT FROM 'object'
           OR NOT binding ?& ARRAY['schema','org_id','backup_id','reservation_id','attempt_id',
                'plan_sha256','format','key_ref','wrapping','ciphertext']
           OR binding - ARRAY['schema','org_id','backup_id','reservation_id','attempt_id',
                'plan_sha256','format','key_ref','wrapping','ciphertext'] <> '{}'::jsonb
           OR binding->'schema' IS DISTINCT FROM '1'::jsonb
           OR binding->>'org_id' IS DISTINCT FROM OLD.org_id
           OR binding->>'backup_id' IS DISTINCT FROM OLD.backup_id
           OR binding->>'reservation_id' IS DISTINCT FROM OLD.id
           OR binding->>'attempt_id' IS DISTINCT FROM plan->'plan'->>'attempt_id'
           OR binding->>'plan_sha256' IS DISTINCT FROM plan->>'plan_sha256'
           OR binding->>'format' IS DISTINCT FROM 'vnbu1-aes256gcm-chunk5242880'
           OR binding->>'format' IS DISTINCT FROM plan->'plan'->'encryption'->>'format'
           OR binding->>'key_ref' IS DISTINCT FROM plan->'plan'->'encryption'->>'key_ref'
           OR binding->>'wrapping' IS DISTINCT FROM 'aes256-keywrap/1'
           OR jsonb_typeof(binding->'ciphertext') IS DISTINCT FROM 'string'
           OR binding->>'ciphertext' !~ '^[A-Za-z0-9+/]{54}==$' THEN
            RAISE EXCEPTION 'Invalid attempt key binding' USING ERRCODE='23514';
        END IF;
        RETURN NEW;
        END $$""")
    op.execute("""CREATE TRIGGER storage_attempt_key BEFORE INSERT OR UPDATE
        ON s3_publications FOR EACH ROW EXECUTE FUNCTION vnbui_storage_attempt_key()""")


def downgrade():
    raise RuntimeError(
        "Wrapped attempt custody requires reviewed database/image rollback"
    )
