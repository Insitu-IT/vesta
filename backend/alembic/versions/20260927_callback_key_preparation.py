"""Separate committed preparation intent permits exact wrapped-key attachment."""

import importlib.util
from pathlib import Path
from alembic import op

revision = "callback_key_preparation"
down_revision = "callback_receipt_response"
branch_labels = None
depends_on = None

spec = importlib.util.spec_from_file_location(
    "callback_receipt_predecessor",
    Path(__file__).with_name("20260927_callback_receipt_response.py"),
)
previous = importlib.util.module_from_spec(spec)
spec.loader.exec_module(previous)

ATTACHMENT = (
    """
   IF OLD.attempt_key_preparation_intent IS NULL OR OLD.attempt_key_preparation_xid IS NULL
     OR OLD.attempt_key_preparation_xid=txid_current()
     OR NEW.attempt_key_preparation_intent IS DISTINCT FROM OLD.attempt_key_preparation_intent
     OR NEW.attempt_key_disclosure_intent IS DISTINCT FROM OLD.attempt_key_disclosure_intent
     OR NEW.receipt_verification_intent IS DISTINCT FROM OLD.receipt_verification_intent
     OR OLD.attempt_key_disclosure_intent IS NOT NULL
     OR OLD.wrapped_attempt_key IS NOT NULL OR NEW.wrapped_attempt_key IS NULL
     OR OLD.prepared_receipt IS NOT NULL OR NEW.prepared_receipt IS NOT NULL
     OR jsonb_build_array(NEW.provider_control,NEW.finalize_intent,NEW.checkpoint_proof)
       IS DISTINCT FROM jsonb_build_array(OLD.provider_control,OLD.finalize_intent,OLD.checkpoint_proof)
     OR OLD.state IS DISTINCT FROM 'reserved' OR NEW.state IS DISTINCT FROM 'reserved' THEN
     RAISE EXCEPTION 'Callback effect continuation remains dormant' USING ERRCODE='23514';
   END IF;
   expected:=OLD.attempt_key_preparation_intent;
"""
    + previous.AUTHORITY
    + """
   SELECT * INTO keyrow FROM public.encryption_keys
     WHERE id=split_part(expected->>'key_ref',':',2) AND org_id=b.org_id FOR UPDATE;
   IF keyrow.id IS NULL OR keyrow.status IS DISTINCT FROM 'active'
     OR keyrow.provider IS DISTINCT FROM 'local' OR keyrow.algorithm IS DISTINCT FROM 'aes-256-gcm'
     OR keyrow.provider_key_ref IS NOT NULL
     OR keyrow.key_hash IS DISTINCT FROM split_part(expected->>'key_ref',':',3)
     OR NEW.wrapped_attempt_key->>'key_ref' IS DISTINCT FROM expected->>'key_ref'
     OR NEW.wrapped_attempt_key->>'format' IS DISTINCT FROM expected->>'format' THEN
     RAISE EXCEPTION 'Callback key identity unavailable' USING ERRCODE='23514';
   END IF;
   -- The existing storage_attempt_key trigger enforces the exact ten-field
   -- ciphertext envelope, original plan binding and write-once semantics.
"""
)

SQL = previous.SQL.replace(
    previous.ATTACHMENT,
    "IF NEW.wrapped_attempt_key::jsonb IS DISTINCT FROM OLD.wrapped_attempt_key::jsonb THEN\n"
    + ATTACHMENT
    + "\nELSE\n"
    + previous.ATTACHMENT
    + "\nEND IF;\n",
)
assert SQL != previous.SQL


def upgrade():
    op.execute(SQL)
    op.execute("REVOKE ALL ON FUNCTION vnbui_callback_intent() FROM PUBLIC")


def downgrade():
    raise RuntimeError("Callback key custody requires reviewed rollback")
