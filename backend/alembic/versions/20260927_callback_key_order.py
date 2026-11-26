"""Monotonic key-first effects, without attributing predecessor ciphertext."""

import importlib.util
from pathlib import Path

from alembic import op
import sqlalchemy as sa

revision = "callback_key_order"
down_revision = "callback_key_preparation"
branch_labels = None
depends_on = None

spec = importlib.util.spec_from_file_location(
    "callback_key_predecessor",
    Path(__file__).with_name("20260927_callback_key_preparation.py"),
)
previous = importlib.util.module_from_spec(spec)
spec.loader.exec_module(previous)

ORDER = """
 IF TG_OP='INSERT' THEN
   IF NEW.wrapped_attempt_key_xid IS NOT NULL THEN
     RAISE EXCEPTION 'Key transaction marker is server owned' USING ERRCODE='23514';
   END IF;
 ELSIF TG_OP='UPDATE' THEN
   IF NEW.wrapped_attempt_key_xid IS DISTINCT FROM OLD.wrapped_attempt_key_xid THEN
     RAISE EXCEPTION 'Key transaction marker is server owned' USING ERRCODE='23514';
   END IF;
   IF (OLD.attempt_key_preparation_intent IS NULL AND NEW.attempt_key_preparation_intent IS NOT NULL)
     OR (OLD.wrapped_attempt_key IS NULL AND NEW.wrapped_attempt_key IS NOT NULL) THEN
     IF OLD.receipt_verification_intent IS NOT NULL OR NEW.receipt_verification_intent IS NOT NULL
       OR OLD.provider_control IS NOT NULL OR NEW.provider_control IS NOT NULL
       OR OLD.prepared_receipt IS NOT NULL OR NEW.prepared_receipt IS NOT NULL
       OR OLD.attempt_key_disclosure_intent IS NOT NULL OR NEW.attempt_key_disclosure_intent IS NOT NULL THEN
       RAISE EXCEPTION 'Callback effect continuation remains dormant' USING ERRCODE='23514';
     END IF;
   END IF;
   IF OLD.wrapped_attempt_key IS NULL AND NEW.wrapped_attempt_key IS NOT NULL THEN
     NEW.wrapped_attempt_key_xid:=txid_current();
   END IF;
   IF OLD.expected_plan->>'schema'='3'
     AND OLD.expected_plan->'transaction'->'plan'->'encryption'->>'format' IS DISTINCT FROM 'none'
     AND (NEW.receipt_verification_intent IS DISTINCT FROM OLD.receipt_verification_intent
       OR NEW.prepared_receipt::jsonb IS DISTINCT FROM OLD.prepared_receipt::jsonb
       OR NEW.provider_control::jsonb IS DISTINCT FROM OLD.provider_control::jsonb
       OR NEW.attempt_key_disclosure_intent IS DISTINCT FROM OLD.attempt_key_disclosure_intent) THEN
     doc:=OLD.expected_plan::jsonb->'transaction'; v:=OLD.wrapped_attempt_key::jsonb;
     IF v IS NULL OR OLD.wrapped_attempt_key_xid IS NULL
       OR OLD.wrapped_attempt_key_xid=txid_current()
       OR v->>'org_id' IS DISTINCT FROM OLD.org_id
       OR v->>'backup_id' IS DISTINCT FROM OLD.backup_id
       OR v->>'reservation_id' IS DISTINCT FROM OLD.id
       OR v->>'attempt_id' IS DISTINCT FROM doc->'plan'->>'attempt_id'
       OR v->>'plan_sha256' IS DISTINCT FROM doc->>'plan_sha256'
       OR v->>'key_ref' IS DISTINCT FROM doc->'plan'->'encryption'->>'key_ref'
       OR v->>'format' IS DISTINCT FROM doc->'plan'->'encryption'->>'format' THEN
       RAISE EXCEPTION 'Committed key required' USING ERRCODE='23514';
     END IF;
   END IF;
 END IF;
"""

SQL = previous.SQL.replace("BEGIN\n", "BEGIN\n" + ORDER, 1)


def upgrade():
    # NULL preserves predecessor custody; migration cannot prove its key origin.
    op.add_column(
        "s3_publications", sa.Column("wrapped_attempt_key_xid", sa.BigInteger())
    )
    op.execute(SQL)
    op.execute("REVOKE ALL ON FUNCTION vnbui_callback_intent() FROM PUBLIC")


def downgrade():
    raise RuntimeError("Key ordering custody requires reviewed rollback")
