"""Retain already-observed create results across credential revocation only."""

from alembic import op
import importlib.util
from pathlib import Path

revision = "provider_result_custody"
down_revision = "callback_provider_create"
branch_labels = None
depends_on = None

spec = importlib.util.spec_from_file_location(
    "provider_create_predecessor",
    Path(__file__).with_name("20260927_callback_provider_create.py"),
)
previous = importlib.util.module_from_spec(spec)
spec.loader.exec_module(previous)

# First intents still authenticate the current credential. An immutable prior
# intent already records that authentication; retaining its exact result is not
# capability delivery. All owner, capacity, agent, plan and key checks remain.
credential_start = "   IF jsonb_typeof(v->'credential_id')"
credential_end = "   expected:=jsonb_build_object"
start = previous.COMMON.index(credential_start)
end = previous.COMMON.index(credential_end, start)
credential = previous.COMMON[start:end]
CUSTODY_COMMON = previous.COMMON.replace(
    credential,
    "   IF pc_old IS NULL THEN\n" + credential + "   END IF;\n",
    1,
)
SQL = previous.SQL.replace(previous.COMMON, CUSTODY_COMMON, 1)


def upgrade():
    op.execute(SQL)
    op.execute("REVOKE ALL ON FUNCTION vnbui_callback_intent() FROM PUBLIC")


def downgrade():
    raise RuntimeError("Provider result custody requires reviewed rollback")
