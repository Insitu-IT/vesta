"""Pause fresh reservations without revoking existing continuation authority.

An absent pause setting preserves the predecessor's admission behavior. The
capacity policy, emergency maintenance guard and all custody remain unchanged.
"""

from alembic import op
import sqlalchemy as sa

revision = "backup_admission_pause"
down_revision = "operator_requests"
branch_labels = None
depends_on = None

LOCK = "PERFORM pg_advisory_xact_lock(1447977557,1);"
VALIDATE = """
 IF pause_policy IS NULL OR jsonb_typeof(pause_policy) IS DISTINCT FROM 'object'
   OR NOT pause_policy ?& ARRAY['schema','revision','paused']
   OR pause_policy-ARRAY['schema','revision','paused']<>'{}'::jsonb
   OR pause_policy->'schema' IS DISTINCT FROM '1'::jsonb
   OR pause_policy->>'schema' IS DISTINCT FROM '1'
   OR jsonb_typeof(pause_policy->'revision') IS DISTINCT FROM 'number'
   OR (pause_policy->>'revision' ~ '^[1-9][0-9]*$') IS NOT TRUE
   OR (pause_policy->>'revision')::numeric>9223372036854775807
   OR jsonb_typeof(pause_policy->'paused') IS DISTINCT FROM 'boolean' THEN
   RAISE EXCEPTION 'Persisted admission pause absent or invalid' USING ERRCODE='23514';
 END IF;
"""

# This nested block runs only inside the original owner-validated, locked fresh
# reservation branch. Never place it before the existing-custody early return.
RESERVATION_GUARD = (
    """
 -- Fresh reservation pause; existing custody and emergency maintenance differ.
 DECLARE pause_policy jsonb; pause_present boolean;
   pause_previous_platform text:=current_setting('app.platform_admin',true);
 BEGIN
   BEGIN
     PERFORM set_config('app.platform_admin','true',true);
     SELECT value::jsonb,true INTO pause_policy,pause_present
       FROM public.settings_v3 WHERE key='backup.admission_pause';
     PERFORM set_config('app.platform_admin',coalesce(pause_previous_platform,''),true);
   EXCEPTION WHEN OTHERS THEN
     PERFORM set_config('app.platform_admin',coalesce(pause_previous_platform,''),true);
     RAISE;
   END;
   IF pause_present IS TRUE THEN
"""
    + VALIDATE
    + """
     IF pause_policy->'paused'='true'::jsonb THEN
       RAISE EXCEPTION 'New backup admission paused' USING ERRCODE='23514';
     END IF;
   END IF;
 END;
"""
)

POLICY_GUARD = (
    """
 -- Admission pause is a separate, revisioned installation setting.
 IF TG_OP<>'INSERT' AND OLD.key='backup.admission_pause' THEN
   IF TG_OP='DELETE' THEN
     RAISE EXCEPTION 'Admission pause cannot be deleted' USING ERRCODE='23514';
   END IF;
   IF NEW.key IS DISTINCT FROM OLD.key THEN
     RAISE EXCEPTION 'Admission pause key is immutable' USING ERRCODE='23514';
   END IF;
 END IF;
 IF TG_OP<>'DELETE' AND NEW.key='backup.admission_pause' THEN
   """
    + LOCK
    + """
   DECLARE pause_policy jsonb:=NEW.value::jsonb;
   BEGIN
"""
    + VALIDATE
    + """
     IF TG_OP='UPDATE' AND NEW.value IS DISTINCT FROM OLD.value THEN
       IF (pause_policy->>'revision')::bigint<=(OLD.value::jsonb->>'revision')::bigint THEN
         RAISE EXCEPTION 'Admission pause revision must increase' USING ERRCODE='23514';
       END IF;
     END IF;
   END;
   -- Let the predecessor guard reject renaming the capacity key into this key.
   IF TG_OP='UPDATE' AND OLD.key='backup.capacity_admission' THEN
     RAISE EXCEPTION 'Capacity policy key is immutable' USING ERRCODE='23514';
   END IF;
   RETURN NEW;
 END IF;
"""
)

RESERVATION_MARKER = "   IF (policy->>'maintenance')::boolean OR occupied>=(policy->>'limit')::integer OR same_vm>0 THEN"
POLICY_MARKER = "\nBEGIN\n"


def replace_function(name, old, new):
    """Retain every later safety extension, owner and existing function ACL."""
    definition = op.get_bind().scalar(
        sa.text(f"SELECT pg_get_functiondef('public.{name}()'::regprocedure)")
    )
    if definition.count(old) != 1:
        raise RuntimeError(f"{name} guard changed; inspect admission-pause integration")
    op.execute(definition.replace(old, new, 1))


def upgrade():
    replace_function(
        "vnbui_capacity_owner",
        RESERVATION_MARKER,
        RESERVATION_GUARD + RESERVATION_MARKER,
    )
    replace_function(
        "vnbui_capacity_policy",
        POLICY_MARKER,
        POLICY_MARKER + POLICY_GUARD,
    )


def downgrade():
    # Rolling back a paused site must never silently reopen fresh admission.
    # Writers are stopped by the reviewed installer procedure. Retain the same
    # advisory lock through validation, guard removal and owner-only row removal.
    connection = op.get_bind()
    connection.execute(sa.text("SELECT pg_advisory_xact_lock(1447977557,1)"))
    previous_platform = connection.scalar(
        sa.text("SELECT current_setting('app.platform_admin',true)")
    )
    connection.execute(sa.text("SELECT set_config('app.platform_admin','true',true)"))
    row = connection.execute(
        sa.text(
            "SELECT value FROM public.settings_v3 WHERE key='backup.admission_pause'"
        )
    ).one_or_none()
    connection.execute(
        sa.text("SELECT set_config('app.platform_admin',:previous,true)"),
        {"previous": previous_platform or ""},
    )
    if row is not None:
        import json

        try:
            pause = json.loads(row.value)
        except (ValueError, TypeError):
            raise RuntimeError("Invalid admission pause; rollback refused") from None
        if (
            type(pause) is not dict
            or set(pause) != {"schema", "revision", "paused"}
            or type(pause["schema"]) is not int
            or pause["schema"] != 1
            or type(pause["revision"]) is not int
            or not 0 < pause["revision"] < 2**63
            or pause["paused"] is not False
        ):
            raise RuntimeError("Explicitly unpause admission before reviewed rollback")
    replace_function(
        "vnbui_capacity_owner",
        RESERVATION_GUARD + RESERVATION_MARKER,
        RESERVATION_MARKER,
    )
    replace_function(
        "vnbui_capacity_policy",
        POLICY_MARKER + POLICY_GUARD,
        POLICY_MARKER,
    )
    # The migration owner may also be NOBYPASSRLS; scope only this exact removal.
    op.execute("""DO $$ DECLARE prior text:=current_setting('app.platform_admin',true);
    BEGIN
      PERFORM set_config('app.platform_admin','true',true);
      DELETE FROM public.settings_v3 WHERE key='backup.admission_pause';
      PERFORM set_config('app.platform_admin',coalesce(prior,''),true);
    EXCEPTION WHEN OTHERS THEN
      PERFORM set_config('app.platform_admin',coalesce(prior,''),true);
      RAISE;
    END $$""")
