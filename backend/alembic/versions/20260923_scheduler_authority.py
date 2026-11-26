"""Dormant scheduler authority; no enrollment, occurrence producer or effects.

Historical actorless rows remain immutable history. Downgrade cannot discard
attribution or revocation fences: restoring a prior image/database needs review.
"""

from alembic import op
import sqlalchemy as sa

revision = "scheduler_authority"
down_revision = "native_inventory"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        "organizations",
        sa.Column(
            "scheduler_epoch",
            sa.BigInteger(),
            nullable=False,
            server_default=sa.text("0"),
        ),
    )
    op.add_column(
        "organizations",
        sa.Column(
            "scheduler_order",
            sa.BigInteger(),
            nullable=False,
            server_default=sa.text("0"),
        ),
    )
    op.add_column(
        "schedules",
        sa.Column(
            "authority_revision",
            sa.BigInteger(),
            nullable=False,
            server_default=sa.text("1"),
        ),
    )
    op.add_column(
        "schedules", sa.Column("current_grant_id", sa.String(), nullable=True)
    )
    op.add_column(
        "schedules", sa.Column("retired_at", sa.DateTime(timezone=True), nullable=True)
    )
    op.add_column("backups", sa.Column("authority_kind", sa.String(), nullable=True))
    op.add_column(
        "backups", sa.Column("scheduler_occurrence_id", sa.String(), nullable=True)
    )
    op.add_column(
        "backup_queue", sa.Column("authority_kind", sa.String(), nullable=True)
    )
    op.add_column(
        "backup_queue", sa.Column("scheduler_occurrence_id", sa.String(), nullable=True)
    )
    op.create_unique_constraint("uq_schedules_org_id", "schedules", ["org_id", "id"])
    op.create_unique_constraint("uq_users_org_id", "users", ["org_id", "id"])
    op.create_unique_constraint("uq_vms_org_id", "vms", ["org_id", "id"])
    op.execute("""CREATE TABLE scheduler_principals (
	id VARCHAR NOT NULL,
	schedule_id VARCHAR NOT NULL,
	created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
	org_id VARCHAR NOT NULL,
	PRIMARY KEY (id),
	CONSTRAINT uq_scheduler_principal_binding UNIQUE (org_id, id, schedule_id),
	CONSTRAINT uq_scheduler_principal_schedule UNIQUE (org_id, schedule_id),
	FOREIGN KEY(org_id, schedule_id) REFERENCES schedules (org_id, id) ON DELETE RESTRICT,
	CONSTRAINT fk_scheduler_principals_org_id FOREIGN KEY(org_id) REFERENCES organizations (id)
)""")
    op.execute(
        "CREATE INDEX idx_scheduler_principals_org_id ON scheduler_principals (org_id)"
    )
    op.execute("""CREATE TABLE scheduler_grants (
	id VARCHAR NOT NULL,
	principal_id VARCHAR NOT NULL,
	schedule_id VARCHAR NOT NULL,
	schedule_revision BIGINT NOT NULL,
	org_epoch BIGINT NOT NULL,
	scope JSONB NOT NULL,
	scope_sha256 VARCHAR NOT NULL,
	enrolled_by VARCHAR NOT NULL,
	enrollment_request_id VARCHAR NOT NULL,
	created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
	state VARCHAR NOT NULL,
	revoked_at TIMESTAMP WITH TIME ZONE,
	revoked_by VARCHAR,
	revoke_reason VARCHAR,
	revoke_order BIGINT,
	org_id VARCHAR NOT NULL,
	PRIMARY KEY (id),
	CONSTRAINT uq_scheduler_grant_binding UNIQUE (org_id, id, schedule_id, schedule_revision),
	CONSTRAINT uq_scheduler_enrollment_request UNIQUE (org_id, schedule_id, enrollment_request_id),
	FOREIGN KEY(org_id, principal_id, schedule_id) REFERENCES scheduler_principals (org_id, id, schedule_id) ON DELETE RESTRICT,
	FOREIGN KEY(org_id, enrolled_by) REFERENCES users (org_id, id) ON DELETE RESTRICT,
	FOREIGN KEY(org_id, revoked_by) REFERENCES users (org_id, id) ON DELETE RESTRICT,
	CONSTRAINT ck_scheduler_grant_generation CHECK (schedule_revision > 0 AND org_epoch >= 0),
	CONSTRAINT ck_scheduler_grant_state CHECK ((state = 'active' AND revoked_at IS NULL AND revoked_by IS NULL AND revoke_reason IS NULL AND revoke_order IS NULL) OR (state = 'revoked' AND revoked_at IS NOT NULL AND revoke_reason IS NOT NULL AND revoke_order IS NOT NULL AND revoke_order > 0)),
	CONSTRAINT fk_scheduler_grants_org_id FOREIGN KEY(org_id) REFERENCES organizations (id)
)""")
    op.execute("CREATE INDEX idx_scheduler_grants_org_id ON scheduler_grants (org_id)")
    op.execute(
        "CREATE UNIQUE INDEX uq_scheduler_active_grant ON scheduler_grants (org_id, schedule_id) WHERE state = 'active'"
    )
    op.execute("""CREATE TABLE schedule_occurrences (
	id VARCHAR NOT NULL,
	schedule_id VARCHAR NOT NULL,
	schedule_revision BIGINT NOT NULL,
	grant_id VARCHAR NOT NULL,
	scheduled_at TIMESTAMP WITH TIME ZONE NOT NULL,
	admission_order BIGINT NOT NULL,
	created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
	org_id VARCHAR NOT NULL,
	PRIMARY KEY (id),
	CONSTRAINT uq_schedule_occurrence_org UNIQUE (org_id, id),
	CONSTRAINT uq_schedule_occurrence_instant UNIQUE (org_id, schedule_id, schedule_revision, scheduled_at),
	FOREIGN KEY(org_id, grant_id, schedule_id, schedule_revision) REFERENCES scheduler_grants (org_id, id, schedule_id, schedule_revision) ON DELETE RESTRICT,
	CONSTRAINT ck_schedule_occurrence_order CHECK (admission_order > 0),
	CONSTRAINT fk_schedule_occurrences_org_id FOREIGN KEY(org_id) REFERENCES organizations (id)
)""")
    op.execute(
        "CREATE INDEX idx_schedule_occurrences_org_id ON schedule_occurrences (org_id)"
    )
    op.execute("""CREATE TABLE schedule_occurrence_members (
	occurrence_id VARCHAR NOT NULL,
	vm_id VARCHAR NOT NULL,
	source_snapshot JSONB NOT NULL,
	source_sha256 VARCHAR NOT NULL,
	org_id VARCHAR NOT NULL,
	PRIMARY KEY (occurrence_id, vm_id),
	FOREIGN KEY(org_id, occurrence_id) REFERENCES schedule_occurrences (org_id, id) ON DELETE RESTRICT,
	FOREIGN KEY(org_id, vm_id) REFERENCES vms (org_id, id) ON DELETE RESTRICT,
	CONSTRAINT fk_schedule_occurrence_members_org_id FOREIGN KEY(org_id) REFERENCES organizations (id)
)""")
    op.execute(
        "CREATE INDEX idx_schedule_occurrence_members_org_id ON schedule_occurrence_members (org_id)"
    )
    op.execute(
        "ALTER TABLE schedules ADD CONSTRAINT fk_schedule_current_grant FOREIGN KEY(org_id, current_grant_id, id, authority_revision) REFERENCES scheduler_grants (org_id, id, schedule_id, schedule_revision) DEFERRABLE INITIALLY DEFERRED"
    )
    op.execute(
        "ALTER TABLE backups ADD CONSTRAINT uq_backups_occurrence UNIQUE (scheduler_occurrence_id, vm_id)"
    )
    op.execute(
        "ALTER TABLE backups ADD CONSTRAINT fk_backups_occurrence FOREIGN KEY(scheduler_occurrence_id, vm_id) REFERENCES schedule_occurrence_members (occurrence_id, vm_id) ON DELETE RESTRICT"
    )
    op.execute(
        "ALTER TABLE backup_queue ADD CONSTRAINT uq_backup_queue_occurrence UNIQUE (scheduler_occurrence_id, vm_id)"
    )
    op.execute(
        "ALTER TABLE backup_queue ADD CONSTRAINT fk_backup_queue_occurrence FOREIGN KEY(scheduler_occurrence_id, vm_id) REFERENCES schedule_occurrence_members (occurrence_id, vm_id) ON DELETE RESTRICT"
    )
    # Classification only; never infer a user or create a grant.
    for table in ("backups", "backup_queue"):
        op.execute(
            f"UPDATE {table} SET authority_kind=CASE WHEN initiating_user_id IS NULL THEN 'legacy_held' ELSE 'human' END"
        )
    for table in ("backups", "backup_queue"):
        op.execute(
            f"ALTER TABLE {table} ADD CONSTRAINT ck_{table}_authority CHECK (authority_kind IS NOT NULL AND ((authority_kind='human' AND initiating_user_id IS NOT NULL AND scheduler_occurrence_id IS NULL) OR (authority_kind='scheduler' AND initiating_user_id IS NULL AND scheduler_occurrence_id IS NOT NULL) OR (authority_kind='legacy_held' AND initiating_user_id IS NULL AND scheduler_occurrence_id IS NULL)))"
        )
    op.execute(
        "ALTER TABLE schedules ADD CONSTRAINT ck_schedule_authority_revision CHECK (authority_revision > 0)"
    )
    op.execute(
        "ALTER TABLE scheduler_grants ADD CONSTRAINT ck_scheduler_scope CHECK (jsonb_typeof(scope)='object' AND octet_length(scope::text)<=65536 AND scope_sha256 ~ '^[0-9a-f]{64}$')"
    )
    for statement in FUNCTIONS:
        op.execute(statement)
    for table in (
        "scheduler_principals",
        "scheduler_grants",
        "schedule_occurrences",
        "schedule_occurrence_members",
    ):
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
        op.execute(
            f"CREATE POLICY tenant_isolation_{table} ON {table} USING (org_id = NULLIF(current_setting('app.current_org', true), '')) WITH CHECK (org_id = NULLIF(current_setting('app.current_org', true), ''))"
        )
        op.execute(f"REVOKE ALL ON {table} FROM PUBLIC")
        op.execute(
            f"CREATE TRIGGER scheduler_immutable BEFORE UPDATE OR DELETE ON {table} FOR EACH ROW EXECUTE FUNCTION vnbui_scheduler_immutable()"
        )
    # Even internal ORM and raw runtime SQL cannot produce scheduled work yet.
    for table in ("schedule_occurrences", "schedule_occurrence_members"):
        op.execute(
            f"CREATE TRIGGER scheduler_dormant BEFORE INSERT ON {table} FOR EACH ROW EXECUTE FUNCTION vnbui_scheduler_dormant()"
        )
    op.execute(
        "CREATE TRIGGER scheduler_grant_insert BEFORE INSERT ON scheduler_grants FOR EACH ROW EXECUTE FUNCTION vnbui_scheduler_grant_insert()"
    )
    for table in ("scheduler_principals", "scheduler_grants", "schedule_occurrences"):
        op.execute(
            f"CREATE TRIGGER audit_{table}_access AFTER INSERT OR UPDATE ON {table} FOR EACH ROW EXECUTE FUNCTION audit_access()"
        )
    op.execute(
        "CREATE TRIGGER scheduler_epoch BEFORE INSERT OR UPDATE ON organizations FOR EACH ROW EXECUTE FUNCTION vnbui_scheduler_epoch()"
    )
    op.execute(
        "CREATE TRIGGER scheduler_revision BEFORE UPDATE ON schedules FOR EACH ROW EXECUTE FUNCTION vnbui_scheduler_revision()"
    )
    for table in ("schedules", "scheduler_grants"):
        op.execute(
            f"CREATE CONSTRAINT TRIGGER scheduler_binding AFTER INSERT OR UPDATE OR DELETE ON {table} DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION vnbui_scheduler_binding()"
        )
    for table in ("backups", "backup_queue"):
        op.execute(
            f"CREATE TRIGGER scheduler_authority BEFORE INSERT OR UPDATE ON {table} FOR EACH ROW EXECUTE FUNCTION vnbui_scheduler_authority()"
        )
    for function in (
        "epoch",
        "revision",
        "binding",
        "immutable",
        "dormant",
        "authority",
        "grant_insert",
    ):
        op.execute(f"REVOKE ALL ON FUNCTION vnbui_scheduler_{function}() FROM PUBLIC")


def downgrade():
    raise RuntimeError(
        "Scheduler authority/custody cannot be discarded; use reviewed database/image rollback"
    )


FUNCTIONS = [
    """CREATE FUNCTION vnbui_scheduler_grant_insert() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
DECLARE o public.organizations%ROWTYPE;
BEGIN
  SELECT * INTO o FROM public.organizations WHERE id=NEW.org_id FOR UPDATE;
  IF NOT FOUND OR o.enabled IS NOT TRUE OR NEW.org_epoch<>o.scheduler_epoch OR NEW.state<>'active' THEN
    RAISE EXCEPTION 'New grant requires current organization epoch' USING ERRCODE='23514';
  END IF;
  RETURN NEW;
END $$""",
    """CREATE FUNCTION vnbui_scheduler_epoch() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$ BEGIN
  IF TG_OP='INSERT' THEN
    IF NEW.scheduler_epoch<>0 OR NEW.scheduler_order<>0 THEN
      RAISE EXCEPTION 'Initial scheduler fence must be zero' USING ERRCODE='23514';
    END IF;
  ELSE
    IF NEW.scheduler_epoch IS DISTINCT FROM OLD.scheduler_epoch
      OR NEW.scheduler_order < OLD.scheduler_order
      OR (NEW.scheduler_order > OLD.scheduler_order AND NEW.scheduler_order-OLD.scheduler_order<>1) THEN
      RAISE EXCEPTION 'Scheduler fence is monotonic and epoch is disable-owned' USING ERRCODE='23514';
    END IF;
    IF OLD.enabled IS TRUE AND NEW.enabled IS NOT TRUE THEN
      NEW.scheduler_epoch := OLD.scheduler_epoch+1;
      NEW.scheduler_order := OLD.scheduler_order+1;
    END IF;
  END IF;
  RETURN NEW;
END $$""",
    """CREATE FUNCTION vnbui_scheduler_revision() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$ BEGIN
  IF NEW.authority_revision < OLD.authority_revision
    OR NEW.authority_revision > OLD.authority_revision AND NEW.authority_revision-OLD.authority_revision<>1
    OR NEW.authority_revision<=0
    OR OLD.retired_at IS NOT NULL AND NEW.retired_at IS DISTINCT FROM OLD.retired_at THEN
    RAISE EXCEPTION 'Invalid schedule revision/retirement' USING ERRCODE='23514';
  END IF;
  IF ROW(NEW.vm_id,NEW.vm_group_id,NEW.cron_expression,NEW.retention_days,NEW.backup_type,NEW.exclude_disks,NEW.workers,NEW.tags)
    IS DISTINCT FROM ROW(OLD.vm_id,OLD.vm_group_id,OLD.cron_expression,OLD.retention_days,OLD.backup_type,OLD.exclude_disks,OLD.workers,OLD.tags)
    AND (NEW.current_grant_id IS NOT NULL OR NEW.authority_revision<>OLD.authority_revision+1) THEN
    RAISE EXCEPTION 'Scope edits require detached revision' USING ERRCODE='23514';
  END IF;
  RETURN NEW;
END $$""",
    """CREATE FUNCTION vnbui_scheduler_binding() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
DECLARE sid text; oid text; s public.schedules%ROWTYPE; g public.scheduler_grants%ROWTYPE;
BEGIN
  IF TG_TABLE_NAME='schedules' THEN sid:=COALESCE(NEW.id,OLD.id); ELSE sid:=COALESCE(NEW.schedule_id,OLD.schedule_id); END IF;
  oid:=COALESCE(NEW.org_id,OLD.org_id);
  SELECT * INTO s FROM public.schedules WHERE id=sid AND org_id=oid;
  IF NOT FOUND THEN
    IF TG_TABLE_NAME='schedules' AND TG_OP='DELETE' THEN RETURN NULL; END IF;
    RAISE EXCEPTION 'Schedule binding unavailable at commit' USING ERRCODE='23514';
  END IF;
  SELECT * INTO g FROM public.scheduler_grants WHERE org_id=oid AND schedule_id=sid AND state='active';
  IF FOUND THEN
    IF s.current_grant_id IS DISTINCT FROM g.id OR s.authority_revision<>g.schedule_revision OR s.retired_at IS NOT NULL THEN
      RAISE EXCEPTION 'Active grant requires exact current schedule binding' USING ERRCODE='23514';
    END IF;
  ELSIF s.current_grant_id IS NOT NULL THEN
    RAISE EXCEPTION 'Current schedule grant must be active' USING ERRCODE='23514';
  END IF;
  RETURN NULL;
END $$""",
    """CREATE FUNCTION vnbui_scheduler_immutable() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$ BEGIN
  IF TG_OP='DELETE' THEN RAISE EXCEPTION 'Scheduler custody is retained' USING ERRCODE='23514'; END IF;
  IF TG_TABLE_NAME<>'scheduler_grants' THEN
    IF to_jsonb(NEW) IS DISTINCT FROM to_jsonb(OLD) THEN RAISE EXCEPTION 'Scheduler binding is immutable' USING ERRCODE='23514'; END IF;
  ELSE
    IF (to_jsonb(NEW)-ARRAY['state','revoked_at','revoked_by','revoke_reason','revoke_order']) IS DISTINCT FROM
       (to_jsonb(OLD)-ARRAY['state','revoked_at','revoked_by','revoke_reason','revoke_order'])
       OR OLD.state='revoked' AND to_jsonb(NEW) IS DISTINCT FROM to_jsonb(OLD) THEN
      RAISE EXCEPTION 'Grant identity is immutable; revocation terminal' USING ERRCODE='23514';
    END IF;
    IF OLD.state='active' AND NEW.state='revoked' THEN
      UPDATE public.organizations SET scheduler_order=scheduler_order+1 WHERE id=NEW.org_id RETURNING scheduler_order INTO NEW.revoke_order;
      IF NOT FOUND THEN RAISE EXCEPTION 'Grant organization unavailable' USING ERRCODE='23514'; END IF;
    END IF;
  END IF;
  RETURN NEW;
END $$""",
    """CREATE FUNCTION vnbui_scheduler_dormant() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$ BEGIN
  RAISE EXCEPTION 'Scheduler occurrence production awaits integrated admission' USING ERRCODE='23514';
END $$""",
    """CREATE FUNCTION vnbui_scheduler_authority() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$ BEGIN
  IF TG_OP='INSERT' THEN
    IF NEW.authority_kind IS DISTINCT FROM 'human' OR NEW.initiating_user_id IS NULL OR NEW.scheduler_occurrence_id IS NOT NULL THEN
      RAISE EXCEPTION 'Explicit human authority required; scheduler dormant, history unadoptable' USING ERRCODE='23514';
    END IF;
  ELSE
    IF NEW.vm_id IS DISTINCT FROM OLD.vm_id OR
       ROW(NEW.authority_kind,NEW.scheduler_occurrence_id,NEW.initiating_user_id) IS DISTINCT FROM
       ROW(OLD.authority_kind,OLD.scheduler_occurrence_id,OLD.initiating_user_id) THEN
      RAISE EXCEPTION 'Original authority is immutable' USING ERRCODE='23514';
    END IF;
  END IF;
  RETURN NEW;
END $$""",
]
