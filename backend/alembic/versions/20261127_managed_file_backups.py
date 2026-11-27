"""Retain managed file schedules, attempt history, and encrypted archive identity."""

from alembic import op
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy import (
    Column,
    String,
    BigInteger,
    Boolean,
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Integer,
    UniqueConstraint,
    CheckConstraint,
    text,
    Text,
)

revision = "managed_file_backups"
down_revision = "backup_admission_pause"
branch_labels = None
depends_on = None

CUSTODY = r"""
CREATE FUNCTION public.vnbui_file_custody() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
DECLARE org_epoch bigint; schedule public.file_schedules%ROWTYPE;
BEGIN
 IF TG_OP='DELETE' THEN
   RAISE EXCEPTION 'File backup history is retained' USING ERRCODE='23514';
 END IF;
 IF NEW.file_set !~ '^[a-z][a-z0-9_-]{0,62}$' THEN
   RAISE EXCEPTION 'Invalid file set name' USING ERRCODE='23514';
 END IF;
 IF TG_TABLE_NAME='file_schedules' THEN
   IF TG_OP='UPDATE' THEN
     IF (NEW.org_id, NEW.id, NEW.agent_id, NEW.file_set, NEW.created_at)
       IS DISTINCT FROM (OLD.org_id, OLD.id, OLD.agent_id, OLD.file_set, OLD.created_at)
       OR OLD.retired_at IS NOT NULL THEN
       RAISE EXCEPTION 'File schedule target identity is retained' USING ERRCODE='23514';
     END IF;
   END IF;
   IF NEW.retired_at IS NOT NULL AND NEW.enabled THEN
     RAISE EXCEPTION 'Retired file schedule cannot run' USING ERRCODE='23514';
   END IF;
   IF TG_OP='INSERT' OR (NEW.enabled AND NOT OLD.enabled)
      OR NEW.authorized_by IS DISTINCT FROM OLD.authorized_by
      OR NEW.org_epoch IS DISTINCT FROM OLD.org_epoch
      OR NEW.grant_id IS DISTINCT FROM OLD.grant_id
      OR (NEW.storage_endpoint, NEW.storage_region, NEW.storage_bucket, NEW.storage_prefix, NEW.storage_recipient_sha256)
          IS DISTINCT FROM (OLD.storage_endpoint, OLD.storage_region, OLD.storage_bucket, OLD.storage_prefix, OLD.storage_recipient_sha256) THEN
     SELECT o.scheduler_epoch INTO org_epoch FROM public.organizations o
       WHERE o.id=NEW.org_id AND o.enabled FOR SHARE;
     IF NOT FOUND OR org_epoch<>NEW.org_epoch OR NOT EXISTS(
       SELECT 1 FROM public.users u WHERE u.org_id=NEW.org_id
         AND u.id=NEW.authorized_by AND u.is_active AND u.role='admin'
     ) OR NOT EXISTS(
       SELECT 1 FROM public.agents a WHERE a.org_id=NEW.org_id AND a.id=NEW.agent_id
         AND (a.capabilities->'managed_file_sets') ? NEW.file_set
         AND a.capabilities#>>'{managed_file_storage,endpoint}'=NEW.storage_endpoint
         AND a.capabilities#>>'{managed_file_storage,region}'=NEW.storage_region
         AND a.capabilities#>>'{managed_file_storage,bucket}'=NEW.storage_bucket
         AND a.capabilities#>>'{managed_file_storage,prefix}'=NEW.storage_prefix
         AND (a.capabilities#>'{managed_file_storage,recipient_sha256}')->>NEW.file_set=NEW.storage_recipient_sha256
     ) THEN
       RAISE EXCEPTION 'File schedule grant unavailable' USING ERRCODE='23514';
     END IF;
   END IF;
   RETURN NEW;
 END IF;
 IF TG_OP='UPDATE' THEN
   IF (NEW.org_id, NEW.id, NEW.agent_id, NEW.file_set, NEW.schedule_id, NEW.schedule_grant_id, NEW.scheduled_at,
       NEW.actor_id, NEW.request_key, NEW.created_at,
       NEW.storage_endpoint, NEW.storage_region, NEW.storage_bucket, NEW.storage_prefix, NEW.storage_recipient_sha256)
      IS DISTINCT FROM (OLD.org_id, OLD.id, OLD.agent_id, OLD.file_set, OLD.schedule_id, OLD.schedule_grant_id, OLD.scheduled_at,
       OLD.actor_id, OLD.request_key, OLD.created_at,
       OLD.storage_endpoint, OLD.storage_region, OLD.storage_bucket, OLD.storage_prefix, OLD.storage_recipient_sha256)
      OR (OLD.status IN ('completed','failed') AND NEW IS DISTINCT FROM OLD)
      OR (OLD.status='running' AND NEW.status='pending')
      OR (OLD.dispatch_started_at IS NOT NULL AND NEW.dispatch_started_at IS DISTINCT FROM OLD.dispatch_started_at)
      OR (OLD.agent_accepted_at IS NOT NULL AND NEW.agent_accepted_at IS DISTINCT FROM OLD.agent_accepted_at) THEN
     RAISE EXCEPTION 'File backup custody is immutable' USING ERRCODE='23514';
   END IF;
   RETURN NEW;
 END IF;
 SELECT o.scheduler_epoch INTO org_epoch FROM public.organizations o
   WHERE o.id=NEW.org_id AND o.enabled FOR SHARE;
 IF NOT FOUND OR NEW.status<>'pending' OR NEW.dispatch_started_at IS NOT NULL OR
   NEW.agent_accepted_at IS NOT NULL OR NEW.started_at IS NOT NULL THEN
   RAISE EXCEPTION 'Fresh file backup authority unavailable' USING ERRCODE='23514';
 END IF;
 IF NEW.schedule_id IS NULL THEN
   IF NOT EXISTS(SELECT 1 FROM public.users u WHERE u.org_id=NEW.org_id
        AND u.id=NEW.actor_id AND u.is_active AND u.role IN ('admin','operator'))
     OR NOT EXISTS(SELECT 1 FROM public.agents a WHERE a.org_id=NEW.org_id AND a.id=NEW.agent_id
        AND (a.capabilities->'managed_file_sets') ? NEW.file_set
         AND a.capabilities#>>'{managed_file_storage,endpoint}'=NEW.storage_endpoint
         AND a.capabilities#>>'{managed_file_storage,region}'=NEW.storage_region
         AND a.capabilities#>>'{managed_file_storage,bucket}'=NEW.storage_bucket
         AND a.capabilities#>>'{managed_file_storage,prefix}'=NEW.storage_prefix
         AND (a.capabilities#>'{managed_file_storage,recipient_sha256}')->>NEW.file_set=NEW.storage_recipient_sha256) THEN
     RAISE EXCEPTION 'File backup requester or target unavailable' USING ERRCODE='23514';
   END IF;
 ELSE
   SELECT * INTO schedule FROM public.file_schedules s
     WHERE s.id=NEW.schedule_id AND s.org_id=NEW.org_id FOR SHARE;
   IF NOT FOUND OR NOT schedule.enabled OR schedule.retired_at IS NOT NULL
      OR schedule.org_epoch<>org_epoch OR schedule.grant_id<>NEW.schedule_grant_id
      OR (NEW.storage_endpoint, NEW.storage_region, NEW.storage_bucket, NEW.storage_prefix, NEW.storage_recipient_sha256)
          IS DISTINCT FROM (schedule.storage_endpoint, schedule.storage_region, schedule.storage_bucket, schedule.storage_prefix, schedule.storage_recipient_sha256) THEN
     RAISE EXCEPTION 'Schedule target grant is unavailable' USING ERRCODE='23514';
   END IF;
 END IF;
 RETURN NEW;
END $$;
"""


LEGACY_S3_CUSTODY = r"""
DO $$
DECLARE tenant text;
        previous_org text := current_setting('app.current_org',true);
        previous_platform text := current_setting('app.platform_admin',true);
BEGIN
 PERFORM set_config('app.platform_admin','true',true);
 FOR tenant IN SELECT id FROM public.organizations LOOP
   PERFORM set_config('app.current_org',tenant,true);
   UPDATE public.backups b SET unverified_legacy_s3=true
   WHERE b.org_id=tenant AND b.status='completed'
     AND NOT EXISTS(
       SELECT 1 FROM public.storage_lineage_generations g
       JOIN public.s3_publications p ON p.org_id=g.org_id AND p.backup_id=g.backup_id
       WHERE g.org_id=b.org_id AND g.backup_id=b.id AND g.state='accepted'
         AND p.kind='payload' AND p.state='published'
     )
     AND (
       b.storage_path LIKE 's3://%'
       OR b.tags->'imported_from_s3'='true'::jsonb
       OR EXISTS(
         SELECT 1 FROM public.vms v JOIN public.agents a ON a.id=v.agent_id AND a.org_id=v.org_id
         WHERE v.org_id=b.org_id AND v.id=b.vm_id
           AND (a.hostname='__s3_import__' OR v.vm_metadata->'imported_from_s3'='true'::jsonb)
       )
       OR (
         b.storage_path IS NULL
         AND EXISTS(
           SELECT 1 FROM public.activity_logs audit JOIN public.users u ON u.id=audit.user_id
           WHERE u.org_id=b.org_id AND audit.action='s3_chain_imported'
             AND audit.resource_type='backup_chain'
             AND audit.resource_id=COALESCE(b.chain_id,b.id)
         )
       )
     );
 END LOOP;
 PERFORM set_config('app.current_org',coalesce(previous_org,''),true);
 PERFORM set_config('app.platform_admin',coalesce(previous_platform,''),true);
END $$;

CREATE FUNCTION public.vnbui_unverified_legacy_s3() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
BEGIN
 IF TG_OP='DELETE' THEN
   IF OLD.unverified_legacy_s3 THEN
     RAISE EXCEPTION 'Unverified legacy S3 catalog history is retained' USING ERRCODE='23514';
   END IF;
   RETURN OLD;
 END IF;
 IF (TG_OP='INSERT' AND NEW.unverified_legacy_s3)
    OR (TG_OP='UPDATE' AND NEW.unverified_legacy_s3 IS DISTINCT FROM OLD.unverified_legacy_s3) THEN
   RAISE EXCEPTION 'Unverified legacy S3 custody cannot be changed' USING ERRCODE='23514';
 END IF;
 IF NEW.parent_backup_id IS NOT NULL
    AND (TG_OP='INSERT' OR NEW.parent_backup_id IS DISTINCT FROM OLD.parent_backup_id)
    AND EXISTS(
      SELECT 1 FROM public.backups parent WHERE parent.id=NEW.parent_backup_id
        AND parent.org_id=NEW.org_id AND parent.unverified_legacy_s3
    ) THEN
   RAISE EXCEPTION 'Unverified legacy S3 backup cannot be a parent' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER unverified_legacy_s3_custody BEFORE INSERT OR UPDATE OR DELETE ON public.backups
FOR EACH ROW EXECUTE FUNCTION public.vnbui_unverified_legacy_s3();
REVOKE ALL ON FUNCTION public.vnbui_unverified_legacy_s3() FROM PUBLIC;
"""


RECOVERY_CUSTODY = r"""
CREATE FUNCTION public.vnbui_recovery_signer_marker() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
BEGIN
 IF TG_OP='DELETE' THEN
   IF OLD.key='recovery.signing_identity.v1' THEN
     RAISE EXCEPTION 'Recovery signer identity is retained' USING ERRCODE='23514';
   END IF;
   RETURN OLD;
 END IF;
 IF TG_OP='UPDATE' AND (
     OLD.key='recovery.signing_identity.v1' OR NEW.key='recovery.signing_identity.v1'
 ) THEN
   RAISE EXCEPTION 'Recovery signer identity is immutable' USING ERRCODE='23514';
 END IF;
 IF NEW.key='recovery.signing_identity.v1' AND (
     current_setting('app.platform_admin',true) IS DISTINCT FROM 'true'
     OR NEW.value_type IS DISTINCT FROM 'json'
     OR NEW.source IS DISTINCT FROM 'installation'
 ) THEN
   RAISE EXCEPTION 'Recovery signer requires installation scope' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER recovery_signer_marker BEFORE INSERT OR UPDATE OR DELETE
  ON public.settings_v3 FOR EACH ROW EXECUTE FUNCTION public.vnbui_recovery_signer_marker();
REVOKE ALL ON FUNCTION public.vnbui_recovery_signer_marker() FROM PUBLIC;

ALTER TABLE public.recovery_publications ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.recovery_publications FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_recovery_publications ON public.recovery_publications
 USING (org_id = NULLIF(current_setting('app.current_org',true),''))
 WITH CHECK (org_id = NULLIF(current_setting('app.current_org',true),''));
REVOKE ALL ON public.recovery_publications FROM PUBLIC;

CREATE FUNCTION public.vnbui_recovery_publication_custody() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
DECLARE installation text;
BEGIN
 IF TG_OP='DELETE' THEN
   RAISE EXCEPTION 'Recovery publication custody is retained' USING ERRCODE='23514';
 END IF;
 IF TG_OP='INSERT' THEN
   SELECT installation_id INTO installation FROM public.storage_configuration_clock WHERE slot=1;
   IF NOT FOUND OR NOT EXISTS(
     SELECT 1 FROM public.storage_lineage_generations g
     JOIN public.backups b ON b.id=g.backup_id AND b.org_id=g.org_id
     JOIN public.s3_publications p ON p.id=g.id AND p.org_id=g.org_id AND p.backup_id=g.backup_id
     WHERE g.id=NEW.generation_id AND g.org_id=NEW.org_id AND g.backup_id=NEW.backup_id
       AND g.state='accepted' AND b.status='completed' AND NOT b.unverified_legacy_s3
       AND p.kind='chain_manifest' AND p.state='published'
   ) OR NEW.object_key IS DISTINCT FROM (
      'vesta-recovery/v1/'||installation||'/'||NEW.org_id||'/'||NEW.backup_id||'.json'
   ) OR NEW.envelope IS NOT NULL OR NEW.published_at IS NOT NULL OR NEW.publication_receipt IS NOT NULL THEN
     RAISE EXCEPTION 'Accepted generation required for recovery registration' USING ERRCODE='23514';
   END IF;
 ELSE
   IF (NEW.generation_id,NEW.org_id,NEW.backup_id,NEW.object_key,NEW.created_at)
      IS DISTINCT FROM (OLD.generation_id,OLD.org_id,OLD.backup_id,OLD.object_key,OLD.created_at)
      OR (OLD.envelope IS NOT NULL AND NEW.envelope IS DISTINCT FROM OLD.envelope)
      OR (OLD.published_at IS NOT NULL AND NEW IS DISTINCT FROM OLD) THEN
     RAISE EXCEPTION 'Recovery publication identity is immutable' USING ERRCODE='23514';
   END IF;
   IF (NEW.published_at IS NULL) IS DISTINCT FROM (NEW.publication_receipt IS NULL)
      OR (NEW.envelope IS NOT NULL AND NOT octet_length(NEW.envelope) BETWEEN 1 AND 65536)
      OR (NEW.published_at IS NOT NULL AND (
        NEW.envelope IS NULL
        OR jsonb_typeof(NEW.publication_receipt) IS DISTINCT FROM 'object'
        OR NOT NEW.publication_receipt ?& ARRAY['etag','version_id','bytes','sha256']
        OR NEW.publication_receipt - ARRAY['etag','version_id','bytes','sha256'] <> '{}'::jsonb
        OR NEW.publication_receipt->'bytes' IS DISTINCT FROM to_jsonb(octet_length(NEW.envelope))
        OR NEW.publication_receipt->>'sha256' IS DISTINCT FROM encode(sha256(convert_to(NEW.envelope,'UTF8')),'hex')
        OR NOT COALESCE(length(NEW.publication_receipt->>'etag') BETWEEN 2 AND 1024,false)
        OR left(NEW.publication_receipt->>'etag',1) IS DISTINCT FROM '"'
        OR right(NEW.publication_receipt->>'etag',1) IS DISTINCT FROM '"'
        OR strpos(NEW.publication_receipt->>'etag',chr(13)) <> 0
        OR strpos(NEW.publication_receipt->>'etag',chr(10)) <> 0
      )) THEN
     RAISE EXCEPTION 'Recovery publication custody incomplete' USING ERRCODE='23514';
   END IF;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER recovery_publication_custody BEFORE INSERT OR UPDATE OR DELETE
  ON public.recovery_publications FOR EACH ROW EXECUTE FUNCTION public.vnbui_recovery_publication_custody();
REVOKE ALL ON FUNCTION public.vnbui_recovery_publication_custody() FROM PUBLIC;
"""


def upgrade():
    op.add_column("restores", Column("s3_recovery", JSONB(), nullable=True))
    op.alter_column("restores", "backup_id", nullable=True)
    op.create_check_constraint(
        "ck_restores_one_source",
        "restores",
        "(backup_id IS NOT NULL AND s3_recovery IS NULL) OR "
        "(backup_id IS NULL "
        "AND s3_recovery IS NOT NULL AND restore_to_original IS FALSE "
        "AND target_vm_id IS NULL AND (native_plan IS NULL) <> (kubevirt_plan IS NULL))",
    )
    op.execute("""
        CREATE FUNCTION public.vnbui_guard_s3_recovery_restore() RETURNS trigger
        LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
        BEGIN
          IF OLD.s3_recovery IS DISTINCT FROM NEW.s3_recovery
             OR (OLD.s3_recovery IS NOT NULL AND
                 (OLD.id, OLD.org_id, OLD.created_by, OLD.target_vm_name, OLD.native_plan, OLD.kubevirt_plan)
                 IS DISTINCT FROM
                 (NEW.id, NEW.org_id, NEW.created_by, NEW.target_vm_name, NEW.native_plan, NEW.kubevirt_plan)) THEN
            RAISE EXCEPTION 'Approved S3 recovery identity is immutable' USING ERRCODE='23514';
          END IF;
          RETURN NEW;
        END $$;
        CREATE TRIGGER guard_s3_recovery_restore BEFORE UPDATE ON public.restores
        FOR EACH ROW EXECUTE FUNCTION public.vnbui_guard_s3_recovery_restore();
    """)
    op.add_column(
        "backups",
        Column(
            "unverified_legacy_s3",
            Boolean,
            nullable=False,
            server_default=text("false"),
        ),
    )
    op.execute(LEGACY_S3_CUSTODY)
    op.create_table(
        "file_schedules",
        Column("id", String, primary_key=True),
        Column("agent_id", String, nullable=False),
        Column("file_set", String(63), nullable=False),
        Column("storage_endpoint", String(320), nullable=False),
        Column("storage_region", String(63), nullable=False),
        Column("storage_bucket", String(63), nullable=False),
        Column("storage_prefix", String(512), nullable=False),
        Column("storage_recipient_sha256", String(64), nullable=False),
        Column("name", String(255), nullable=False),
        Column("cron_expression", String(100), nullable=False),
        Column("enabled", Boolean, nullable=False),
        Column("authorized_by", String, nullable=False),
        Column("grant_id", String, nullable=False),
        Column("org_epoch", BigInteger, nullable=False),
        Column("created_at", DateTime(timezone=True), nullable=False),
        Column("retired_at", DateTime(timezone=True)),
        Column("last_run_at", DateTime(timezone=True)),
        Column("next_run_at", DateTime(timezone=True)),
        Column(
            "org_id",
            String,
            ForeignKey("organizations.id", name="fk_file_schedules_org_id"),
            nullable=False,
        ),
        UniqueConstraint(
            "org_id", "id", "agent_id", "file_set", name="uq_file_schedule_target"
        ),
        CheckConstraint(
            r"storage_endpoint ~ '^https://([a-z0-9.-]+|\[[0-9a-f:]+\])(:[1-9][0-9]{0,4})?$' "
            r"AND storage_region ~ '^[a-z0-9][a-z0-9-]{0,62}$'",
            name="ck_file_schedule_storage_origin",
        ),
        Index("ix_file_schedules_due", "org_id", "enabled", "next_run_at"),
    )
    op.create_table(
        "file_backups",
        Column("id", String, primary_key=True),
        Column("agent_id", String, nullable=False),
        Column("file_set", String(63), nullable=False),
        Column("storage_endpoint", String(320), nullable=False),
        Column("storage_region", String(63), nullable=False),
        Column("storage_bucket", String(63), nullable=False),
        Column("storage_prefix", String(512), nullable=False),
        Column("storage_recipient_sha256", String(64), nullable=False),
        Column("schedule_id", String),
        Column("schedule_grant_id", String),
        Column("scheduled_at", DateTime(timezone=True)),
        Column("actor_id", String),
        Column("request_key", String(128)),
        Column("status", String(16), nullable=False),
        Column("created_at", DateTime(timezone=True), nullable=False),
        Column("started_at", DateTime(timezone=True)),
        Column("dispatch_started_at", DateTime(timezone=True)),
        Column("agent_accepted_at", DateTime(timezone=True)),
        Column("completed_at", DateTime(timezone=True)),
        Column("next_check_at", DateTime(timezone=True), nullable=False),
        Column("check_token", String),
        Column("files", BigInteger),
        Column("directories", BigInteger),
        Column("bytes", BigInteger),
        Column("error", String(255)),
        Column("s3_path", String(2048)),
        Column("s3_version_id", String(1024)),
        Column("archive_format", String(40)),
        Column("archive_size_bytes", BigInteger),
        Column("archive_sha256", String(64)),
        Column("recipient_sha256", String(64)),
        Column(
            "org_id",
            String,
            ForeignKey("organizations.id", name="fk_file_backups_org_id"),
            nullable=False,
        ),
        ForeignKeyConstraint(
            ("org_id", "schedule_id", "agent_id", "file_set"),
            (
                "file_schedules.org_id",
                "file_schedules.id",
                "file_schedules.agent_id",
                "file_schedules.file_set",
            ),
            name="fk_file_backup_schedule_target",
        ),
        UniqueConstraint(
            "org_id", "actor_id", "request_key", name="uq_file_backup_request"
        ),
        UniqueConstraint(
            "schedule_id", "scheduled_at", name="uq_file_backup_occurrence"
        ),
        CheckConstraint(
            "(schedule_id IS NULL AND schedule_grant_id IS NULL AND scheduled_at IS NULL AND actor_id IS NOT NULL) OR "
            "(schedule_id IS NOT NULL AND schedule_grant_id IS NOT NULL AND scheduled_at IS NOT NULL AND actor_id IS NULL AND request_key IS NULL)",
            name="ck_file_backup_authority",
        ),
        CheckConstraint(
            "status IN ('pending', 'running', 'completed', 'failed') AND "
            "((status IN ('completed', 'failed')) = (completed_at IS NOT NULL))",
            name="ck_file_backup_status",
        ),
        CheckConstraint(
            "(status = 'completed' AND s3_path IS NOT NULL AND s3_version_id IS NOT NULL "
            "AND archive_format IS NOT NULL AND archive_size_bytes > 0 AND archive_size_bytes IS NOT NULL "
            "AND archive_sha256 IS NOT NULL AND recipient_sha256 IS NOT NULL "
            "AND files IS NOT NULL AND directories IS NOT NULL AND bytes IS NOT NULL AND error IS NULL) OR "
            "(status <> 'completed' AND s3_path IS NULL AND s3_version_id IS NULL "
            "AND archive_format IS NULL AND archive_size_bytes IS NULL AND archive_sha256 IS NULL "
            "AND recipient_sha256 IS NULL)",
            name="ck_file_backup_archive",
        ),
        CheckConstraint(
            r"storage_endpoint ~ '^https://([a-z0-9.-]+|\[[0-9a-f:]+\])(:[1-9][0-9]{0,4})?$' "
            r"AND storage_region ~ '^[a-z0-9][a-z0-9-]{0,62}$'",
            name="ck_file_backup_storage_origin",
        ),
        Index("ix_file_backups_ready", "org_id", "status", "next_check_at"),
        Index("ix_file_backups_target", "org_id", "agent_id", "file_set", "created_at"),
        Index("ix_file_backups_schedule", "org_id", "schedule_id", "scheduled_at"),
    )
    op.execute(CUSTODY)
    for table in ("file_schedules", "file_backups"):
        op.create_index(f"idx_{table}_org_id", table, ["org_id"])
        op.execute(f"ALTER TABLE public.{table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE public.{table} FORCE ROW LEVEL SECURITY")
        condition = "org_id = NULLIF(current_setting('app.current_org',true),'')"
        op.execute(
            f"CREATE POLICY tenant_isolation_{table} ON public.{table} "
            f"USING ({condition}) WITH CHECK ({condition})"
        )
        op.execute(f"REVOKE ALL ON public.{table} FROM PUBLIC")
        op.execute(
            f"CREATE TRIGGER file_custody BEFORE INSERT OR UPDATE OR DELETE "
            f"ON public.{table} FOR EACH ROW EXECUTE FUNCTION public.vnbui_file_custody()"
        )
    op.execute("REVOKE ALL ON FUNCTION public.vnbui_file_custody() FROM PUBLIC")

    op.create_table(
        "recovery_publications",
        Column(
            "generation_id",
            String,
            ForeignKey("storage_lineage_generations.id"),
            primary_key=True,
        ),
        Column(
            "org_id",
            String,
            ForeignKey("organizations.id", name="fk_recovery_publications_org_id"),
            nullable=False,
        ),
        Column("backup_id", String, ForeignKey("backups.id"), nullable=False),
        Column("object_key", String(1024), nullable=False),
        Column("created_at", DateTime(timezone=True), nullable=False),
        Column("next_attempt_at", DateTime(timezone=True), nullable=False),
        Column("attempt_count", Integer, nullable=False, server_default=text("0")),
        Column("last_failure_at", DateTime(timezone=True)),
        Column("claim_token", String, nullable=False),
        Column("envelope", Text),
        Column("published_at", DateTime(timezone=True)),
        Column("publication_receipt", JSONB(none_as_null=True)),
        UniqueConstraint("org_id", "backup_id", name="uq_recovery_publication_backup"),
        CheckConstraint(
            "attempt_count >= 0", name="ck_recovery_publication_attempt_count"
        ),
        Index("ix_recovery_publication_due", "org_id", "next_attempt_at"),
        Index("idx_recovery_publications_org_id", "org_id"),
    )
    op.execute(RECOVERY_CUSTODY)


def downgrade():
    # PostgreSQL refuses the downgrade if recovery jobs retain a NULL catalog ID.
    op.alter_column("restores", "backup_id", nullable=False)
    op.execute("DROP TRIGGER guard_s3_recovery_restore ON public.restores")
    op.execute("DROP FUNCTION public.vnbui_guard_s3_recovery_restore()")
    op.drop_constraint("ck_restores_one_source", "restores")
    op.drop_column("restores", "s3_recovery")
    # FORCE RLS also applies to a non-superuser owner. Do not use a query that
    # would mistake an inaccessible tenant's retained history for an empty table.
    op.execute("""
        DO $$
        DECLARE previous_platform text := current_setting('app.platform_admin',true);
        BEGIN
          PERFORM set_config('app.platform_admin','true',true);
          IF EXISTS(SELECT 1 FROM public.backups WHERE unverified_legacy_s3) THEN
            RAISE EXCEPTION 'Unverified legacy S3 custody is retained; downgrade refused';
          END IF;
          PERFORM set_config('app.platform_admin',coalesce(previous_platform,''),true);
          EXECUTE 'ALTER TABLE public.recovery_publications DISABLE ROW LEVEL SECURITY';
          IF EXISTS(SELECT 1 FROM public.recovery_publications) THEN
            RAISE EXCEPTION 'Signed recovery publication custody is retained; downgrade refused';
          END IF;
          EXECUTE 'ALTER TABLE public.file_backups DISABLE ROW LEVEL SECURITY';
          EXECUTE 'ALTER TABLE public.file_schedules DISABLE ROW LEVEL SECURITY';
          IF EXISTS(SELECT 1 FROM public.file_backups) OR
             EXISTS(SELECT 1 FROM public.file_schedules) THEN
            RAISE EXCEPTION 'Managed file custody is retained; downgrade refused';
          END IF;
        END $$;
    """)
    op.drop_table("recovery_publications")
    op.execute("DROP FUNCTION public.vnbui_recovery_publication_custody()")
    op.execute("DROP TRIGGER recovery_signer_marker ON public.settings_v3")
    op.execute("DROP FUNCTION public.vnbui_recovery_signer_marker()")
    op.drop_table("file_backups")
    op.drop_table("file_schedules")
    op.execute("DROP FUNCTION public.vnbui_file_custody()")

    op.execute("DROP TRIGGER unverified_legacy_s3_custody ON public.backups")
    op.execute("DROP FUNCTION public.vnbui_unverified_legacy_s3()")
    op.drop_column("backups", "unverified_legacy_s3")
