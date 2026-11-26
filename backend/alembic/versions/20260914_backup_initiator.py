"""Retain initiating authority; historical NULL is not adoptable authority."""

from alembic import op
import sqlalchemy as sa

revision = "backup_initiator"
down_revision = "storage_dispatch_custody"
branch_labels = None
depends_on = None


def upgrade():
    for table in ("backups", "backup_queue"):
        op.add_column(
            table, sa.Column("initiating_user_id", sa.String(), nullable=True)
        )
        op.create_foreign_key(
            f"fk_{table}_initiator", table, "users", ["initiating_user_id"], ["id"]
        )
        op.create_index(f"ix_{table}_initiating_user_id", table, ["initiating_user_id"])
    # No backfill from tags, created_by, scheduler identity, or worker context.
    op.add_column(
        "backup_queue", sa.Column("started_backup_id", sa.String(), nullable=True)
    )
    op.create_foreign_key(
        "fk_backup_queue_started_backup",
        "backup_queue",
        "backups",
        ["started_backup_id"],
        ["id"],
    )
    op.create_index(
        "ix_backup_queue_started_backup_id", "backup_queue", ["started_backup_id"]
    )
    op.execute("""CREATE FUNCTION vnbui_backup_initiator() RETURNS trigger
        LANGUAGE plpgsql AS $$
        DECLARE source_org text;
        BEGIN
        IF TG_OP='UPDATE' THEN
            IF NEW.initiating_user_id IS DISTINCT FROM OLD.initiating_user_id THEN
                RAISE EXCEPTION 'Initiating principal is immutable' USING ERRCODE='23514';
            END IF;
            IF OLD.initiating_user_id IS NOT NULL AND NEW.vm_id IS DISTINCT FROM OLD.vm_id THEN
                RAISE EXCEPTION 'Initiating source is immutable' USING ERRCODE='23514';
            END IF;
            RETURN NEW;
        END IF;
        IF NEW.initiating_user_id IS NULL THEN RETURN NEW; END IF;
        SELECT org_id INTO source_org FROM vms WHERE id=NEW.vm_id;
        IF source_org IS NULL OR NOT EXISTS (
            SELECT 1 FROM users u JOIN organizations o ON o.id=u.org_id
            WHERE u.id=NEW.initiating_user_id AND u.org_id=source_org
              AND u.is_active AND o.enabled AND u.role IN ('admin','operator')
        ) THEN
            RAISE EXCEPTION 'Initiating principal unavailable' USING ERRCODE='23514';
        END IF;
        RETURN NEW;
        END $$""")
    for table in ("backups", "backup_queue"):
        op.execute(f"""CREATE TRIGGER backup_initiator
            BEFORE INSERT OR UPDATE ON {table} FOR EACH ROW
            EXECUTE FUNCTION vnbui_backup_initiator()""")
    op.execute("""CREATE FUNCTION vnbui_queue_started_backup() RETURNS trigger
        LANGUAGE plpgsql AS $$ BEGIN
        IF TG_OP='UPDATE' AND OLD.started_backup_id IS NOT NULL
          AND NEW.started_backup_id IS DISTINCT FROM OLD.started_backup_id THEN
            RAISE EXCEPTION 'Queue backup binding is immutable' USING ERRCODE='23514';
        END IF;
        IF NEW.started_backup_id IS NOT NULL AND NOT EXISTS (
            SELECT 1 FROM backups b WHERE b.id=NEW.started_backup_id
              AND b.vm_id=NEW.vm_id AND b.initiating_user_id=NEW.initiating_user_id
        ) THEN
            RAISE EXCEPTION 'Queue backup has no matching initiator' USING ERRCODE='23514';
        END IF;
        RETURN NEW; END $$""")
    op.execute(
        """CREATE TRIGGER queue_started_backup BEFORE INSERT OR UPDATE ON backup_queue
        FOR EACH ROW EXECUTE FUNCTION vnbui_queue_started_backup()"""
    )


def downgrade():
    raise RuntimeError("Initiating authority requires reviewed database/image rollback")
