"""Read-only runtime lineage interface; no publication or historical adoption."""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = "storage_lineage"
down_revision = "backup_initiator"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "storage_lineage_generations",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column(
            "org_id", sa.String(), sa.ForeignKey("organizations.id"), nullable=False
        ),
        sa.Column("vm_id", sa.String(), sa.ForeignKey("vms.id"), nullable=False),
        sa.Column(
            "backup_id", sa.String(), sa.ForeignKey("backups.id"), nullable=False
        ),
        sa.Column(
            "root_backup_id", sa.String(), sa.ForeignKey("backups.id"), nullable=False
        ),
        sa.Column("state", sa.String(), nullable=False),
        sa.Column("receipt_sha256", sa.String(), nullable=False),
        sa.Column("root_receipt_sha256", sa.String(), nullable=False),
        sa.Column("manifest_receipt_sha256", sa.String(), nullable=False),
        sa.Column("tracker_uid", sa.String(), nullable=False),
        sa.Column("checkpoint", sa.String(), nullable=False),
        sa.Column("accepted_request", JSONB(), nullable=False),
    )
    op.create_index(
        "ix_storage_lineage_generations_vm_id", "storage_lineage_generations", ["vm_id"]
    )
    op.create_table(
        "storage_lineage_heads",
        sa.Column("vm_id", sa.String(), sa.ForeignKey("vms.id"), primary_key=True),
        sa.Column(
            "org_id", sa.String(), sa.ForeignKey("organizations.id"), nullable=False
        ),
        sa.Column(
            "generation_id",
            sa.String(),
            sa.ForeignKey("storage_lineage_generations.id"),
            nullable=False,
        ),
        sa.Column("state", sa.String(), nullable=False),
        sa.Column("manifest_receipt_sha256", sa.String(), nullable=False),
        sa.Column(
            "root_backup_id", sa.String(), sa.ForeignKey("backups.id"), nullable=False
        ),
        sa.Column("tracker_uid", sa.String(), nullable=False),
        sa.Column("checkpoint", sa.String(), nullable=False),
    )
    # Any future writer must acquire the same VM lock as D02. Holding only a
    # head-row lock would not fence an absent/new head or a generation insertion.
    op.execute("""CREATE FUNCTION vnbui_lineage_fence() RETURNS trigger
        LANGUAGE plpgsql AS $$ DECLARE source_org text; BEGIN
        IF TG_OP='DELETE' THEN
            RAISE EXCEPTION 'Lineage facts must be retained' USING ERRCODE='23514';
        END IF;
        IF TG_OP='UPDATE' THEN
            IF TG_TABLE_NAME='storage_lineage_generations' OR
               ROW(NEW.org_id,NEW.vm_id) IS DISTINCT FROM ROW(OLD.org_id,OLD.vm_id) THEN
                RAISE EXCEPTION 'Lineage identity is immutable' USING ERRCODE='23514';
            END IF;
        END IF;
        SELECT org_id INTO source_org FROM vms WHERE id=NEW.vm_id FOR UPDATE;
        IF source_org IS NULL OR source_org IS DISTINCT FROM NEW.org_id THEN
            RAISE EXCEPTION 'Lineage source organization mismatch' USING ERRCODE='23514';
        END IF;
        RETURN NEW; END $$""")
    for table in ("storage_lineage_generations", "storage_lineage_heads"):
        op.create_index(f"idx_{table}_org_id", table, ["org_id"])
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
        op.execute(
            f"""CREATE POLICY tenant_isolation_{table} ON {table}
            USING (org_id = NULLIF(current_setting('app.current_org', true), ''))
            WITH CHECK (org_id = NULLIF(current_setting('app.current_org', true), ''))"""
        )
        op.execute(f"REVOKE ALL ON {table} FROM PUBLIC")
        op.execute(
            f"""CREATE TRIGGER lineage_fence BEFORE INSERT OR UPDATE OR DELETE ON {table}
            FOR EACH ROW EXECUTE FUNCTION vnbui_lineage_fence()"""
        )


def downgrade():
    raise RuntimeError("Lineage authority requires reviewed database/image rollback")
