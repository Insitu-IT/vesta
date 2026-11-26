"""Preserve VM incarnation and inventory history without reinterpreting legacy UIDs."""

import sqlalchemy as sa
from alembic import op

revision = "vm_inventory_identity"
down_revision = "tenant_enforcement"
branch_labels = None
depends_on = None


def upgrade():
    for name, size in (
        ("provider", 32),
        ("namespace", 255),
        ("vm_uid", 64),
        ("vmi_uid", 64),
    ):
        op.add_column("vms", sa.Column(name, sa.String(size), nullable=True))
    op.add_column(
        "vms",
        sa.Column(
            "inventory_present", sa.Boolean(), nullable=False, server_default=sa.true()
        ),
    )
    op.add_column("vms", sa.Column("last_observed_at", sa.DateTime(), nullable=True))
    op.add_column("vms", sa.Column("absent_since", sa.DateTime(), nullable=True))
    op.add_column("vms", sa.Column("replaces_vm_id", sa.String(), nullable=True))
    op.create_foreign_key("fk_vm_replaces", "vms", "vms", ["replaces_vm_id"], ["id"])
    op.create_unique_constraint(
        "uq_vm_identity", "vms", ["agent_id", "provider", "namespace", "vm_uid"]
    )
    # FK existence alone bypasses RLS; predecessor attribution must not.
    op.execute("""CREATE FUNCTION vnbui_vm_predecessor_scope() RETURNS trigger
        LANGUAGE plpgsql AS $$ BEGIN
        IF TG_OP='UPDATE' THEN
            IF NEW.agent_id IS DISTINCT FROM OLD.agent_id
                OR NEW.uuid IS DISTINCT FROM OLD.uuid
                OR (OLD.provider IS NULL AND
                    COALESCE(NEW.vm_metadata->>'provider','libvirt') IS DISTINCT FROM
                    COALESCE(OLD.vm_metadata->>'provider','libvirt')) THEN
                RAISE EXCEPTION 'VM source identity is immutable' USING ERRCODE='23514';
            END IF;
            IF ROW(NEW.provider,NEW.namespace,NEW.vm_uid)
                IS DISTINCT FROM ROW(OLD.provider,OLD.namespace,OLD.vm_uid)
                AND NOT (
                    OLD.provider IS NULL AND OLD.namespace IS NULL AND OLD.vm_uid IS NULL
                    AND OLD.uuid IS NOT NULL AND OLD.uuid<>''
                    AND COALESCE(OLD.vm_metadata->>'provider','libvirt')='libvirt'
                    AND NEW.provider IS NOT DISTINCT FROM 'libvirt'
                    AND NEW.namespace IS NOT DISTINCT FROM ''
                    AND NEW.vm_uid IS NOT DISTINCT FROM OLD.uuid
                ) THEN
                RAISE EXCEPTION 'VM source identity is immutable' USING ERRCODE='23514';
            END IF;
            IF OLD.replaces_vm_id IS NOT NULL
                AND NEW.replaces_vm_id IS DISTINCT FROM OLD.replaces_vm_id THEN
                RAISE EXCEPTION 'VM predecessor attribution is immutable' USING ERRCODE='23514';
            END IF;
        END IF;
        IF NEW.replaces_vm_id IS NOT NULL AND NOT EXISTS (
            SELECT 1 FROM vms p WHERE p.id=NEW.replaces_vm_id
            AND p.org_id=NEW.org_id AND p.agent_id=NEW.agent_id AND p.id<>NEW.id
        ) THEN
            RAISE EXCEPTION 'VM predecessor is outside source owner scope'
                USING ERRCODE='23503';
        END IF;
        RETURN NEW;
        END $$""")
    op.execute("""CREATE TRIGGER vm_predecessor_scope BEFORE INSERT OR UPDATE ON vms
        FOR EACH ROW EXECUTE FUNCTION vnbui_vm_predecessor_scope()""")


def downgrade():
    raise RuntimeError(
        "Identity history cannot be safely downgraded; restore a pre-migration database backup"
    )
