"""Enforce authenticated tenant context without a database-default fallback.

Revision ID: tenant_enforcement
Revises: oss_schema_parity
"""

from alembic import op
import sqlalchemy as sa

revision = "tenant_enforcement"
down_revision = "oss_schema_parity"
branch_labels = None
depends_on = None

TABLES = (
    "users",
    "agents",
    "vms",
    "vm_groups",
    "backups",
    "s3_publications",
    "schedules",
    "restores",
    "notification_rules",
    "backup_verifications",
    "saved_searches",
    "reports",
    "report_executions",
    "notification_logs",
    "encryption_keys",
)

REFERENCES = {
    "s3_publications": (("backup_id", "backups"),),
    "vms": (("agent_id", "agents"),),
    "backups": (
        ("vm_id", "vms"),
        ("parent_backup_id", "backups"),
        ("chain_id", "backups"),
        ("encryption_key_id", "encryption_keys"),
    ),
    "schedules": (("vm_id", "vms"), ("vm_group_id", "vm_groups")),
    "restores": (
        ("backup_id", "backups"),
        ("target_vm_id", "vms"),
        ("created_by", "users"),
    ),
    "notification_rules": (("created_by", "users"),),
    "backup_verifications": (("backup_id", "backups"), ("created_by", "users")),
    "saved_searches": (("created_by", "users"),),
    "reports": (("created_by", "users"),),
    "report_executions": (("report_id", "reports"),),
    "notification_logs": (("rule_id", "notification_rules"),),
    "encryption_keys": (("created_by", "users"), ("replaced_by_id", "encryption_keys")),
}

# These children inherit identity from an immutable tenant-owned parent. They
# have no independent organization assignment that can drift from that parent.
CHILDREN = {
    "activity_logs": ("user_id", "users"),
    "orchestrator_api_keys": ("created_by", "users"),
    "agent_registration_keys": ("created_by", "users"),
    "agent_api_keys": ("agent_id", "agents"),
    "agent_certificates": ("agent_id", "agents"),
}


def enforce_access_audit():
    # The measured deployed predecessor has neither this table nor its triggers.
    # Keep the historical layout and bytes when they exist. In particular, a
    # missing historical organization is not permission to infer one from a
    # mutable (or already deleted) source row. Such history is platform-only.
    op.execute("""CREATE TABLE IF NOT EXISTS public.access_audit (
        id SERIAL PRIMARY KEY, table_name TEXT NOT NULL, operation TEXT NOT NULL,
        org_id TEXT, user_id TEXT, accessed_at TIMESTAMP DEFAULT NOW(), row_id TEXT
    )""")
    inspector = sa.inspect(op.get_bind())
    expected = {
        "id",
        "table_name",
        "operation",
        "org_id",
        "user_id",
        "accessed_at",
        "row_id",
    }
    if {c["name"] for c in inspector.get_columns("access_audit")} != expected:
        raise RuntimeError(
            "Unrecognized access_audit shape; operator disposition required"
        )
    if (
        op.get_bind()
        .execute(
            sa.text(
                "SELECT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname='public' "
                "AND tablename='access_audit')"
            )
        )
        .scalar_one()
    ):
        raise RuntimeError(
            "Unrecognized access_audit policies; operator disposition required"
        )
    op.execute("ALTER TABLE public.access_audit ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE public.access_audit FORCE ROW LEVEL SECURITY")
    predicate = """(NULLIF(org_id, '') = NULLIF(current_setting('app.current_org', true), '')
        OR current_setting('app.platform_admin', true) = 'true')"""
    op.execute(
        f"CREATE POLICY audit_read ON public.access_audit FOR SELECT USING ({predicate})"
    )
    # No UPDATE or DELETE policy, including for platform scope. The runtime
    # grant contract independently excludes both privileges and TRUNCATE.
    op.execute(f"""CREATE POLICY audit_append ON public.access_audit FOR INSERT
        WITH CHECK (NULLIF(org_id, '') IS NOT NULL AND {predicate})""")
    op.execute("""CREATE OR REPLACE FUNCTION public.audit_access() RETURNS trigger
        LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog AS $$
        DECLARE audited record;
        BEGIN
            IF TG_OP = 'DELETE' THEN audited := OLD; ELSE audited := NEW; END IF;
            IF NULLIF(audited.org_id, '') IS NULL THEN
                RAISE EXCEPTION 'Audited row requires persisted organization attribution'
                    USING ERRCODE = '23514';
            END IF;
            INSERT INTO public.access_audit(table_name, operation, org_id, user_id, row_id)
            VALUES (TG_TABLE_NAME, TG_OP, audited.org_id,
                NULLIF(current_setting('app.user_id', true), ''), audited.id::text);
            RETURN audited;
        END $$""")
    for table in ("backups", "agents", "users"):
        op.execute(f"DROP TRIGGER IF EXISTS audit_{table}_access ON public.{table}")
        op.execute(f"""CREATE TRIGGER audit_{table}_access
            AFTER INSERT OR UPDATE OR DELETE ON public.{table}
            FOR EACH ROW EXECUTE FUNCTION public.audit_access()""")


def attribute_encryption_keys():
    op.add_column("encryption_keys", sa.Column("org_id", sa.String(), nullable=True))
    # Rotation links transfer the same key lineage. Collect all creator and
    # backup-owner evidence over the undirected rotation component; choosing
    # one source preferentially would conceal a historically shared KEK.
    rows = op.get_bind().execute(sa.text("""WITH RECURSIVE
        edges(a,b) AS (
            SELECT id,replaced_by_id FROM encryption_keys WHERE replaced_by_id IS NOT NULL
            UNION SELECT replaced_by_id,id FROM encryption_keys WHERE replaced_by_id IS NOT NULL
        ), reach(root,id) AS (
            SELECT id,id FROM encryption_keys
            UNION SELECT r.root,e.b FROM reach r JOIN edges e ON e.a=r.id
        ), evidence(id,org_id) AS (
            SELECT k.id,u.org_id FROM encryption_keys k JOIN users u ON u.id=k.created_by
            UNION SELECT encryption_key_id,org_id FROM backups WHERE encryption_key_id IS NOT NULL
        ) SELECT r.root,array_agg(DISTINCT e.org_id) FILTER (WHERE e.org_id IS NOT NULL)
          FROM reach r LEFT JOIN evidence e ON e.id=r.id GROUP BY r.root
    """)).all()
    organizations = (
        op.get_bind().execute(sa.text("SELECT id FROM organizations")).scalars().all()
    )
    for key_id, owners in rows:
        if not owners and len(organizations) == 1:
            owners = organizations
        if not owners or len(owners) != 1:
            raise RuntimeError(
                "Ambiguous encryption-key history; operator attribution required before migration"
            )
        op.get_bind().execute(
            sa.text("UPDATE encryption_keys SET org_id=:org WHERE id=:id"),
            {"org": owners[0], "id": key_id},
        )
    op.alter_column("encryption_keys", "org_id", nullable=False)
    op.create_foreign_key(
        "fk_encryption_keys_org_id",
        "encryption_keys",
        "organizations",
        ["org_id"],
        ["id"],
    )
    op.create_index("idx_encryption_keys_org_id", "encryption_keys", ["org_id"])


def enforce_system_events():
    op.add_column("system_events", sa.Column("org_id", sa.String(), nullable=True))
    op.add_column(
        "system_events", sa.Column("attribution", sa.String(32), nullable=True)
    )
    resource_tables = {
        "agent": "agents",
        "backup": "backups",
        "vm": "vms",
        "schedule": "schedules",
        "user": "users",
        "restore": "restores",
    }
    evidence = []
    for kind, table in resource_tables.items():
        evidence.append(
            f"SELECT e.id,p.org_id FROM system_events e JOIN {table} p "
            f"ON e.resource_type='{kind}' AND p.id=e.resource_id "
            "AND e.source <> 'operator_command'"
        )
    for source, table in (("agent", "agents"), ("scheduler", "schedules")):
        evidence.append(
            f"SELECT e.id,p.org_id FROM system_events e JOIN {table} p "
            f"ON e.source='{source}' AND p.id=e.source_id"
        )
    rows = (
        op.get_bind()
        .execute(
            sa.text(
                "WITH evidence AS (" + " UNION ".join(evidence) + ") "
                "SELECT e.id,array_agg(DISTINCT p.org_id) FILTER (WHERE p.org_id IS NOT NULL) "
                "FROM system_events e LEFT JOIN evidence p ON p.id=e.id GROUP BY e.id"
            )
        )
        .all()
    )
    for event_id, owners in rows:
        if owners and len(owners) != 1:
            raise RuntimeError(
                "Conflicting system-event ownership requires operator attribution"
            )
        op.get_bind().execute(
            sa.text(
                "UPDATE system_events SET org_id=:org,attribution=:kind WHERE id=:id"
            ),
            {
                "id": event_id,
                "org": owners[0] if owners else None,
                "kind": "tenant" if owners else "legacy_unattributed",
            },
        )
    op.alter_column("system_events", "attribution", nullable=False)
    op.create_index("idx_system_events_org_id", "system_events", ["org_id"])
    op.create_check_constraint(
        "ck_system_events_attribution",
        "system_events",
        "(attribution='tenant' AND org_id IS NOT NULL AND org_id <> '') OR "
        "(attribution IN ('platform','legacy_unattributed') AND org_id IS NULL)",
    )
    op.execute("ALTER TABLE system_events ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE system_events FORCE ROW LEVEL SECURITY")
    platform = "current_setting('app.platform_admin',true)='true'"
    tenant = "attribution='tenant' AND org_id=current_setting('app.current_org',true)"
    op.execute(
        f"CREATE POLICY event_read ON system_events FOR SELECT USING ({platform} OR ({tenant}))"
    )
    op.execute(
        f"CREATE POLICY event_append ON system_events FOR INSERT WITH CHECK "
        f"(({tenant}) OR ({platform} AND attribution='platform'))"
    )
    # A reported source/resource is metadata, never authority. Validate any live
    # recognized parent against the writer. A vanished parent cannot authorize
    # a new reference; previously recorded events retain durable ownership.
    checks = []
    for kind, table in resource_tables.items():
        checks.append(
            f"""IF NEW.resource_type='{kind}' AND NEW.resource_id IS NOT NULL
            AND NOT EXISTS (SELECT 1 FROM public.{table} p WHERE p.id=NEW.resource_id AND p.org_id=NEW.org_id)
            THEN RAISE EXCEPTION 'Event resource unavailable in organization' USING ERRCODE='23514'; END IF;"""
        )
    for source, table in (("agent", "agents"), ("scheduler", "schedules")):
        checks.append(
            f"""IF NEW.source='{source}' AND NEW.source_id IS NOT NULL
            AND NOT EXISTS (SELECT 1 FROM public.{table} p WHERE p.id=NEW.source_id AND p.org_id=NEW.org_id)
            THEN RAISE EXCEPTION 'Event source unavailable in organization' USING ERRCODE='23514'; END IF;"""
        )
    op.execute(
        """CREATE FUNCTION public.vnbui_event_scope() RETURNS trigger LANGUAGE plpgsql
        SECURITY INVOKER SET search_path=pg_catalog AS $$ BEGIN
        IF TG_OP <> 'INSERT' THEN RAISE EXCEPTION 'System events are immutable' USING ERRCODE='23514'; END IF;
        IF NEW.attribution='tenant' THEN """
        + "\n".join(checks)
        + """
        END IF; RETURN NEW; END $$"""
    )
    op.execute(
        """CREATE TRIGGER event_scope BEFORE INSERT OR UPDATE OR DELETE ON system_events
        FOR EACH ROW EXECUTE FUNCTION public.vnbui_event_scope()"""
    )


def upgrade():
    # Inspect the complete pre-enforcement dataset as the migration owner.
    # row_security=off raises rather than silently returning a policy-filtered
    # subset if this connection cannot see every existing attribution.
    op.execute("SET LOCAL row_security = off")
    # Existing S3 paths are deliberately NOT backfilled into ownership claims.
    # Current credentials/configuration cannot establish their publication origin.
    op.create_table(
        "s3_publications",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column(
            "org_id",
            sa.String(),
            sa.ForeignKey("organizations.id", name="fk_s3_publications_org_id"),
            nullable=False,
        ),
        sa.Column(
            "backup_id", sa.String(), sa.ForeignKey("backups.id"), nullable=False
        ),
        sa.Column("kind", sa.String(), nullable=False),
        sa.Column("endpoint", sa.String(), nullable=False),
        sa.Column("bucket", sa.String(), nullable=False),
        sa.Column("object_key", sa.String(), nullable=False),
        sa.Column("expected_plan", sa.JSON(), nullable=True),
        sa.Column("prepared_receipt", sa.JSON(), nullable=True),
        sa.Column("receipt_transaction_id", sa.BigInteger(), nullable=True),
        sa.Column("state", sa.String(), nullable=False, server_default="reserved"),
        sa.UniqueConstraint("backup_id", "kind", name="uq_s3_publication_backup_kind"),
        sa.UniqueConstraint(
            "endpoint", "bucket", "object_key", name="uq_s3_publication_object"
        ),
        sa.CheckConstraint(
            "kind IN ('payload', 'chain_manifest')", name="ck_s3_publication_kind"
        ),
        sa.CheckConstraint(
            "state IN ('reserved', 'published', 'cleanup_required', 'deleted')",
            name="ck_s3_publication_state",
        ),
    )
    op.create_index("idx_s3_publications_org_id", "s3_publications", ["org_id"])
    op.execute("""CREATE FUNCTION vnbui_s3_publication_immutable() RETURNS trigger
        LANGUAGE plpgsql AS $$ BEGIN
            IF TG_OP = 'DELETE' THEN
                RAISE EXCEPTION 'Storage ownership records must be retained' USING ERRCODE='23514';
            END IF;
            IF NEW.object_key IS DISTINCT FROM (
                'vnbui-owned/v1/' || encode(sha256(convert_to(NEW.org_id, 'UTF8')), 'hex') || '/' ||
                encode(sha256(convert_to(NEW.backup_id, 'UTF8')), 'hex') || '/' ||
                CASE NEW.kind WHEN 'payload' THEN 'payload/' WHEN 'chain_manifest' THEN 'chain.json' END) THEN
                RAISE EXCEPTION 'Storage key is outside immutable owner namespace' USING ERRCODE='23514';
            END IF;
            IF TG_OP = 'INSERT' THEN
                IF NEW.state <> 'reserved' OR NEW.prepared_receipt IS NOT NULL
                   OR NEW.receipt_transaction_id IS NOT NULL THEN
                    RAISE EXCEPTION 'Publication must begin with a reservation' USING ERRCODE='23514';
                END IF;
                RETURN NEW;
            END IF;
            IF ROW(NEW.id, NEW.org_id, NEW.backup_id, NEW.kind, NEW.endpoint, NEW.bucket, NEW.object_key)
               IS DISTINCT FROM
               ROW(OLD.id, OLD.org_id, OLD.backup_id, OLD.kind, OLD.endpoint, OLD.bucket, OLD.object_key) THEN
                RAISE EXCEPTION 'Storage ownership is immutable' USING ERRCODE='23514';
            END IF;
            IF OLD.state = 'deleted' AND NEW.state <> 'deleted' THEN
                RAISE EXCEPTION 'Deleted publication cannot be reused' USING ERRCODE='23514';
            END IF;
            IF OLD.expected_plan IS NOT NULL AND
               NEW.expected_plan::jsonb IS DISTINCT FROM OLD.expected_plan::jsonb THEN
                RAISE EXCEPTION 'Artifact plan is immutable' USING ERRCODE='23514';
            END IF;
            IF OLD.prepared_receipt IS NOT NULL AND
               NEW.prepared_receipt::jsonb IS DISTINCT FROM OLD.prepared_receipt::jsonb THEN
                RAISE EXCEPTION 'Prepared receipt is immutable' USING ERRCODE='23514';
            END IF;
            IF NEW.receipt_transaction_id IS DISTINCT FROM OLD.receipt_transaction_id THEN
                RAISE EXCEPTION 'Receipt transaction identity is database-owned' USING ERRCODE='23514';
            END IF;
            IF OLD.prepared_receipt IS NULL AND NEW.prepared_receipt IS NOT NULL AND
               (OLD.state <> 'reserved' OR NEW.state <> 'reserved' OR NEW.expected_plan IS NULL) THEN
                RAISE EXCEPTION 'Prepared receipt requires a planned reservation' USING ERRCODE='23514';
            END IF;
            IF OLD.prepared_receipt IS NULL AND NEW.prepared_receipt IS NOT NULL THEN
                NEW.receipt_transaction_id := txid_current();
            END IF;
            IF NEW.state = 'published' AND OLD.state <> 'published' AND
               (OLD.prepared_receipt IS NULL OR OLD.receipt_transaction_id IS NULL
                OR OLD.receipt_transaction_id = txid_current()) THEN
                RAISE EXCEPTION 'Publication requires receipt committed in a prior transaction' USING ERRCODE='23514';
            END IF;
            IF OLD.expected_plan IS NULL AND NEW.expected_plan IS NOT NULL AND OLD.state <> 'reserved' THEN
                RAISE EXCEPTION 'Only a reservation may acquire an artifact plan' USING ERRCODE='23514';
            END IF;
            IF (OLD.state = 'published' AND NEW.state = 'reserved') OR
               (OLD.state = 'cleanup_required' AND NEW.state NOT IN ('cleanup_required', 'deleted')) THEN
                RAISE EXCEPTION 'Publication lineage cannot move backwards' USING ERRCODE='23514';
            END IF;
            RETURN NEW;
        END $$""")
    op.execute(
        """CREATE TRIGGER storage_ownership_immutable BEFORE INSERT OR UPDATE OR DELETE ON s3_publications
        FOR EACH ROW EXECUTE FUNCTION vnbui_s3_publication_immutable()"""
    )
    attribute_encryption_keys()
    enforce_system_events()
    # Rule-less notifications are emitted by the active sender, not malformed
    # children. Historical attribution is only unambiguous on a single-org
    # installation; do not guess an owner from a recipient or message body.
    op.add_column("notification_logs", sa.Column("org_id", sa.String(), nullable=True))
    op.execute("""UPDATE notification_logs n SET org_id=r.org_id
        FROM notification_rules r WHERE r.id=n.rule_id""")
    unresolved = (
        op.get_bind()
        .execute(
            sa.text(
                "SELECT EXISTS (SELECT 1 FROM notification_logs WHERE org_id IS NULL)"
            )
        )
        .scalar_one()
    )
    if unresolved:
        organizations = (
            op.get_bind()
            .execute(sa.text("SELECT id FROM organizations"))
            .scalars()
            .all()
        )
        if len(organizations) != 1:
            raise RuntimeError(
                "Unattributed notification history requires operator disposition before migration"
            )
        op.get_bind().execute(
            sa.text("UPDATE notification_logs SET org_id=:org WHERE org_id IS NULL"),
            {"org": organizations[0]},
        )
    op.alter_column("notification_logs", "org_id", nullable=False)
    op.create_foreign_key(
        "fk_notification_logs_org_id",
        "notification_logs",
        "organizations",
        ["org_id"],
        ["id"],
    )
    op.create_index("idx_notification_logs_org_id", "notification_logs", ["org_id"])
    for column, parent in (("created_by", "users"), ("schedule_id", "schedules")):
        if (
            op.get_bind()
            .execute(
                sa.text(
                    f"SELECT EXISTS (SELECT 1 FROM backup_queue q JOIN vms v ON v.id=q.vm_id "
                    f"JOIN {parent} p ON p.id=q.{column} WHERE p.org_id IS DISTINCT FROM v.org_id)"
                )
            )
            .scalar_one()
        ):
            raise RuntimeError(
                f"Cross-organization queue {column}; operator disposition required before migration"
            )
    if op.get_bind().execute(sa.text("""
        SELECT EXISTS (SELECT 1 FROM vm_group_members m
        JOIN vms v ON v.id=m.vm_id JOIN vm_groups g ON g.id=m.group_id
        WHERE v.org_id IS DISTINCT FROM g.org_id)
    """)).scalar_one():
        raise RuntimeError(
            "Cross-organization VM group membership exists; operator disposition required before migration"
        )
    for table, references in REFERENCES.items():
        for column, parent in references:
            bad_existing = (
                op.get_bind()
                .execute(
                    sa.text(
                        f"SELECT EXISTS (SELECT 1 FROM {table} c JOIN {parent} p ON p.id=c.{column} WHERE p.org_id IS DISTINCT FROM c.org_id)"
                    )
                )
                .scalar_one()
            )
            if bad_existing:
                raise RuntimeError(
                    f"Cross-organization attribution exists in {table}.{column}; operator disposition required before migration"
                )
    op.execute("SET LOCAL row_security = on")
    op.add_column(
        "users",
        sa.Column(
            "is_platform_admin",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
    )
    inspector = sa.inspect(op.get_bind())
    for table, column in (
        ("users", "username"),
        ("agents", "hostname"),
        ("vm_groups", "name"),
    ):
        for constraint in inspector.get_unique_constraints(table):
            if constraint["column_names"] == [column]:
                op.drop_constraint(constraint["name"], table, type_="unique")
        for index in inspector.get_indexes(table):
            if (
                index["column_names"] == [column]
                and index["unique"]
                and not index.get("duplicates_constraint")
            ):
                op.drop_index(index["name"], table_name=table)
        op.create_unique_constraint(
            f"uq_{table}_org_{column}", table, ["org_id", column]
        )
    # Keep the non-unique username lookup index after replacing its unique form.
    if not any(
        index["name"] == "ix_users_username" and not index["unique"]
        for index in sa.inspect(op.get_bind()).get_indexes("users")
    ):
        op.create_index("ix_users_username", "users", ["username"])

    op.execute("""
        CREATE FUNCTION vnbui_org_immutable() RETURNS trigger
        LANGUAGE plpgsql AS $$ BEGIN
            IF NEW.org_id IS DISTINCT FROM OLD.org_id THEN
                RAISE EXCEPTION 'Organization attribution is immutable'
                    USING ERRCODE = '23514';
            END IF;
            RETURN NEW;
        END $$
    """)
    for table in TABLES:
        op.execute(
            f"CREATE TRIGGER tenant_identity_immutable BEFORE UPDATE OF org_id ON {table} FOR EACH ROW EXECUTE FUNCTION vnbui_org_immutable()"
        )
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation_{table} ON {table}")
        op.execute(f"DROP POLICY IF EXISTS admin_bypass_{table} ON {table}")
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
        predicate = "(org_id = NULLIF(current_setting('app.current_org', true), '') OR current_setting('app.platform_admin', true) = 'true')"
        op.execute(
            f"CREATE POLICY tenant_isolation_{table} ON {table} "
            f"USING ({predicate}) WITH CHECK ({predicate})"
        )
    # PostgreSQL FK checks intentionally bypass RLS. Existing FKs stay intact;
    # these invoker-rights checks also require same-org attribution. The parent
    # org is immutable above, so a later parent update cannot break this bound.
    for table, references in REFERENCES.items():
        checks = []
        for column, parent in references:
            self_reference = f" AND NEW.{column} <> NEW.id" if parent == table else ""
            checks.append(f"""
                IF NEW.{column} IS NOT NULL{self_reference} AND NOT EXISTS (
                    SELECT 1 FROM {parent} WHERE id=NEW.{column} AND org_id=NEW.org_id
                ) THEN
                    RAISE EXCEPTION 'Referenced row is outside organization scope'
                        USING ERRCODE = '23503';
                END IF;
            """)
        op.execute(
            f"CREATE FUNCTION vnbui_scope_{table}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN {''.join(checks)} RETURN NEW; END $$"
        )
        op.execute(
            f"CREATE TRIGGER tenant_reference_scope BEFORE INSERT OR UPDATE ON {table} FOR EACH ROW EXECUTE FUNCTION vnbui_scope_{table}()"
        )

    for table, (column, parent) in CHILDREN.items():
        predicate = f"EXISTS (SELECT 1 FROM {parent} p WHERE p.id={table}.{column})"
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
        op.execute(
            f"CREATE POLICY tenant_parent_scope ON {table} USING ({predicate}) WITH CHECK ({predicate})"
        )

    # Both association endpoints must be visible AND share identity, even for
    # an explicit platform operation. FK existence alone bypasses parent RLS.
    group_predicate = """EXISTS (
        SELECT 1 FROM vms v JOIN vm_groups g ON g.org_id=v.org_id
        WHERE v.id=vm_group_members.vm_id AND g.id=vm_group_members.group_id
    )"""
    op.execute("ALTER TABLE vm_group_members ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE vm_group_members FORCE ROW LEVEL SECURITY")
    op.execute(
        f"CREATE POLICY tenant_parent_scope ON vm_group_members USING ({group_predicate}) WITH CHECK ({group_predicate})"
    )

    # A queue item always belongs to its VM. Optional creator/schedule may be
    # absent for automated work, but a present reference must share that VM's
    # organization even during a platform operation.
    queue_predicate = """EXISTS (
        SELECT 1 FROM vms v WHERE v.id=backup_queue.vm_id
        AND (backup_queue.created_by IS NULL OR EXISTS (
            SELECT 1 FROM users u WHERE u.id=backup_queue.created_by AND u.org_id=v.org_id))
        AND (backup_queue.schedule_id IS NULL OR EXISTS (
            SELECT 1 FROM schedules s WHERE s.id=backup_queue.schedule_id AND s.org_id=v.org_id))
    )"""
    op.execute("ALTER TABLE backup_queue ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE backup_queue FORCE ROW LEVEL SECURITY")
    op.execute(
        f"CREATE POLICY tenant_parent_scope ON backup_queue USING ({queue_predicate}) WITH CHECK ({queue_predicate})"
    )
    enforce_access_audit()

    for table in ("settings_v3", "secrets_v3", "system_settings"):
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
        op.execute(f"REVOKE ALL ON TABLE {table} FROM PUBLIC")
        predicate = "current_setting('app.platform_admin', true) = 'true'"
        op.execute(
            f"CREATE POLICY installation_administration ON {table} "
            f"USING ({predicate}) WITH CHECK ({predicate})"
        )

    for table in ("demo_sessions", "demo_rate_buckets"):
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
        op.execute(f"REVOKE ALL ON TABLE {table} FROM PUBLIC")
        predicate = "current_setting('app.demo', true) = 'true'"
        op.execute(
            f"CREATE POLICY demo_storage ON {table} "
            f"USING ({predicate}) WITH CHECK ({predicate})"
        )


def downgrade():
    raise RuntimeError(
        "Use the reviewed dump/restore rollback; tenant enforcement must not be silently removed"
    )
