"""Converge historical installs to the OSS application schema without deleting data.

Revision ID: oss_schema_parity
Revises: add_demo_rate_buckets
"""

from alembic import context, op
import sqlalchemy as sa
import uuid

revision = "oss_schema_parity"
down_revision = "add_demo_rate_buckets"
branch_labels = None
depends_on = None

# Frozen structural declarations from the accepted application contract.
SERVER_DEFAULTS = (
    ("organizations", "created_at", "now()"),
    ("organizations", "updated_at", "now()"),
    ("secrets_v3", "source", "'ui'"),
    ("secrets_v3", "updated_at", "now()"),
    ("settings_v3", "value_type", "'string'"),
    ("settings_v3", "source", "'default'"),
    ("settings_v3", "updated_at", "now()"),
    ("system_events", "details", "'{}'"),
    ("system_events", "created_at", "now()"),
    ("agents", "capabilities", "'{}'"),
    ("agents", "metrics", "'{}'"),
    ("agents", "config", "'{}'"),
    ("agents", "mtls_enabled", "false"),
    ("users", "is_active", "true"),
    ("users", "auth_source", "'local'"),
    ("users", "role_source", "'local'"),
    ("vm_groups", "group_type", "'static'"),
    ("vm_groups", "rules_match", "'all'"),
    ("agent_certificates", "issued_at", "now()"),
    ("agent_certificates", "status", "'active'"),
    ("encryption_keys", "algorithm", "'aes-256-gcm'"),
    ("encryption_keys", "status", "'active'"),
    ("encryption_keys", "provider", "'local'"),
    ("encryption_keys", "created_at", "now()"),
    ("encryption_keys", "backed_up", "false"),
    ("encryption_keys", "backed_up_locations", "'[]'"),
    ("notification_rules", "enabled", "true"),
    ("notification_rules", "notification_type", "'email'"),
    ("reports", "enabled", "true"),
    ("reports", "format", "'pdf'"),
    ("saved_searches", "is_public", "false"),
    ("system_settings", "value_type", "'string'"),
    ("vms", "disks", "'[]'"),
    ("vms", "vm_metadata", "'{}'"),
    ("backups", "backup_type", "'full'"),
    ("backups", "exclude_disks", "'[]'"),
    ("backups", "checkpoints", "'[]'"),
    ("notification_logs", "status", "'sent'"),
    ("notification_logs", "read", "false"),
    ("report_executions", "status", "'pending'"),
    ("schedules", "retention_days", "30"),
    ("schedules", "tags", "'{}'"),
    ("schedules", "enabled", "true"),
    ("schedules", "backup_type", "'full'"),
    ("schedules", "exclude_disks", "'[]'"),
    ("backup_verifications", "status", "'pending'"),
    ("backup_verifications", "verification_type", "'checksum'"),
    ("restores", "restore_to_original", "true"),
    ("restores", "status", "'pending'"),
    ("restores", "progress", "0"),
    ("restores", "auto_define", "false"),
    ("restores", "adjust_config", "false"),
    ("restores", "selected_disks", "'[]'"),
)
REQUIRED_INDEXES = (
    (
        "demo_sessions",
        "ix_demo_sessions_absolute_expires_at",
        ("absolute_expires_at",),
        False,
        None,
    ),
    ("demo_sessions", "ix_demo_sessions_expires_at", ("expires_at",), False, None),
    ("demo_sessions", "ix_demo_sessions_token_hash", ("token_hash",), False, None),
    ("system_events", "ix_system_events_created_at", ("created_at",), False, None),
    ("system_events", "ix_system_events_event_type", ("event_type",), False, None),
    ("agents", "idx_agents_org_id", ("org_id",), False, None),
    ("users", "idx_users_org_id", ("org_id",), False, None),
    (
        "users",
        "ix_users_oidc_subject",
        ("oidc_subject", "oidc_issuer"),
        True,
        "oidc_subject IS NOT NULL",
    ),
    ("users", "ix_users_username", ("username",), True, None),
    ("vm_groups", "idx_vm_groups_org_id", ("org_id",), False, None),
    ("activity_logs", "ix_activity_logs_action", ("action",), False, None),
    ("activity_logs", "ix_activity_logs_created_at", ("created_at",), False, None),
    ("activity_logs", "ix_activity_logs_user_id", ("user_id",), False, None),
    (
        "agent_certificates",
        "ix_agent_certificates_serial_number",
        ("serial_number",),
        True,
        None,
    ),
    ("encryption_keys", "ix_encryption_keys_status", ("status",), False, None),
    ("notification_rules", "idx_notification_rules_org_id", ("org_id",), False, None),
    ("notification_rules", "ix_notification_rules_enabled", ("enabled",), False, None),
    (
        "notification_rules",
        "ix_notification_rules_event_type",
        ("event_type",),
        False,
        None,
    ),
    ("reports", "idx_reports_org_id", ("org_id",), False, None),
    ("reports", "ix_reports_enabled", ("enabled",), False, None),
    ("reports", "ix_reports_report_type", ("report_type",), False, None),
    ("saved_searches", "idx_saved_searches_org_id", ("org_id",), False, None),
    ("saved_searches", "ix_saved_searches_created_by", ("created_by",), False, None),
    ("saved_searches", "ix_saved_searches_search_type", ("search_type",), False, None),
    ("system_settings", "ix_system_settings_category", ("category",), False, None),
    ("vms", "idx_vms_org_id", ("org_id",), False, None),
    ("backups", "idx_backups_org_id", ("org_id",), False, None),
    ("backups", "ix_backups_chain_id", ("chain_id",), False, None),
    (
        "notification_logs",
        "ix_notification_logs_event_type",
        ("event_type",),
        False,
        None,
    ),
    ("notification_logs", "ix_notification_logs_sent_at", ("sent_at",), False, None),
    ("report_executions", "idx_report_executions_org_id", ("org_id",), False, None),
    (
        "report_executions",
        "ix_report_executions_created_at",
        ("created_at",),
        False,
        None,
    ),
    (
        "report_executions",
        "ix_report_executions_report_id",
        ("report_id",),
        False,
        None,
    ),
    ("schedules", "idx_schedules_org_id", ("org_id",), False, None),
    ("schedules", "ix_schedules_enabled", ("enabled",), False, None),
    ("schedules", "ix_schedules_next_run_at", ("next_run_at",), False, None),
    (
        "backup_queue",
        "ix_backup_queue_status_priority",
        ("status", "priority"),
        False,
        None,
    ),
    (
        "backup_verifications",
        "idx_backup_verifications_org_id",
        ("org_id",),
        False,
        None,
    ),
    (
        "backup_verifications",
        "ix_backup_verifications_backup_id",
        ("backup_id",),
        False,
        None,
    ),
    (
        "backup_verifications",
        "ix_backup_verifications_status",
        ("status",),
        False,
        None,
    ),
    ("restores", "idx_restores_org_id", ("org_id",), False, None),
    ("restores", "ix_restores_backup_id", ("backup_id",), False, None),
    ("restores", "ix_restores_created_at", ("created_at",), False, None),
    ("restores", "ix_restores_status", ("status",), False, None),
)


def upgrade():
    # Frozen declarations: never import current application metadata into a
    # historical migration. Existing out-of-chain tables are validated by the
    # parity gate, rather than replaced or recreated.
    bind = op.get_bind()
    tables = set(sa.inspect(bind).get_table_names())
    for name in ("agent_api_keys", "agent_registration_keys", "orchestrator_api_keys"):
        if name in tables:
            continue
        columns = [
            sa.Column("id", sa.String(), primary_key=True),
            sa.Column("name", sa.String(255), nullable=name == "agent_api_keys"),
            sa.Column("key_hash", sa.String(64), nullable=False),
            sa.Column("key_prefix", sa.String(16), nullable=False),
            sa.Column("expires_at", sa.DateTime()),
            sa.Column("enabled", sa.Boolean()),
            sa.Column("last_used_at", sa.DateTime()),
            sa.Column("created_at", sa.DateTime()),
            sa.Column("updated_at", sa.DateTime()),
        ]
        if name == "agent_api_keys":
            columns.append(
                sa.Column(
                    "agent_id",
                    sa.String(),
                    sa.ForeignKey("agents.id"),
                    nullable=False,
                    unique=True,
                )
            )
        else:
            columns.append(
                sa.Column(
                    "created_by", sa.String(), sa.ForeignKey("users.id"), nullable=False
                )
            )
        if name in ("orchestrator_api_keys", "agent_registration_keys"):
            columns.append(sa.UniqueConstraint("key_hash"))
        if name == "agent_registration_keys":
            columns.extend(
                (
                    sa.Column("max_uses", sa.Integer()),
                    sa.Column("use_count", sa.Integer()),
                )
            )
        op.create_table(name, *columns)

    for table, column, kind in (
        ("agents", "display_name", sa.String(255)),
        ("backups", "storage_path", sa.String(512)),
        ("users", "email", sa.String(255)),
        ("users", "full_name", sa.String(255)),
        ("users", "last_login", sa.DateTime()),
    ):
        existing = {c["name"]: c for c in sa.inspect(bind).get_columns(table)}
        if column not in existing:
            op.add_column(table, sa.Column(column, kind, nullable=True))

    size_type = next(
        c["type"]
        for c in sa.inspect(bind).get_columns("backups")
        if c["name"] == "size_bytes"
    )
    if not isinstance(size_type, sa.BigInteger):
        if not isinstance(size_type, sa.Integer):
            raise RuntimeError(
                "Unexpected backups.size_bytes type; inspect schema before migration"
            )
        op.alter_column(
            "backups", "size_bytes", existing_type=size_type, type_=sa.BigInteger()
        )

    from sqlalchemy.dialects.postgresql import JSON, JSONB

    tags_type = next(
        c["type"]
        for c in sa.inspect(bind).get_columns("vm_groups")
        if c["name"] == "tags"
    )
    if not isinstance(tags_type, JSONB):
        if not isinstance(tags_type, JSON):
            raise RuntimeError(
                "Unexpected vm_groups.tags type; inspect schema before migration"
            )
        op.alter_column(
            "vm_groups",
            "tags",
            existing_type=tags_type,
            type_=JSONB(),
            postgresql_using="tags::jsonb",
        )

    if "organization_defaults" not in tables:
        op.create_table(
            "organization_defaults",
            sa.Column("slot", sa.String(16), primary_key=True),
            sa.Column(
                "org_id", sa.String(), sa.ForeignKey("organizations.id"), nullable=False
            ),
            sa.CheckConstraint("slot = 'oss'", name="ck_organization_defaults_slot"),
        )
    existing_default = bind.execute(
        sa.text("SELECT org_id FROM organization_defaults WHERE slot='oss'")
    ).scalar_one_or_none()
    requested = context.get_x_argument(as_dictionary=True).get(
        "default_organization_id"
    )
    if existing_default:
        if requested and requested != existing_default:
            raise RuntimeError(
                "Existing OSS organization assignment differs; migration will not rewrite it"
            )
        organization = existing_default
    elif requested:
        organization = bind.execute(
            sa.text("SELECT id FROM organizations WHERE id=:id"), {"id": requested}
        ).scalar_one_or_none()
        if organization is None:
            raise RuntimeError(
                "default_organization_id must name an existing organization"
            )
    else:
        organizations = (
            bind.execute(sa.text("SELECT id FROM organizations ORDER BY id LIMIT 2"))
            .scalars()
            .all()
        )
        if not organizations:
            organization = str(uuid.uuid4())
            bind.execute(
                sa.text(
                    "INSERT INTO organizations (id,name,enabled) VALUES (:id,'Default Organization',true)"
                ),
                {"id": organization},
            )
        elif len(organizations) != 1:
            raise RuntimeError(
                "OSS default organization is ambiguous or absent. Preserve attribution: "
                "inspect organizations, then run alembic -x default_organization_id=<existing-id> upgrade head"
            )
        else:
            organization = organizations[0]
    if not existing_default:
        bind.execute(
            sa.text(
                "INSERT INTO organization_defaults (slot, org_id) VALUES ('oss', :id)"
            ),
            {"id": organization},
        )
    converge_deployed_shape(bind, organization)


def converge_deployed_shape(bind, organization):
    # The measured deployed revision predates the org mappings despite being
    # stamped at the same Alembic head. Add attribution only where absent; never
    # rewrite an existing organization or alter RLS/audit behavior.
    scoped = (
        "users",
        "agents",
        "vms",
        "vm_groups",
        "backups",
        "schedules",
        "restores",
        "notification_rules",
        "backup_verifications",
        "saved_searches",
        "reports",
        "report_executions",
    )
    for table in scoped:
        columns = {c["name"] for c in sa.inspect(bind).get_columns(table)}
        if "org_id" not in columns:
            op.add_column(table, sa.Column("org_id", sa.String(), nullable=True))
            bind.execute(
                sa.text(f"UPDATE {table} SET org_id=:org"), {"org": organization}
            )
            op.alter_column(table, "org_id", nullable=False)
            op.create_foreign_key(
                f"fk_{table}_org_id", table, "organizations", ["org_id"], ["id"]
            )

    for table, column in (
        ("agents", "capabilities"),
        ("agents", "metrics"),
        ("backups", "tags"),
    ):
        # NULL JSON collections carry no payload; normalize to the same empty
        # object used by the existing ORM. Non-null content is untouched.
        bind.execute(
            sa.text(f"UPDATE {table} SET {column}='{{}}'::jsonb WHERE {column} IS NULL")
        )
        op.alter_column(table, column, nullable=False)
    if bind.execute(
        sa.text("SELECT EXISTS (SELECT 1 FROM backups WHERE retention_days IS NULL)")
    ).scalar_one():
        raise RuntimeError(
            "Existing backups have NULL retention_days; determine retention explicitly before migration, then rerun alembic upgrade head"
        )
    op.alter_column("backups", "retention_days", nullable=False)

    for table, column, default in SERVER_DEFAULTS:
        actual = next(
            c for c in sa.inspect(bind).get_columns(table) if c["name"] == column
        )
        if actual["default"] is None:
            op.alter_column(table, column, server_default=sa.text(default))
    for table, name, columns, unique, predicate in REQUIRED_INDEXES:
        if name not in {i["name"] for i in sa.inspect(bind).get_indexes(table)}:
            options = {"postgresql_where": sa.text(predicate)} if predicate else {}
            op.create_index(name, table, list(columns), unique=unique, **options)
    for table, name, columns in (
        ("users", "users_username_key", ("username",)),
        ("system_settings", "uq_settings_category_key", ("category", "key")),
    ):
        existing = sa.inspect(bind).get_unique_constraints(table)
        if not any(tuple(c["column_names"]) == columns for c in existing):
            op.create_unique_constraint(name, table, list(columns))


def downgrade():
    raise RuntimeError(
        "Data-preserving forward migration only; restore the rehearsed pre-migration dump for rollback"
    )
