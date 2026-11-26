"""Current-object runtime grants, shared by disposable acceptance and operators.

Run under the schema owner after the reviewed migrations. This function neither
creates roles nor changes role attributes. Deployment orchestration stays with
the operator. This handles existing objects only; defaults are a separate step.
"""

from sqlalchemy import inspect, text

from core.table_scope import assert_classified


def table_privileges(table):
    """Shared current-object contract for grant application and inspection."""
    if table in {
        "access_audit",
        "system_events",
        "scheduler_principals",
        "schedule_occurrences",
        "schedule_occurrence_members",
    }:
        return {"SELECT", "INSERT"}
    if table == "storage_configuration_clock":
        return {"SELECT", "UPDATE"}
    if table in {
        "storage_configuration_generations",
        "storage_configuration_activations",
        "alembic_version",
        "organization_defaults",
        "storage_capability_evidence",
        "storage_capability_qualifications",
        "storage_capability_revocations",
        "storage_lineage_generations",
        "storage_lineage_heads",
    }:
        return {"SELECT"}
    if table in {
        "operator_requests",
        "operator_dispatches",
        "agent_key_rotations",
        "s3_publications",
        "s3_upload_parts",
        "s3_upload_results",
        "s3_part_observation_scans",
        "s3_part_observation_pages",
        "scheduler_grants",
    }:
        return {"SELECT", "INSERT", "UPDATE"}
    return {"SELECT", "INSERT", "UPDATE", "DELETE"}


def apply_default_runtime_grants(connection, role):
    """New objects stay private until classified and explicitly granted.

    Execute as the actual migration identity in the application database.
    Global defaults and schema additions are additive in PostgreSQL; clear both.
    """
    quote = connection.dialect.identifier_preparer.quote
    owner = quote(connection.execute(text("SELECT current_user")).scalar_one())
    target = quote(role)
    for scope in ("", " IN SCHEMA public"):
        for objects in ("TABLES", "SEQUENCES", "FUNCTIONS"):
            for grantee in (target, "PUBLIC"):
                connection.execute(
                    text(
                        f"ALTER DEFAULT PRIVILEGES FOR ROLE {owner}{scope} "
                        f"REVOKE ALL ON {objects} FROM {grantee}"
                    )
                )


def apply_current_runtime_grants(connection, role):
    tables = set(inspect(connection).get_table_names(schema="public"))
    assert_classified(tables - {"alembic_version"})
    quote = connection.dialect.identifier_preparer.quote
    target = quote(role)
    database = quote(connection.execute(text("SELECT current_database()")).scalar_one())
    connection.execute(text("REVOKE CREATE ON SCHEMA public FROM PUBLIC"))
    connection.execute(text(f"REVOKE CREATE ON SCHEMA public FROM {target}"))
    connection.execute(text(f"GRANT CONNECT ON DATABASE {database} TO {target}"))
    connection.execute(text(f"GRANT USAGE ON SCHEMA public TO {target}"))
    for table in sorted(tables):
        qualified = "public." + quote(table)
        connection.execute(text(f"REVOKE ALL ON TABLE {qualified} FROM {target}"))
        if table in {
            "operator_requests",
            "operator_dispatches",
            "agent_key_rotations",
            "scheduler_principals",
            "scheduler_grants",
            "schedule_occurrences",
            "schedule_occurrence_members",
            "access_audit",
            "system_events",
            "settings_v3",
            "secrets_v3",
            "system_settings",
            "organization_defaults",
            "demo_sessions",
            "demo_rate_buckets",
            "s3_publications",
            "s3_upload_parts",
            "s3_upload_results",
            "s3_part_observation_scans",
            "s3_part_observation_pages",
            "storage_configuration_generations",
            "storage_configuration_activations",
            "storage_configuration_clock",
            "storage_capability_evidence",
            "storage_capability_qualifications",
            "storage_capability_revocations",
            "storage_lineage_generations",
            "storage_lineage_heads",
            "oidc_login_states",
        }:
            connection.execute(text(f"REVOKE ALL ON TABLE {qualified} FROM PUBLIC"))
        privileges = ", ".join(sorted(table_privileges(table)))
        connection.execute(text(f"GRANT {privileges} ON TABLE {qualified} TO {target}"))
    connection.execute(
        text(f"GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO {target}")
    )
    # Lineage tables remain read-only. This narrow routine atomically publishes
    # only an exact, checkpointed generation with a prior durable S3 receipt.
    connection.execute(
        text(
            "GRANT EXECUTE ON FUNCTION "
            "public.vnbui_publish_storage_generation(text,text,text,text) "
            f"TO {target}"
        )
    )
    # The invoker-security custody trigger calls this read-only helper under
    # the original runtime role. It grants neither publication nor owner access.
    connection.execute(
        text(
            "GRANT EXECUTE ON FUNCTION "
            "public.vnbui_verification_expected(jsonb,text,text,text) "
            f"TO {target}"
        )
    )
    for table in ("storage_lineage_generations", "storage_lineage_heads"):
        for privilege in (
            "SELECT",
            "INSERT",
            "UPDATE",
            "DELETE",
            "TRUNCATE",
            "REFERENCES",
            "TRIGGER",
        ):
            actual = connection.execute(
                text("SELECT has_table_privilege(:role,:table,:privilege)"),
                {"role": role, "table": "public." + table, "privilege": privilege},
            ).scalar_one()
            if actual != (privilege == "SELECT"):
                raise RuntimeError(
                    "Runtime lineage authority must be read-only; inspect ownership and inherited grants"
                )
    for privilege, expected in (
        ("SELECT", True),
        ("INSERT", True),
        ("UPDATE", False),
        ("DELETE", False),
        ("TRUNCATE", False),
        ("REFERENCES", False),
        ("TRIGGER", False),
    ):
        actual = connection.execute(
            text("SELECT has_table_privilege(:role,'public.access_audit',:privilege)"),
            {"role": role, "privilege": privilege},
        ).scalar_one()
        if actual != expected:
            raise RuntimeError(
                f"Runtime audit privilege {privilege} differs from append/read contract; "
                "inspect inherited roles and ownership before applying grants"
            )
