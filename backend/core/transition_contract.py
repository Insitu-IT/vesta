"""Candidate transition object/ACL inspection, without repair or attribution."""

from pathlib import Path

from alembic.script import ScriptDirectory
from sqlalchemy import UniqueConstraint, inspect, text

from core.table_scope import SCOPES
from core.runtime_grants import table_privileges

SEQUENCES = {
    "access_audit_id_seq": "access_audit",
    "storage_configuration_activations_id_seq": "storage_configuration_activations",
}

PUBLICATION_FUNCTION = "vnbui_publish_storage_generation"
VERIFICATION_FUNCTION = "vnbui_verification_expected"
OWNER_REVIEW_FUNCTIONS = {
    "vnbui_review_legacy_capacity",
    "vnbui_review_modern_capacity",
    "vnbui_review_restore_cleanup",
}


def function_signature(row):
    """Only classified function signatures may reach grant/revoke statements."""
    if row["proname"] == PUBLICATION_FUNCTION:
        return "(text,text,text,text)"
    if row["proname"] == VERIFICATION_FUNCTION:
        return "(jsonb,text,text,text)"
    if row["proname"] in OWNER_REVIEW_FUNCTIONS:
        return "(jsonb)"
    return "()"


def _publication_function(row):
    return (
        row["proname"] == PUBLICATION_FUNCTION
        and row["pronargs"] == 4
        and not row["trigger"]
        and row["prosecdef"]
        and row.get("argument_types") == "25 25 25 25"
        and row.get("returns_jsonb")
    )


def _owner_review_function(row):
    return (
        row["proname"] in OWNER_REVIEW_FUNCTIONS
        and row["pronargs"] == 1
        and not row["trigger"]
        and not row["prosecdef"]
        and row.get("argument_types") == "3802"
        and row.get("returns_jsonb")
    )


def _verification_function(row):
    """Read-only invoker helper required by the scrub custody trigger."""
    return (
        row["proname"] == VERIFICATION_FUNCTION
        and row["pronargs"] == 4
        and not row["trigger"]
        and not row["prosecdef"]
        and row.get("argument_types") == "3802 25 25 25"
        and row.get("returns_jsonb")
    )


def trigger_functions():
    # Explicit callable classification, with the dynamic same-org trigger family
    # derived from its authoritative migration rather than table-name heuristics.
    script = ScriptDirectory(str(Path(__file__).resolve().parents[1] / "alembic"))
    references = script.get_revision("tenant_enforcement").module.REFERENCES
    return {
        "vnbui_operator_custody",
        "vnbui_operator_request_complete",
        "audit_access",
        "vnbui_configuration_clock",
        "vnbui_configuration_registry",
        "vnbui_capability_registry",
        "vnbui_capability_effect",
        "vnbui_callback_intent",
        "vnbui_provider_part",
        "vnbui_provider_result",
        "vnbui_part_observation",
        "vnbui_capacity_owner",
        "vnbui_capacity_effect",
        "vnbui_capacity_policy",
        "vnbui_capacity_audit",
        "vnbui_event_scope",
        "vnbui_s3_publication_immutable",
        "vnbui_org_immutable",
        "vnbui_vm_predecessor_scope",
        "vnbui_oidc_state_transition",
        "vnbui_lineage_fence",
        "vnbui_storage_dispatch_custody",
        "vnbui_backup_initiator",
        "vnbui_queue_started_backup",
        "vnbui_storage_attempt_key",
        "vnbui_storage_control",
        "vnbui_storage_compensation",
        "vnbui_compensation_retirement",
        "vnbui_storage_finalize",
        "vnbui_storage_completion_hold",
        "vnbui_native_inventory",
        "vnbui_native_execution",
        "vnbui_scheduler_epoch",
        "vnbui_dispatch_admission",
        "vnbui_scheduler_grant_insert",
        "vnbui_scheduler_revision",
        "vnbui_scheduler_binding",
        "vnbui_scheduler_immutable",
        "vnbui_scheduler_dormant",
        "vnbui_scheduler_construct",
        "vnbui_scheduler_queue",
        "vnbui_scheduler_queue_audit",
        "vnbui_scheduler_complete",
        "vnbui_scheduler_authority",
        "vnbui_guard_restore_cleanup_review",
        "vnbui_verification_guard",
    } | {"vnbui_scope_" + table for table in references}


def object_inventory(connection):
    expected_tables = set(SCOPES) | {"alembic_version"}
    # Resolve the authoritative migration catalogue once per inspection, not
    # once per database function. Do not cache across separate inspections.
    expected_triggers = trigger_functions()
    relations = (
        connection.execute(
            text(
                "SELECT c.oid,c.relname,c.relkind,c.relowner FROM pg_class c JOIN pg_namespace n "
                "ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind NOT IN ('i','I','t')"
            )
        )
        .mappings()
        .all()
    )
    functions = (
        connection.execute(
            text(
                "SELECT p.oid,p.proname,p.proowner,p.pronargs,p.prorettype='trigger'::regtype AS trigger, "
                "p.prosecdef,p.proargtypes::text AS argument_types,p.prorettype='jsonb'::regtype AS returns_jsonb "
                "FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public'"
            )
        )
        .mappings()
        .all()
    )
    sequences = {r["relname"] for r in relations if r["relkind"] == "S"}
    actual_functions = {p["proname"] for p in functions}
    unknown = sum(
        not (
            (r["relkind"] in {"r", "p"} and r["relname"] in expected_tables)
            or (r["relkind"] == "S" and r["relname"] in SEQUENCES)
        )
        for r in relations
    ) + sum(
        bool(
            not _publication_function(p)
            and not _owner_review_function(p)
            and not _verification_function(p)
            and (
                p["proname"] not in expected_triggers
                or p["pronargs"]
                or not p["trigger"]
                or p["prosecdef"]
            )
        )
        for p in functions
    )
    missing = len(
        expected_tables
        - {r["relname"] for r in relations if r["relkind"] in {"r", "p"}}
    )
    missing += len(expected_triggers - actual_functions) + len(
        set(SEQUENCES) - sequences
    )
    missing += PUBLICATION_FUNCTION not in actual_functions
    missing += VERIFICATION_FUNCTION not in actual_functions
    missing += len(OWNER_REVIEW_FUNCTIONS - actual_functions)
    # A same-named sequence without the reviewed owned-by dependency is unknown.
    for sequence, table in SEQUENCES.items():
        if sequence not in sequences:
            continue
        owned = connection.scalar(
            text(
                "SELECT count(*) FROM pg_depend d JOIN pg_class s ON s.oid=d.objid "
                "JOIN pg_class t ON t.oid=d.refobjid JOIN pg_attribute a "
                "ON a.attrelid=t.oid AND a.attnum=d.refobjsubid WHERE s.oid=to_regclass(:sequence) "
                "AND d.classid='pg_class'::regclass AND d.refclassid='pg_class'::regclass "
                "AND d.deptype IN ('a','i') AND t.oid=to_regclass(:table) AND a.attname='id'"
            ),
            dict(sequence="public." + sequence, table="public." + table),
        )
        unknown += owned != 1
    return relations, functions, int(unknown), missing


def default_acl_hazards(connection, migrator):
    """NULL ACL means PostgreSQL built-in defaults, not an empty ACL."""
    return connection.scalar(
        text(
            "WITH owner AS (SELECT oid FROM pg_roles WHERE rolname=:role), kinds(k) AS "
            "(VALUES ('r'::\"char\"),('S'::\"char\"),('f'::\"char\")), "
            "global_acl AS (SELECT o.oid, COALESCE(d.defaclacl,acldefault(k.k,o.oid)) acl "
            "FROM owner o CROSS JOIN kinds k LEFT JOIN pg_default_acl d ON d.defaclrole=o.oid "
            "AND d.defaclnamespace=0 AND d.defaclobjtype=k.k), "
            "schema_acl AS (SELECT o.oid,d.defaclacl acl FROM owner o JOIN pg_default_acl d ON d.defaclrole=o.oid "
            "WHERE d.defaclnamespace='public'::regnamespace AND d.defaclobjtype IN ('r','S','f')) "
            "SELECT count(*) FROM (SELECT * FROM global_acl UNION ALL SELECT * FROM schema_acl) defaults "
            "CROSS JOIN LATERAL aclexplode(defaults.acl) a WHERE a.grantee<>defaults.oid"
        ),
        {"role": migrator},
    )


def grant_mismatches(connection, role, relations, functions):
    differences = 0
    for row in relations:
        kind = row["relkind"]
        if kind not in {"r", "p", "S"}:
            continue
        sequence = kind == "S"
        privileges = (
            ("USAGE", "SELECT", "UPDATE")
            if sequence
            else (
                "SELECT",
                "INSERT",
                "UPDATE",
                "DELETE",
                "TRUNCATE",
                "REFERENCES",
                "TRIGGER",
            )
        )
        expected = {"USAGE", "SELECT"} if sequence else table_privileges(row["relname"])
        function = "has_sequence_privilege" if sequence else "has_table_privilege"
        for privilege in privileges:
            actual = connection.scalar(
                text(f"SELECT {function}(:role,:oid,:privilege)"),
                {"role": role, "oid": row["oid"], "privilege": privilege},
            )
            differences += actual != (privilege in expected)
            differences += bool(
                connection.scalar(
                    text(f"SELECT {function}(:role,:oid,:privilege)"),
                    {
                        "role": role,
                        "oid": row["oid"],
                        "privilege": privilege + " WITH GRANT OPTION",
                    },
                )
            )
            # Table revokes do not remove pre-existing column grants.
            if (
                not sequence
                and privilege in {"SELECT", "INSERT", "UPDATE", "REFERENCES"}
                and privilege not in expected
            ):
                differences += bool(
                    connection.scalar(
                        text("SELECT has_any_column_privilege(:role,:oid,:privilege)"),
                        {"role": role, "oid": row["oid"], "privilege": privilege},
                    )
                )
            if not sequence and privilege in {
                "SELECT",
                "INSERT",
                "UPDATE",
                "REFERENCES",
            }:
                differences += bool(
                    connection.scalar(
                        text("SELECT has_any_column_privilege(:role,:oid,:privilege)"),
                        {
                            "role": role,
                            "oid": row["oid"],
                            "privilege": privilege + " WITH GRANT OPTION",
                        },
                    )
                )
    for row in functions:
        differences += bool(
            connection.scalar(
                text("SELECT has_function_privilege(:role,:oid,'EXECUTE')"),
                {"role": role, "oid": row["oid"]},
            )
        ) != bool(_publication_function(row) or _verification_function(row))
        differences += bool(
            connection.scalar(
                text(
                    "SELECT has_function_privilege(:role,:oid,'EXECUTE WITH GRANT OPTION')"
                ),
                {"role": role, "oid": row["oid"]},
            )
        )
    return differences


def inspect_contract(connection, runtime, migrator=None):
    relations, functions, unknown, missing = object_inventory(connection)
    findings = [
        dict(code="UNKNOWN_OBJECT_CONTRACT", count=unknown),
        dict(code="MISSING_OBJECT_CONTRACT", count=missing),
    ]
    exists = connection.scalar(
        text("SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname=:role)"),
        {"role": runtime},
    )
    if exists and not unknown and not missing:
        findings.append(
            dict(
                code="RUNTIME_EFFECTIVE_GRANT_MISMATCHES",
                count=grant_mismatches(connection, runtime, relations, functions),
            )
        )
    else:
        findings.append(dict(code="RUNTIME_EFFECTIVE_GRANTS_UNKNOWN"))
    owner = connection.execute(
        text("SELECT oid FROM pg_roles WHERE rolname=:role"), {"role": migrator}
    ).scalar_one_or_none()
    if owner is None:
        findings.append(dict(code="MIGRATOR_IDENTITY_UNKNOWN"))
    else:
        mismatch = connection.scalar(
            text("SELECT current_user<>:role OR session_user<>:role"),
            {"role": migrator},
        )
        findings.append(dict(code="MIGRATOR_EXECUTOR_MISMATCH", count=int(mismatch)))
        findings.append(
            dict(
                code="NON_MIGRATOR_OBJECT_OWNERS",
                count=sum(r["relowner"] != owner for r in relations)
                + sum(p["proowner"] != owner for p in functions),
            )
        )
        findings.append(
            dict(
                code="MIGRATOR_DEFAULT_ACL_HAZARDS",
                count=default_acl_hazards(connection, migrator),
            )
        )
    return findings


def inspect_attribution(connection):
    """Read source-declared foreign keys and credential namespaces as aggregates.

    Nullable historical audit/event attribution is reported separately, never
    repaired. Predecessors lacking current columns remain UNKNOWN.
    """
    if not connection.scalar(
        text("SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname=current_user")
    ):
        return [dict(code="FULL_ATTRIBUTION_UNKNOWN_VISIBILITY")]
    from models import Base

    inspector = inspect(connection)
    tables = set(inspector.get_table_names(schema="public"))
    columns = {
        t: {c["name"] for c in inspector.get_columns(t, schema="public")}
        for t in tables
    }
    quote = connection.dialect.identifier_preparer.quote
    unknown = invalid = historical = unresolved = 0
    for table in Base.metadata.tables.values():
        if table.name not in tables:
            unknown += 1
            continue
        name = quote(table.name)
        if "org_id" in table.columns and "org_id" not in columns[table.name]:
            unknown += 1
        if "org_id" in table.columns and "org_id" in columns[table.name]:
            count = connection.scalar(
                text(f"SELECT count(*) FROM public.{name} WHERE org_id IS NULL")
            )
            if table.name in {"system_events"}:
                historical += count
            else:
                unresolved += count
        for constraint in table.foreign_key_constraints:
            if len(constraint.elements) != 1:
                unknown += 1
                continue
            element = constraint.elements[0]
            parent = element.column.table.name
            child_column, parent_column = element.parent.name, element.column.name
            if (
                parent not in tables
                or child_column not in columns[table.name]
                or parent_column not in columns[parent]
            ):
                unknown += 1
                continue
            child, target = quote(child_column), quote(parent_column)
            if not element.parent.nullable and child_column != "org_id":
                invalid += connection.scalar(
                    text(f"SELECT count(*) FROM public.{name} WHERE {child} IS NULL")
                )
            same_org = "org_id" in columns[table.name] and "org_id" in columns[parent]
            mismatch = " OR c.org_id IS DISTINCT FROM p.org_id" if same_org else ""
            invalid += connection.scalar(
                text(
                    f"SELECT count(*) FROM public.{name} c LEFT JOIN public.{quote(parent)} p "
                    f"ON c.{child}=p.{target} WHERE c.{child} IS NOT NULL AND (p.{target} IS NULL{mismatch})"
                )
            )
        # Parent-owned tables have no org_id of their own. Compare all present
        # tenant-bearing parents rather than blessing each FK independently.
        parents = []
        for constraint in table.foreign_key_constraints:
            if len(constraint.elements) != 1:
                continue
            element = constraint.elements[0]
            parent = element.column.table.name
            if element.parent.name in columns[table.name] and {
                element.column.name,
                "org_id",
            } <= columns.get(parent, set()):
                parents.append((element.parent.name, parent, element.column.name))
        if "org_id" not in table.columns:
            for index, (field, parent, key) in enumerate(parents):
                for other_field, other_parent, other_key in parents[index + 1 :]:
                    invalid += connection.scalar(
                        text(
                            f"SELECT count(*) FROM public.{name} c "
                            f"JOIN public.{quote(parent)} p ON c.{quote(field)}=p.{quote(key)} "
                            f"JOIN public.{quote(other_parent)} q ON c.{quote(other_field)}=q.{quote(other_key)} "
                            "WHERE p.org_id IS DISTINCT FROM q.org_id"
                        )
                    )
    collisions = 0
    schema_collisions = 0
    for table in Base.metadata.tables.values():
        unique_sets = {tuple(column.name for column in table.primary_key.columns)}
        unique_sets.update(
            tuple(column.name for column in c.columns)
            for c in table.constraints
            if isinstance(c, UniqueConstraint)
        )
        for keys in sorted(unique_sets):
            if not keys or not set(keys) <= columns.get(table.name, set()):
                unknown += 1
                continue
            names = ",".join(quote(k) for k in keys)
            nonnull = " AND ".join(f"{quote(k)} IS NOT NULL" for k in keys)
            schema_collisions += connection.scalar(
                text(
                    f"SELECT count(*) FROM (SELECT {names} FROM public.{quote(table.name)} WHERE {nonnull} "
                    f"GROUP BY {names} HAVING count(*)>1) conflicts"
                )
            )
    for table, keys in (
        ("users", ("org_id", "username")),
        ("users", ("org_id", "oidc_issuer", "oidc_subject")),
        ("agents", ("api_key_hash",)),
        ("agents", ("cert_fingerprint",)),
        ("agent_api_keys", ("key_hash",)),
        ("agent_registration_keys", ("key_hash",)),
        ("orchestrator_api_keys", ("key_hash",)),
        ("agent_certificates", ("fingerprint",)),
        ("agent_certificates", ("serial_number",)),
        ("demo_sessions", ("token_hash",)),
    ):
        if not set(keys) <= columns.get(table, set()):
            unknown += 1
            continue
        names = ",".join(quote(k) for k in keys)
        nonnull = " AND ".join(f"{quote(k)} IS NOT NULL" for k in keys)
        collisions += connection.scalar(
            text(
                f"SELECT count(*) FROM (SELECT {names} FROM public.{quote(table)} WHERE {nonnull} "
                f"GROUP BY {names} HAVING count(*)>1) duplicates"
            )
        )
    for first, first_key, second, second_key in (
        ("agents", "api_key_hash", "agent_api_keys", "key_hash"),
        ("agents", "cert_fingerprint", "agent_certificates", "fingerprint"),
    ):
        if not {"id", first_key} <= columns.get(first, set()) or not {
            "agent_id",
            second_key,
        } <= columns.get(second, set()):
            unknown += 1
            continue
        collisions += connection.scalar(
            text(
                f"SELECT count(*) FROM (SELECT value FROM (SELECT {quote(first_key)} value,id owner "
                f"FROM public.{quote(first)} UNION ALL SELECT {quote(second_key)},agent_id "
                f"FROM public.{quote(second)}) keys "
                "WHERE value IS NOT NULL GROUP BY value HAVING count(DISTINCT owner)>1) conflicts"
            )
        )
    if "access_audit" in tables and "org_id" in columns["access_audit"]:
        historical += connection.scalar(
            text("SELECT count(*) FROM public.access_audit WHERE org_id IS NULL")
        )
    else:
        unknown += 1
    return [
        dict(code="ATTRIBUTION_CHECKS_UNKNOWN", count=unknown),
        dict(code="ATTRIBUTION_CONFLICTS", count=invalid),
        dict(code="UNRESOLVED_TENANT_ATTRIBUTION", count=unresolved),
        dict(code="SCHEMA_UNIQUENESS_COLLISIONS", count=schema_collisions),
        dict(code="HISTORICAL_NULL_ATTRIBUTION_REVIEW", count=historical),
        dict(code="IDENTITY_CREDENTIAL_COLLISIONS", count=collisions),
    ]
