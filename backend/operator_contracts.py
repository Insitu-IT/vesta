"""Audited HTTP descriptions without changing request decoding or response bytes.

Schemas here describe existing wire values. Extensible domain metadata remains
explicit, and the exported inventory does not count opaque objects as typed.
"""

from copy import deepcopy

from fastapi.routing import APIRoute
from operator_schema_inventory import response_inventory


def obj(properties, required=None, *, extra=False):
    return {
        "type": "object",
        "properties": properties,
        "required": list(properties) if required is None else required,
        "additionalProperties": extra,
    }


def nullable(schema):
    return {"anyOf": [schema, {"type": "null"}]}


def safety_diagnostic_schema():
    from core.storage_hold_observation import SAFETY_WORDS, SAFETY_TIMES, SAFETY_COUNTS

    fields = {
        name: {"type": "string", "pattern": "^[a-z][a-z_]{0,79}$"}
        for name in sorted(SAFETY_WORDS)
    }
    fields.update(
        {
            name: {"type": "string", "format": "date-time", "pattern": "Z$"}
            for name in sorted(SAFETY_TIMES)
        }
    )
    fields.update(
        {
            name: {"type": "integer", "minimum": 0, "maximum": 2**63 - 1}
            for name in sorted(SAFETY_COUNTS)
        }
    )
    for name in ("http_status", "native_stop_http_status"):
        fields[name].update(minimum=100, maximum=599)
    fields["disposition"] = {
        "type": "string",
        "enum": ["refused", "transient", "uncertain"],
    }
    schema = obj(fields, required=["stage", "reason", "disposition"])
    schema["description"] = (
        "Bounded retained safety observation. Missing optional counts/timestamps "
        "mean unobserved; zero counts are explicit observations. No credentials, "
        "URLs or provider bodies. This does not grant replay, deletion, capacity "
        "release or successful completion authority."
    )
    return schema


STRING = {"type": "string"}
INTEGER = {"type": "integer"}
BOOLEAN = {"type": "boolean"}
TIME = nullable({"type": "string", "format": "date-time"})
LEGACY_TIME = nullable(
    {
        "type": "string",
        "description": (
            "ISO 8601 timestamp; historical UTC values may omit the timezone offset."
        ),
        "pattern": r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?$",
    }
)
STRINGS = {"type": "array", "items": STRING}
METADATA = {
    "type": "object",
    "additionalProperties": True,
    "description": "Extensible domain metadata; keys are not a closed schema.",
    "x-open-schema-reason": (
        "Persisted/provider-supplied domain metadata permits additional JSON values."
    ),
}


def settings_patch_schema(definitions, secrets):
    properties = {}
    for key, definition in definitions.items():
        properties[key] = {
            "type": "boolean" if definition["type"] == "bool" else "string"
        }
    properties["backup.capacity_admission"] = obj(
        {
            "schema": {"type": "integer", "const": 1},
            "revision": {"type": "integer", "minimum": 1, "maximum": 2**63 - 1},
            "limit": {"type": "integer", "minimum": 1, "maximum": 100000},
            "maintenance": BOOLEAN,
        }
    )
    properties["backup.capacity_admission"]["description"] = (
        "Changing a prior policy requires a strictly increased revision. "
        "Maintenance blocks new reservations and existing effect continuations. "
        "Use backup.admission_pause to stop new reservations while admitted work drains."
    )
    properties["backup.admission_pause"] = obj(
        {
            "schema": {"type": "integer", "const": 1},
            "revision": {"type": "integer", "minimum": 1, "maximum": 2**63 - 1},
            "paused": BOOLEAN,
        }
    )
    properties["backup.admission_pause"]["description"] = (
        "Installation-owned pause for new backup capacity reservations, including "
        "scheduled backups. Already reserved work may continue under its original "
        "authority and safety checks. Null on GET means no separate pause; capacity "
        "policy remains required. A changed value requires a strictly increased "
        "revision. A pause never releases custody or bypasses maintenance."
    )
    properties["oidc.default_role"]["enum"] = ["viewer", "operator"]
    for key in secrets:
        properties[key] = {
            "type": "string",
            "writeOnly": True,
            "description": (
                "Omitted, empty, whitespace-only or entirely */• masked strings retain "
                "the current secret. Null is invalid. No clear-secret operation."
            ),
        }
    schema = obj(properties, required=[])
    schema["description"] = (
        "Flat settings patch; unknown keys and null are invalid. Omitted values"
        " retain prior state. String values are trimmed; booleans require JSON "
        "booleans. Effective OIDC configuration is validated together. "
        "Authorization precedes sensitive JSON decoding; malformed input "
        "returns 400 after authorization."
    )
    return schema


def credential_item(registration=False):
    properties = {
        "id": STRING,
        "name": STRING,
        "key_prefix": STRING,
        "expires_at": TIME,
        "enabled": BOOLEAN,
        "is_expired": BOOLEAN,
        "is_valid": BOOLEAN,
        "last_used_at": TIME,
        "created_at": TIME,
        "created_by": nullable(STRING),
    }
    if registration:
        properties.update(
            {
                "agent_hostname": nullable(STRING),
                "max_uses": nullable(INTEGER),
                "use_count": INTEGER,
                "is_max_uses_reached": BOOLEAN,
            }
        )
    return obj(properties)


def page(item, name="items", *, offset="skip", has_more=True, paged=True):
    properties = {name: {"type": "array", "items": item}, "total": INTEGER}
    if paged:
        properties.update({offset: INTEGER, "limit": INTEGER})
        if has_more:
            properties["has_more"] = BOOLEAN
    return obj(properties)


def response_schema(operation, schema):
    response = operation.setdefault("responses", {}).setdefault(
        "200", {"description": "Successful Response"}
    )
    response["content"] = {"application/json": {"schema": deepcopy(schema)}}


def dependency_names(dependant):
    names = set()
    pending = [dependant]
    while pending:
        current = pending.pop()
        call = getattr(current, "call", None)
        if call:
            names.add(getattr(call, "__name__", type(call).__name__))
        pending.extend(getattr(current, "dependencies", ()))
    return names


def describe_auth(operation, route, require_mtls=False, *, source_path=None):
    names = dependency_names(route.dependant)
    path = source_path or route.path
    if "candidate_credential" in names:
        operation["security"] = [
            {"AgentCandidate": [], **({"AgentMTLS": []} if require_mtls else {})}
        ]
        operation["x-credential-domain"] = "agent-candidate-activation-only"
        operation["x-transport-policy"] = (
            "Candidate proof is bound to this agent and rotation; it grants no "
            "ordinary agent authority. When mTLS is required, a current certificate"
            " for the same agent is required in addition to the candidate."
        )
    elif names & {"verify_agent_api_key", "authenticate_callback"}:
        operation["security"] = (
            [{"AgentMTLS": []}]
            if require_mtls
            else [{"AgentKey": []}, {"AgentMTLS": []}]
        )
        operation["x-credential-domain"] = "agent"
        operation["x-transport-policy"] = (
            "Only a certificate verified by TLS transport is proof. Forwarded "
            "fingerprint headers are not credentials. A verified certificate "
            "selects certificate authentication; API-key fallback is unavailable "
            "when it is present."
        )
    elif "registration_database" in names:
        operation["security"] = [{"RegistrationKey": []}]
        operation["x-credential-domain"] = "agent-registration"
    elif path.startswith("/api/v1/demo/"):
        if path.endswith("/sessions") and "POST" in route.methods:
            operation["security"] = []
            operation["x-credential-domain"] = "public-demo-bootstrap"
        else:
            operation["security"] = [{"DemoSession": []}]
            operation["x-credential-domain"] = "synthetic-demo-session"
    elif path == "/api/v1/auth/oidc/callback":
        operation["security"] = [{"OIDCState": [], "OIDCPKCE": []}]
        operation["x-credential-domain"] = "browser-oidc-callback"
        operation["x-transport-policy"] = (
            "State query and browser state cookie must match; PKCE cookie and "
            "provider response are verified. This is not user Bearer "
            "authentication."
        )
    elif "get_current_user" in names:
        # Keep FastAPI's existing OAuth2 scheme, including dependency overrides.
        operation["x-credential-domain"] = "user-session"
    else:
        operation["x-credential-domain"] = "public-or-route-specific"
    for authority in (
        "get_installation_admin",
        "get_platform_admin",
        "get_admin_user",
        "get_operator_or_admin",
    ):
        if authority in names:
            operation["x-authorization-dependency"] = authority
            break


def effective_http_routes(routes):
    """Yield flat routes and pinned FastAPI's lazy included route contexts.

    Effective contexts retain include-time dependencies and path prefixes. The
    original route only identifies HTTP routes and their protocol-local path;
    its dependant alone would omit authority added by an enclosing router.
    """
    for node in routes:
        contexts = (
            node.effective_route_contexts()
            if callable(getattr(node, "effective_route_contexts", None))
            else [node]
        )
        for context in contexts:
            original = getattr(context, "original_route", context)
            if isinstance(original, APIRoute) and context.include_in_schema:
                yield context, original.path


def apply_contracts(document, routes, definitions, secrets, *, require_mtls=False):
    """Enrich a generated document, retaining the actual routes as denominator."""
    from operator_restore_contracts import restore_shapes, scheduler_decision

    restore_types = restore_shapes()
    document.setdefault("components", {}).setdefault("schemas", {}).update(
        deepcopy(restore_types)
    )
    document["components"]["schemas"][
        "StorageSafetyDiagnostic"
    ] = safety_diagnostic_schema()
    restore_input = document["components"]["schemas"].get("RestoreCreateRequest")
    if restore_input is not None:
        for field, name in (
            ("kubevirt_target", "KubeVirtRestoreTarget"),
            ("native_target", "NativeRestoreInput"),
        ):
            restore_input["properties"][field] = nullable(
                {"$ref": "#/components/schemas/" + name}
            )
    schemes = document.setdefault("components", {}).setdefault("securitySchemes", {})
    schemes.update(
        {
            "AgentCandidate": {
                "type": "apiKey",
                "in": "header",
                "name": "X-Agent-Key",
                "description": (
                    "Pending candidate proof authorizes only its exact activation route."
                ),
            },
            "AgentKey": {"type": "apiKey", "in": "header", "name": "X-Agent-Key"},
            "AgentMTLS": {
                "type": "mutualTLS",
                "description": (
                    "Transport-verified client certificate; never a caller-supplied"
                    " fingerprint header."
                ),
            },
            "RegistrationKey": {"type": "apiKey", "in": "header", "name": "X-API-Key"},
            "DemoSession": {
                "type": "apiKey",
                "in": "cookie",
                "name": "vnbui_demo_session",
            },
            "OIDCState": {"type": "apiKey", "in": "cookie", "name": "oidc_state"},
            "OIDCPKCE": {"type": "apiKey", "in": "cookie", "name": "oidc_pkce"},
        }
    )
    paths = document.get("paths", {})
    for route, source_path in effective_http_routes(routes):
        for method in route.methods:
            operation = paths.get(route.path_format, {}).get(method.lower())
            if operation is not None:
                describe_auth(operation, route, require_mtls, source_path=source_path)
    patch = settings_patch_schema(definitions, secrets)
    settings = paths.get("/api/v1/settings/v3", {})
    if "put" in settings:
        operation = settings["put"]
        operation["requestBody"] = {
            "required": True,
            "content": {"application/json": {"schema": patch}},
        }
        response_schema(
            operation,
            obj(
                {
                    "status": {"const": "ok", "type": "string"},
                    "updated_settings": STRINGS,
                    "updated_secrets": STRINGS,
                }
            ),
        )
        for status, description in (
            (
                "400",
                (
                    "Invalid configuration after authorization; secret values are never"
                    " echoed."
                ),
            ),
            ("401", "Invalid or disabled authenticated identity."),
            ("403", "Installation authority required."),
            ("500", "Settings transaction failed and rolled back."),
        ):
            operation["responses"][status] = {
                "description": description,
                "content": {"application/json": {"schema": obj({"detail": STRING})}},
            }
    if "get" in settings:
        readable = deepcopy(patch["properties"])
        for key in secrets:
            readable.pop(key, None)
        for key, value in readable.items():
            if value.get("type") == "string":
                readable[key] = nullable(value)
        readable["backup.capacity_admission"] = nullable(
            readable["backup.capacity_admission"]
        )
        readable["backup.admission_pause"] = nullable(
            readable["backup.admission_pause"]
        )
        secret_status = obj(
            {"configured": BOOLEAN, "source": {"enum": ["ui", "env", None]}}
        )
        response_schema(
            settings["get"],
            obj(
                {
                    "settings": obj(readable),
                    "secrets": obj({key: secret_status for key in secrets}),
                    "encryption_configured": BOOLEAN,
                }
            ),
        )
    activity_item = obj(
        {
            "id": STRING,
            "source": {"type": "string", "enum": ["user", "system"]},
            "source_name": STRING,
            "event_type": STRING,
            "resource_type": nullable(STRING),
            "resource_id": nullable(STRING),
            "details": METADATA,
            "created_at": TIME,
            "attribution": STRING,
            "org_id": nullable(STRING),
        },
        required=[
            "id",
            "source",
            "source_name",
            "event_type",
            "resource_type",
            "resource_id",
            "details",
            "created_at",
        ],
    )
    operator_dispatch = nullable(
        obj(
            {
                "state": {
                    "type": "string",
                    "enum": ["pending", "dispatching", "delivered", "held"],
                },
                "reason": nullable(STRING),
                "request_id": {"type": "string", "format": "uuid"},
            }
        )
    )
    backup_item = obj(
        {
            "id": STRING,
            "vm_id": STRING,
            "vm_name": STRING,
            "status": STRING,
            "unverified_legacy_s3": BOOLEAN,
            "progress": nullable(INTEGER),
            "safety_diagnostic": nullable(
                {"$ref": "#/components/schemas/StorageSafetyDiagnostic"}
            ),
            "storage_progress": nullable(
                obj(
                    {
                        "schema": {"type": "integer", "const": 1},
                        "reservation_id": STRING,
                        "plan_sha256": STRING,
                        "phase": {
                            "type": "string",
                            "enum": ["pending", "preparing", "uploading", "finalizing"],
                        },
                        "bytes_transferred": {
                            "type": "integer",
                            "minimum": 0,
                            "maximum": 2**63 - 1,
                        },
                        "total_bytes": {
                            "type": "integer",
                            "minimum": 0,
                            "maximum": 2**63 - 1,
                        },
                        "updated_at": {"type": "string", "format": "date-time"},
                    }
                )
            ),
            "size_bytes": nullable(INTEGER),
            "retention_days": nullable(INTEGER),
            "backup_type": STRING,
            "capacity_state": nullable(STRING),
            "storage_path": nullable(STRING),
            "tags": METADATA,
            "created_at": TIME,
            "completed_at": TIME,
            "operator_dispatch": operator_dispatch,
        }
    )
    user_properties = {
        key: nullable(STRING)
        for key in (
            "email",
            "full_name",
            "auth_source",
            "role_source",
            "oidc_subject",
            "oidc_issuer",
        )
    }
    user_properties.update(
        {
            "id": STRING,
            "username": STRING,
            "org_id": STRING,
            "role": STRING,
            "is_active": BOOLEAN,
            "last_login": TIME,
            "created_at": TIME,
        }
    )
    agent_item = obj(
        {
            "id": STRING,
            "hostname": STRING,
            "display_name": nullable(STRING),
            "status": STRING,
            "ip_address": nullable(STRING),
            "port": nullable(INTEGER),
            "version": nullable(STRING),
            "last_heartbeat": TIME,
            "vm_count": INTEGER,
            "metrics": METADATA,
        }
    )
    restore_item = obj(
        {
            "id": STRING,
            "backup_id": nullable(STRING),
            "recovery_source": {"$ref": "#/components/schemas/RecoveryPointResponse"},
            "status": STRING,
            "progress": nullable(INTEGER),
            "restore_to_original": BOOLEAN,
            "target_vm_name": nullable(STRING),
            "target_vm_id": nullable(STRING),
            "created_by": nullable(STRING),
            "created_at": TIME,
            "started_at": TIME,
            "completed_at": TIME,
            "operator_dispatch": operator_dispatch,
            "error_message": nullable(STRING),
            "kubevirt_target": nullable(
                {"$ref": "#/components/schemas/KubeVirtRestoreTarget"}
            ),
            "native_target": nullable(
                {"$ref": "#/components/schemas/NativeRestoreTarget"}
            ),
            "result": nullable(
                {
                    "oneOf": [
                        {"$ref": "#/components/schemas/KubeVirtRestoreResult"},
                        {"$ref": "#/components/schemas/NativeRestoreResult"},
                    ]
                }
            ),
            "backup": obj(
                {
                    "id": STRING,
                    "vm_name": STRING,
                    "created_at": TIME,
                    "size_bytes": nullable(INTEGER),
                }
            ),
            "created_by_user": obj({"username": STRING, "role": STRING}),
        },
        required=[
            "id",
            "backup_id",
            "status",
            "progress",
            "restore_to_original",
            "target_vm_name",
            "target_vm_id",
            "created_by",
            "created_at",
            "started_at",
            "completed_at",
            "error_message",
            "kubevirt_target",
            "native_target",
            "result",
            "operator_dispatch",
        ],
    )
    report_item = obj(
        {
            "id": STRING,
            "name": STRING,
            "report_type": STRING,
            "schedule": nullable(STRING),
            "format": STRING,
            "recipients": nullable(STRINGS),
            "filters": nullable(METADATA),
            "enabled": BOOLEAN,
            "last_run_at": TIME,
            "next_run_at": TIME,
            "created_at": TIME,
            "created_by_user": nullable(obj({"id": STRING, "username": STRING})),
        }
    )
    execution_item = obj(
        {
            "id": STRING,
            "status": STRING,
            "file_path": nullable(STRING),
            "file_size_bytes": nullable(INTEGER),
            "file_size_mb": {"type": "number"},
            "error_message": nullable(STRING),
            "started_at": TIME,
            "completed_at": TIME,
            "created_at": TIME,
        }
    )
    execution_page = page(execution_item, "executions", offset="offset", has_more=False)
    execution_page["properties"].update({"report_id": STRING, "report_name": STRING})
    execution_page["required"].extend(["report_id", "report_name"])
    key_item = obj(
        {
            "id": STRING,
            "name": STRING,
            "algorithm": STRING,
            "key_hash": STRING,
            "status": STRING,
            "provider": STRING,
            "created_at": TIME,
            "created_by": nullable(STRING),
            "rotated_at": TIME,
            "replaced_by_id": nullable(STRING),
            "backed_up": BOOLEAN,
            "backed_up_at": TIME,
            "backed_up_locations": STRINGS,
            "backup_count": INTEGER,
        }
    )
    vm_properties = {
        key: nullable(STRING)
        for key in (
            "uuid",
            "state",
            "provider",
            "namespace",
            "vm_uid",
            "vmi_uid",
            "replaces_vm_id",
            "last_backup_type",
            "last_backup_status",
        )
    }
    vm_properties.update(
        {
            "id": STRING,
            "name": STRING,
            "memory_kb": nullable(INTEGER),
            "vcpu_count": nullable(INTEGER),
            "disks": {"type": "array", "items": METADATA},
            "metadata": METADATA,
            "inventory_present": BOOLEAN,
            "last_observed_at": LEGACY_TIME,
            "absent_since": LEGACY_TIME,
            "agent_id": STRING,
            "agent_hostname": STRING,
            "created_at": TIME,
            "last_backup_at": TIME,
            "backup_eligibility": obj(
                {"eligible": BOOLEAN, "has_raw": BOOLEAN, "warnings": STRINGS}
            ),
        }
    )
    queue_schema = obj(
        {
            "queue": {
                "type": "array",
                "items": obj(
                    {
                        "id": STRING,
                        "vm_id": STRING,
                        "vm_name": STRING,
                        "priority": INTEGER,
                        "position": INTEGER,
                        "queued_at": TIME,
                        "schedule_id": nullable(STRING),
                        "created_by": nullable(STRING),
                        "status": STRING,
                        "hold_reason": nullable(STRING),
                        "started_backup_id": nullable(STRING),
                    }
                ),
            },
            "total_queued": INTEGER,
            "processing": INTEGER,
            "running_backups": INTEGER,
            "max_concurrent": INTEGER,
            "available_slots": INTEGER,
        }
    )
    list_contracts = {
        "/api/v1/vms": (
            page(obj(vm_properties)),
            "requested sort field; equal values have no specified tie order",
            "offset",
        ),
        "/api/v1/backups/queue": (
            queue_schema,
            "priority descending, queued_at ascending, id ascending",
            "unpaginated queued state only",
        ),
        "/api/v1/restores": (
            page(restore_item, has_more=False),
            "created_at descending; equal timestamps have no specified tie order",
            "offset",
        ),
        "/api/v1/reports": (
            page(report_item, "reports", paged=False),
            "created_at descending; equal timestamps have no specified tie order",
            "unpaginated",
        ),
        "/api/v1/reports/{report_id}/executions": (
            execution_page,
            "created_at descending; equal timestamps have no specified tie order",
            "offset",
        ),
        "/api/v1/encryption/keys": (
            page(key_item, paged=False),
            "provider-defined; local created_at descending",
            "unpaginated",
        ),
        "/api/v1/activity": (
            page(activity_item, "activities"),
            "created_at descending, source descending, id descending",
            "offset",
        ),
        "/api/v1/activity/unified": (
            page(activity_item, "activities"),
            "created_at descending, source descending, id descending",
            "offset",
        ),
        "/api/v1/backups": (
            page(backup_item),
            "created_at descending; equal timestamps have no specified tie order",
            "offset",
        ),
        "/api/v1/users": (
            page(obj(user_properties)),
            "created_at descending; equal timestamps have no specified tie order",
            "offset",
        ),
        "/api/v1/orchestrator-keys": (
            page(credential_item(), paged=False),
            "created_at descending; equal timestamps have no specified tie order",
            "unpaginated",
        ),
        "/api/v1/registration-keys": (
            page(credential_item(True), paged=False),
            "created_at descending; equal timestamps have no specified tie order",
            "unpaginated",
        ),
        "/api/v1/agents": (
            {"type": "array", "items": agent_item},
            "unspecified",
            "unpaginated",
        ),
    }
    for path, (schema, order, pagination) in list_contracts.items():
        operation = paths.get(path, {}).get("get")
        if operation is None:
            continue
        response_schema(operation, schema)
        operation["x-list-contract"] = {
            "ordering": order,
            "pagination": pagination,
            "snapshot": False,
            "completeness": (
                "Current authorized query; concurrent changes can move offset "
                "boundaries. Counts and items are not a single snapshot."
            ),
        }
    # These single-resource reads carry current dispatch state independently of
    # the immutable admission receipt and the resource's own execution status.
    backup_single = deepcopy(backup_item)
    backup_single["properties"].pop("capacity_state")
    backup_single["required"].remove("capacity_state")
    backup_single["properties"]["scheduler_decision"] = nullable(scheduler_decision())
    backup_single["required"].append("scheduler_decision")
    backup_single["properties"]["recovery_publication"] = nullable(
        obj(
            {
                "state": {
                    "type": "string",
                    "enum": ["pending", "retrying", "ready", "unavailable"],
                },
                "attempts": {"type": "integer", "minimum": 0},
                "next_attempt_at": nullable({"type": "string", "format": "date-time"}),
            }
        )
    )
    backup_single["required"].append("recovery_publication")
    restore_single = deepcopy(restore_item)
    restore_single["properties"]["backup"]["properties"].update(
        {"vm_id": STRING, "status": STRING}
    )
    restore_single["properties"]["backup"]["required"].extend(["vm_id", "status"])
    restore_single["properties"]["target_vm"] = obj(
        {
            "id": STRING,
            "name": STRING,
            "state": nullable(STRING),
            "agent_hostname": nullable(STRING),
        }
    )
    for path, schema in (
        ("/api/v1/backups/{backup_id}", backup_single),
        ("/api/v1/restores/{restore_id}", restore_single),
    ):
        operation = paths.get(path, {}).get("get")
        if operation is not None:
            response_schema(operation, schema)
    for path in ("/api/v1/backups", "/api/v1/restores", "/api/v1/users"):
        operation = paths.get(path, {}).get("get")
        if operation is not None:
            operation["x-list-contract"][
                "ordering"
            ] = "created_at descending, id descending"
    operation = paths.get("/api/v1/vms", {}).get("get")
    if operation is not None:
        operation["x-list-contract"][
            "ordering"
        ] = "requested sort field and direction, then id ascending"
    # Additional lists retain their existing schemas until item fields are audited.
    # Their envelope and continuation facts are still explicit for CLI discovery.
    for path, collection, pagination, order in (
        (
            "/api/v1/vms",
            "items",
            "skip/limit; has_more",
            "requested sort field; ties unspecified",
        ),
        (
            "/api/v1/restores",
            "items",
            "skip/limit; total",
            "created_at descending; ties unspecified",
        ),
        (
            "/api/v1/reports",
            "reports",
            "unpaginated",
            "created_at descending; ties unspecified",
        ),
        (
            "/api/v1/reports/{report_id}/executions",
            "executions",
            "offset/limit; total",
            "created_at descending; ties unspecified",
        ),
        (
            "/api/v1/encryption/keys",
            "items",
            "unpaginated",
            "provider-defined; local created_at descending",
        ),
        (
            "/api/v1/backups/queue",
            "queue",
            "unpaginated",
            "priority descending, queued_at ascending, id ascending",
        ),
    ):
        operation = paths.get(path, {}).get("get")
        if operation is not None:
            operation.setdefault(
                "x-list-contract",
                {
                    "collection": collection,
                    "pagination": pagination,
                    "ordering": order,
                    "snapshot": False,
                    "completeness": (
                        "Current authorized query, not a historical or stable snapshot."
                        " Queue list includes queued state only."
                        if collection == "queue"
                        else (
                            "Current authorized query; concurrent changes can move"
                            " offset boundaries; no snapshot guarantee."
                        )
                    ),
                },
            )
    for path, method, media in (
        ("/api/v1/encryption/keys/export", "post", ["application/octet-stream"]),
        (
            "/api/v1/report-executions/{execution_id}/download",
            "get",
            [
                "application/pdf",
                "text/csv",
                "application/json",
                "text/html",
                "application/octet-stream",
            ],
        ),
    ):
        operation = paths.get(path, {}).get(method)
        if operation is not None:
            operation.setdefault("responses", {})["200"] = {
                "description": (
                    "Binary attachment. Saving the response does not confirm"
                    " independent encryption-key backup custody."
                ),
                "content": {
                    kind: {"schema": {"type": "string", "format": "binary"}}
                    for kind in media
                },
                "headers": {
                    "Content-Disposition": {
                        "schema": STRING,
                        "description": "Attachment filename.",
                    }
                },
            }
    rotation_metadata = obj(
        {
            "rotation_id": STRING,
            "agent_id": STRING,
            "state": {
                "type": "string",
                "enum": ["pending", "activated", "cancelled", "expired"],
            },
            "key_prefix": STRING,
            "created_at": TIME,
            "expires_at": TIME,
            "activated_at": TIME,
        }
    )
    for path, method, schema in (
        (
            "/api/v1/agents/{agent_id}/key-rotations",
            "get",
            page(rotation_metadata, paged=False),
        ),
        (
            "/api/v1/agents/{agent_id}/key-rotations/{rotation_id}",
            "get",
            rotation_metadata,
        ),
        (
            "/api/v1/agents/{agent_id}/key-rotations/{rotation_id}",
            "delete",
            rotation_metadata,
        ),
        (
            "/api/v1/agents/{agent_id}/key-rotations/{rotation_id}/activate",
            "post",
            rotation_metadata,
        ),
    ):
        operation = paths.get(path, {}).get(method)
        if operation is not None:
            response_schema(operation, schema)
    staged = paths.get("/api/v1/agents/{agent_id}/rotate-key", {}).get("post")
    if staged is not None:
        first, replay = deepcopy(rotation_metadata), deepcopy(rotation_metadata)
        for schema, delivery in ((first, "one_time"), (replay, "unavailable")):
            schema["properties"].update(
                {
                    "request_id": STRING,
                    "secret_delivery": {"type": "string", "const": delivery},
                }
            )
            schema["required"].extend(["request_id", "secret_delivery"])
        first["properties"]["api_key"] = {
            "type": "string",
            "writeOnly": True,
            "description": "Returned once; never present in recovery/replay.",
        }
        first["required"].append("api_key")
        response_schema(
            staged,
            {
                "oneOf": [first, replay],
                "discriminator": {"propertyName": "secret_delivery"},
            },
        )
    from operator_admission_contracts import apply_admission_contracts

    apply_admission_contracts(document)
    from operator_protocol_contracts import apply_protocol_contracts
    from operator_surface_contracts import apply_surface_contracts
    from operator_resource_contracts import apply_resource_contracts
    from operator_error_contracts import apply_error_contracts

    apply_protocol_contracts(document)
    apply_surface_contracts(document)
    apply_resource_contracts(document)
    if any(
        path.startswith(
            ("/api/v1/organizations", "/api/v1/billing", "/api/v1/branding")
        )
        for path in document.get("paths", {})
    ):
        # Optional schemas ship with the implementation; the Community image
        # never needs or imports the commercial package.
        from commercial.backend.contracts import apply_commercial_contracts

        apply_commercial_contracts(document)
    apply_error_contracts(document, routes)
    # The poll feed carries invalidations; producer-specific payload keys are
    # intentionally extensible and require authoritative state resynchronization.
    for name in ("LegacyRealtimeEvent", "CursorRealtimeEvent", "RealtimePage"):
        schema = document.get("components", {}).get("schemas", {}).get(name)
        if schema is not None:
            schema["additionalProperties"] = False
            if "payload" in schema.get("properties", {}):
                schema["properties"]["payload"].update(
                    {
                        "description": (
                            "Event-specific invalidation data; fetch authoritative resource"
                            " state after processing the event."
                        ),
                        "x-open-schema-reason": (
                            "Realtime producers attach event-specific JSON metadata; this"
                            " best-effort feed is not an execution or snapshot protocol."
                        ),
                    }
                )
    document["x-operator-contract-version"] = 1
    document["x-response-schema-inventory"] = response_inventory(document)
    return document


def install_operator_contracts(app, definitions, secrets, *, require_mtls=False):
    """Wrap schema generation; no change to route admission or response filtering."""
    original = app.openapi

    def openapi():
        if app.openapi_schema is None:
            document = original()
            app.openapi_schema = apply_contracts(
                document, app.routes, definitions, secrets, require_mtls=require_mtls
            )
        return app.openapi_schema

    app.openapi = openapi
