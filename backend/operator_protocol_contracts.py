"""Audited protocol projections; schema decoration never validates wire responses."""

from copy import deepcopy

from version import API_SERVICE_NAME


def apply_protocol_contracts(document):
    # Import at call time: operator_contracts can call this after its own schemas.
    from operator_contracts import obj, nullable
    from core.licensing import features as installed_features

    S = {"type": "string"}
    INTEGER = {"type": "integer"}
    N = {"type": "number"}
    B = {"type": "boolean"}
    T = {
        "type": "string",
        "description": (
            "ISO 8601 timestamp as serialized by the handler; legacy values may omit a"
            " UTC offset."
        ),
    }
    NT = nullable(T)
    H = {"type": "string", "pattern": "^[0-9a-f]{64}$"}

    def const(value):
        return {
            "const": value,
            "type": (
                "boolean"
                if type(value) is bool
                else "integer" if type(value) is int else "string"
            ),
        }

    def array(item):
        return {"type": "array", "items": item}

    SS = array(S)

    def fields(names, kind=S):
        return {name: kind for name in names.split()}

    def extension(reason, values=True):
        return {
            "type": "object",
            "additionalProperties": values,
            "description": reason,
            "x-open-schema-reason": reason,
        }

    metadata = extension(
        "Provider and agent supplied domain metadata; keys vary by provider and"
        " installed capability."
    )
    stringmap = extension("Dynamic HTTP header names, each with a string value.", S)
    components = document.setdefault("components", {}).setdefault("schemas", {})

    def named(name, schema):
        components["Protocol" + name] = deepcopy(schema)
        return {"$ref": "#/components/schemas/Protocol" + name}

    def model(cls):
        schema = cls.model_json_schema(
            ref_template="#/components/schemas/ProtocolWire{model}"
        )
        for name, definition in schema.pop("$defs", {}).items():
            components["ProtocolWire" + name] = definition
        return schema

    paths = document.get("paths", {})

    def operation(path, method):
        return paths.get(path, {}).get(method)

    def response(
        path,
        method,
        schema,
        status="200",
        media="application/json",
        description="Successful response",
        headers=None,
    ):
        op = operation(path, method)
        if op is None:
            return
        value = {
            "description": description,
            "content": {media: {"schema": deepcopy(schema)}},
        }
        if headers:
            value["headers"] = {name: {"schema": S} for name in headers}
        op.setdefault("responses", {})[status] = value

    def request(path, method, schema, *, required=True, description=None):
        op = operation(path, method)
        if op is None:
            return
        op["requestBody"] = {
            "required": required,
            "content": {"application/json": {"schema": deepcopy(schema)}},
        }
        if description:
            op["requestBody"]["description"] = description

    def get(path, schema):
        response(path, "get", schema)

    def post(path, schema):
        response(path, "post", schema)

    message = obj({"message": S})

    # public.py, version.py, installed_profile.py, licensing.FeatureFlags
    get("/health", obj({"status": const("ok"), "service": const(API_SERVICE_NAME)}))
    ready = obj(
        {
            "status": const("ready"),
            "checks": obj(
                {"database": obj({"status": const("ok"), "required": const(True)})}
            ),
        }
    )
    get("/ready", ready)
    response(
        "/ready",
        "get",
        obj(
            {
                "status": const("not_ready"),
                "checks": obj(
                    {
                        "database": obj(
                            {
                                "status": const("error"),
                                "required": const(True),
                                "code": const("DATABASE_UNAVAILABLE"),
                            }
                        )
                    }
                ),
            }
        ),
        "503",
        description="Required database probe failed",
    )
    response(
        "/metrics",
        "get",
        S,
        media="text/plain",
        description="Prometheus text exposition, version 0.0.4; UTF-8",
    )
    version_base = fields("version") | fields("major minor patch", INTEGER)
    get(
        "/api/v1/version",
        obj(
            version_base
            | fields("service build_date expected_compatible")
            | {
                "features": obj(
                    fields(
                        "key_management agent_lifecycle custom_ca_support"
                        " multi_key_authentication virtnbdbackup_advanced_options"
                        " agent_remote_config",
                        B,
                    )
                )
            }
        ),
    )
    compatibility = obj(
        {
            "compatible": B,
            "status": {"enum": ["aligned", "degraded", "incompatible"]},
            "reason": nullable(S),
        }
    )
    get(
        "/api/v1/compatibility",
        obj(
            {
                "contract_version": const(6),
                "scope": const("organization-online-agents"),
                "organization_id": S,
                "status": {"enum": ["aligned", "degraded", "incompatible"]},
                "api": obj(version_base),
                "frontend": nullable(obj(compatibility["properties"] | {"version": S})),
                "agents": array(
                    obj(fields("hostname version") | compatibility["properties"])
                ),
                "expected_version": S,
                "warnings": SS,
                "degraded_mode": B,
            }
        ),
    )
    profile = named(
        "InstalledProfile",
        obj(
            {
                "edition": {"enum": ["community", "commercial"]},
                "auth_mode": {"enum": ["single_organization", "multi_organization"]},
                "enabled_modules": SS,
            }
        ),
    )
    get(
        "/api/v1/bootstrap",
        obj(
            {
                "schema_version": const(1),
                "edition": {"enum": ["community", "commercial"]},
                "auth_mode": {"enum": ["single_organization", "multi_organization"]},
                "login_methods": obj(fields("password oidc", B)),
            }
        ),
    )
    capability_base = {
        "tier": {"enum": ["oss", "commercial"]},
        "tier_source": const("installed_distribution"),
        "installed_profile": profile,
        "license_enforcement": const("advisory"),
    }
    if installed_features.profile.edition == "commercial":
        common_flags = (
            "multi_tenancy white_labeling billing_api advanced_rbac compliance_reports"
            " client_encryption"
        )
        feature_flags = obj(fields(common_flags, B))
        license_flags = obj(
            fields(
                common_flags + " vault_integration ldap_auth saml_auth dr_orchestration"
                " storage_tiering hsm_support",
                B,
            )
        )
    else:
        feature_flags = obj({"client_encryption": B}, extra=B)
        license_flags = feature_flags
    get(
        "/api/v1/features",
        obj(
            capability_base
            | {
                "edition": S,
                "features": SS,
                "configured_modules": SS,
                "loaded_modules": SS,
                "flags": feature_flags,
            }
        ),
    )
    get(
        "/api/v1/license/info",
        obj(
            capability_base
            | {
                "edition_name": S,
                "features": license_flags,
            }
        ),
    )

    # auth.py. The form request already has a concrete FastAPI schema.
    token = {"access_token": S, "token_type": const("bearer")}
    post(
        "/api/v1/auth/login", obj(token | {"user": obj(fields("username role org_id"))})
    )
    post("/api/v1/auth/refresh", obj(token))
    post("/api/v1/auth/logout", message)
    get(
        "/api/v1/auth/me",
        obj(
            fields("id username role org_id")
            | fields("auth_source role_source full_name email oidc_issuer", nullable(S))
            | fields("is_platform_admin can_manage_installation is_active", B)
            | fields("last_login created_at", NT)
        ),
    )
    get("/api/v1/auth/oidc/status", obj({"enabled": B, "issuer": nullable(S)}))
    request(
        "/api/v1/auth/oidc/test",
        "post",
        obj({"issuer": S, "client_id": dict(S, default="")}, required=["issuer"]),
    )
    post(
        "/api/v1/auth/oidc/test",
        obj(
            {
                "status": const("ok"),
                "check": const("discovery_only"),
                "credentials_verified": const(False),
            }
            | fields("issuer authorization_endpoint token_endpoint")
            | fields("userinfo_endpoint jwks_uri", nullable(S))
        ),
    )
    for path in ("/api/v1/auth/oidc/login", "/api/v1/auth/oidc/callback"):
        op = operation(path, "get")
        if op is not None:
            op.setdefault("responses", {}).pop("200", None)
            op["responses"]["302"] = {
                "description": (
                    "Redirect to issuer authorization URL"
                    if path.endswith("login")
                    else "Redirect to frontend with access token in URL fragment"
                ),
                "x-no-response-body": True,
                "headers": {
                    "Location": {"schema": S},
                    "Set-Cookie": {
                        "schema": S,
                        "description": (
                            "Login sets oidc_state and oidc_pkce cookies; callback"
                            " deletes both cookies on success and failure."
                        ),
                    },
                },
            }
    callback = operation("/api/v1/auth/oidc/callback", "get")
    if callback is not None:
        callback["responses"].pop("422", None)
        callback["responses"]["400"] = {
            "description": (
                "Provider rejection, exchange failure, invalid local state/code/PKCE"
                " and request validation failure use HTML; browser custody cookies are"
                " deleted."
            ),
            "content": {"text/html": {"schema": S}},
            "headers": {"Set-Cookie": {"schema": S}},
        }
        response(
            "/api/v1/auth/oidc/callback",
            "get",
            S,
            "503",
            "text/html",
            "OIDC organization binding unavailable; browser custody cookies are"
            " deleted",
            ["Set-Cookie"],
        )
        response(
            "/api/v1/auth/oidc/callback",
            "get",
            S,
            "500",
            "text/html",
            "Callback or user provisioning transaction failed; browser custody cookies"
            " are deleted",
            ["Set-Cookie"],
        )

    # PKI get_ca_info and routers/pki.py. Expiring-soon can be null when an
    # active certificate has no expiry (Python's short-circuit and expression).
    ca = named(
        "CA",
        obj(
            fields("subject issuer serial fingerprint")
            | fields("not_before not_after", T)
        ),
    )
    post("/api/v1/pki/initialize", obj({"message": S, "ca": ca}))
    response(
        "/api/v1/pki/ca",
        "get",
        {"type": "string", "format": "binary"},
        media="application/x-pem-file",
        headers=["Content-Disposition"],
    )
    get("/api/v1/pki/backend-cert", obj(fields("cert_pem key_pem usage")))
    get(
        "/api/v1/pki/status",
        obj(
            {
                "initialized": B,
                "ca": nullable(ca),
                "certificates": obj(fields("total active expired revoked", INTEGER)),
                "require_mtls": B,
            },
            required=["initialized", "ca", "certificates"],
        ),
    )
    get(
        "/api/v1/pki/certificates",
        obj(
            {
                "items": array(
                    obj(
                        fields(
                            "id agent_id serial_number fingerprint common_name status"
                        )
                        | fields("issued_at expires_at revoked_at", NT)
                        | {"expiring_soon": nullable(B)}
                    )
                )
            }
        ),
    )
    post("/api/v1/pki/certificates/{cert_id}/revoke", obj(fields("message id")))
    request(
        "/api/v1/pki/renew",
        "post",
        obj({"csr": {"type": "string", "minLength": 1}}, extra=True),
    )
    post("/api/v1/pki/renew", obj(fields("cert_pem fingerprint") | {"expires_at": NT}))

    get(
        "/api/v1/config/realtime",
        obj(
            fields("enableWebSocket enablePolling", B)
            | fields("pollingInterval wsReconnectDelay wsMaxReconnectAttempts", INTEGER)
        ),
    )
    for path in ("/api/v1/auth/oidc/login", "/api/v1/auth/oidc/callback"):
        op = operation(path, "get")
        if op is not None and "302" in op.get("responses", {}):
            op["responses"]["302"]["x-no-response-body"] = True
    # /api/v1/updates already describes both response-model representations.
    for name in ("CursorRealtimeEvent", "LegacyRealtimeEvent"):
        payload = components.get(name, {}).get("properties", {}).get("payload")
        if payload is not None:
            payload.update(
                description=(
                    "Event-kind dependent invalidation payload; clients refresh"
                    " authoritative snapshots."
                ),
                **{
                    "x-open-schema-reason": (
                        "Payload fields vary by event kind and installed producer;"
                        " these are invalidation hints, not resource snapshots."
                    )
                }
            )

    # VM and agent inventory: identity_fields emits raw datetime objects, which
    # FastAPI JSON encoding can serialize without a zone on naive DB values.
    identity = (
        fields("provider namespace vm_uid vmi_uid replaces_vm_id", nullable(S))
        | {"inventory_present": B}
        | fields("last_observed_at absent_since", NT)
    )
    vm = (
        fields("id name")
        | fields("state uuid", nullable(S))
        | fields("memory_kb vcpu_count", nullable(INTEGER))
        | {"disks": array(metadata), "metadata": metadata}
        | identity
    )
    eligibility = obj({"eligible": B, "has_raw": B, "warnings": SS})
    get(
        "/api/v1/vms/{vm_id}",
        obj(
            {k: v for k, v in vm.items() if k != "metadata"}
            | {
                "vm_metadata": metadata,
                "agent_id": S,
                "agent_hostname": S,
                "backup_count": INTEGER,
                "created_at": NT,
                "backup_eligibility": eligibility,
            }
        ),
    )
    post("/api/v1/vms/ids-by-filter", obj({"vm_ids": SS, "count": INTEGER}))
    request(
        "/api/v1/vms/ids-by-filter",
        "post",
        obj(
            fields("search agent_id state group_id", nullable(S)),
            required=[],
            extra=True,
        ),
    )
    key_info = obj(
        {
            "key_prefix": S,
            "expires_at": NT,
            "enabled": B,
            "is_valid": B,
            "last_used_at": NT,
        }
    )
    agent_detail = obj(
        fields("id hostname status")
        | fields("display_name ip_address version platform", nullable(S))
        | {
            "port": nullable(INTEGER),
            "last_heartbeat": NT,
            "created_at": NT,
            "vm_count": INTEGER,
            "vms": array(obj(vm)),
            "capabilities": metadata,
            "metrics": metadata,
            "config": metadata,
            "api_key": nullable(key_info),
        }
    )
    get("/api/v1/agents/{agent_id}", agent_detail)
    response(
        "/api/v1/agents/{agent_id}",
        "patch",
        obj(fields("id hostname status message") | {"display_name": nullable(S)}),
    )
    response(
        "/api/v1/agents/{agent_id}/settings",
        "patch",
        obj(fields("id hostname message") | {"config": metadata}),
    )
    response(
        "/api/v1/agents/{agent_id}",
        "delete",
        obj(
            {"message": S, "deleted": obj(fields("vms backups certificates", INTEGER))}
        ),
    )
    tls = obj(fields("ca_cert agent_cert agent_key fingerprint") | {"expires_at": T})
    post(
        "/api/v1/agents/register",
        obj(
            fields(
                "agent_id hostname api_key key_prefix orchestrator_url env_snippet"
                " message"
            )
            | {
                "orchestrator_api_key_required": B,
                "heartbeat_interval": INTEGER,
                "tls": nullable(tls),
            }
        ),
    )
    request(
        "/api/v1/agents/register",
        "post",
        obj(
            {
                "hostname": S,
                "capabilities": metadata,
                "display_name": nullable(S),
                "ip_address": nullable(S),
                "port": nullable(INTEGER),
                "version": nullable(S),
                "libvirt_uri": nullable(S),
            },
            required=["hostname"],
            extra=True,
        ),
        description=(
            "Registration key must authorize hostname. Capabilities are provider"
            " metadata. Unknown fields are ignored; type validation is performed by"
            " existing handler/database behavior, not this document."
        ),
    )
    post(
        "/api/v1/agents/{hostname}/vms",
        obj({"synced": INTEGER, "agent_hostname": S, "message": S}),
    )
    inventory_item = obj(
        fields("name")
        | fields("provider namespace vm_uid uuid vmi_uid state", S)
        | fields("memory_kb vcpu_count", nullable(INTEGER))
        | {"disks": array(metadata), "metadata": metadata},
        required=["name"],
        extra=True,
    )
    request(
        "/api/v1/agents/{hostname}/vms",
        "post",
        obj(
            {
                "vms": array(inventory_item),
                "complete": dict(B, default=False),
                "source_namespaces": SS,
            },
            required=["vms"],
            extra=True,
        ),
        description=(
            "Stable vm_uid (or libvirt uuid) required directly on each entry. Provider"
            " and namespace may fall back to entry metadata. KubeVirt requires"
            " namespace. Scope ceilings and complete inventory semantics are checked by"
            " sync_inventory."
        ),
    )

    # Heartbeat request has deliberately permissive legacy JSON decoding.
    heartbeat_names = (
        "status version ip_address backup_storage_path provider storage_role"
        " storage_measurement_error"
    )
    heartbeat = obj(
        fields(heartbeat_names, nullable(S))
        | fields(
            "port cpu_cores active_backups active_restores backup_storage_free_bytes"
            " backup_storage_total_bytes",
            nullable(INTEGER),
        )
        | fields(
            "cpu_usage_percent memory_usage_percent load_average_15m"
            " disk_usage_percent",
            nullable(N),
        )
        | fields("provider_accessible libvirt_accessible", nullable(B))
        | {
            "scope": nullable(metadata),
            "capabilities": metadata,
            "events": array(metadata),
        },
        required=[],
        extra=True,
    )
    request(
        "/api/v1/health/agents/{agent_id}/heartbeat",
        "post",
        heartbeat,
        required=False,
        description=(
            "Legacy receiver treats malformed/empty JSON as an empty heartbeat;"
            " non-object JSON has no successful path. Extra fields are ignored."
            " Provider events and capabilities are extensible observations, not"
            " publication authority."
        ),
    )
    s3 = obj(
        {"enabled": const(True), "endpoint": nullable(S), "region": nullable(S)}
        | fields("bucket prefix access_key secret_key")
        | {"delete_local": B}
    )
    post(
        "/api/v1/health/agents/{agent_id}/heartbeat",
        obj(
            {
                "status": const("ok"),
                "timestamp": NT,
                "agent_id": S,
                "config": metadata,
                "s3_config": nullable(s3),
            }
        ),
    )
    get(
        "/api/v1/agents/{agent_id}/pending-jobs",
        obj(
            {
                "backups": array(
                    obj(
                        {
                            "id": S,
                            "vm_name": nullable(S),
                            "storage_path": nullable(S),
                            "started_at": NT,
                            "status": S,
                        }
                    )
                )
            }
        ),
    )

    # health.py projections. include can remove any section except base fields.
    agents_health = obj(
        {
            "summary": obj(
                fields("total_agents online offline", INTEGER)
                | {"health_percentage": N}
            ),
            "agents": array(
                obj(
                    fields("id hostname status")
                    | {
                        "last_heartbeat": NT,
                        "time_since_heartbeat_seconds": INTEGER,
                        "vm_count": INTEGER,
                    }
                )
            ),
        }
    )
    get("/api/v1/health/agents", agents_health)
    backup_health = obj(
        {
            "summary": obj(
                fields("total_backups completed failed running pending", INTEGER)
            ),
            "health_metrics": obj(
                fields(
                    "recent_failures_24h recent_completions_24h old_backups_past_retention"
                    " avg_backup_size_bytes total_storage_bytes",
                    INTEGER,
                )
                | {"success_rate_7d": N}
            ),
            "recent_failures": array(
                obj(fields("id vm_id vm_name error") | {"created_at": NT})
            ),
            "health_status": S,
        }
    )
    get("/api/v1/health/backups", backup_health)
    system_health = obj(
        {
            "status": S,
            "timestamp": NT,
            "metrics": obj(
                {
                    "agents": obj(fields("total online offline", INTEGER)),
                    "vms": obj({"total": INTEGER}),
                    "backups": obj(fields("total running", INTEGER)),
                    "schedules": obj(fields("total active inactive", INTEGER)),
                    "users": obj({"total": INTEGER}),
                    "storage": obj({"total_bytes": INTEGER, "total_gb": N}),
                }
            ),
            "activity": obj({"recent_actions_1h": INTEGER}),
        }
    )
    get("/api/v1/health/system", system_health)
    health_properties = {
        "status": S,
        "timestamp": NT,
        "database": obj(
            {"status": S} | fields("response_time connections max_connections", INTEGER)
        ),
        "agents": obj(
            {"status": S}
            | fields("total online healthy", INTEGER)
            | {"degraded": array(obj({"name": S, "issues": SS}))}
        ),
        "storage": obj(
            {"status": S, "used_space": N, "backup_count": INTEGER, "note": S}
        ),
        "s3": obj(
            {"configured": B, "status": S}
            | fields("endpoint bucket error", nullable(S))
            | {"last_check": NT}
        ),
        "api": obj(fields("status version")),
        "metrics": obj(
            fields(
                "active_backups pending_jobs failed_jobs_24h online_agents total_vms"
                " total_backups",
                INTEGER,
            )
        ),
        "services": array(obj(fields("name description status"))),
    }
    get("/api/v1/health", obj(health_properties, required=["status", "timestamp"]))
    get("/api/v1/health/detailed", obj(health_properties))

    # support_diagnostics.collect uses finite allowlisted projections only.
    def diagnostic_row(
        ids="", states="status", times="", bools="", numbers="", version=False
    ):
        p = (
            fields(ids, nullable(S))
            | fields(states)
            | fields(times, NT)
            | fields(bools, nullable(B))
            | fields(numbers, nullable(INTEGER))
        )
        if version:
            p["version"] = nullable(S)
        return obj(p)

    diagnostic_rows = {
        "agents": diagnostic_row(
            "id",
            times="last_heartbeat cert_expires_at",
            bools="mtls_enabled",
            version=True,
        ),
        "backups": diagnostic_row(
            "id vm_id parent_backup_id",
            "status capacity_state backup_type",
            "created_at completed_at",
            "native_intent_present native_inventory_present"
            " native_failure_evidence_present",
            "progress chain_position",
        ),
        "restores": diagnostic_row(
            "id backup_id",
            times="created_at completed_at",
            bools="error_recorded",
            numbers="progress",
        ),
        "verifications": diagnostic_row(
            "id backup_id verification_worker_id",
            times="created_at completed_at",
            bools="verification_cancel_requested",
            numbers="verification_read_attempts verification_read_limit",
        ),
    }

    def section(row):
        return {
            "oneOf": [
                obj({"status": const("observed"), "truncated": B, "rows": array(row)}),
                obj(
                    {
                        "status": const("unavailable"),
                        "reason": const("collection_failed"),
                    }
                ),
            ]
        }

    get(
        "/api/v1/health/diagnostics",
        obj(
            fields("schema report_id collected_at backend_version scope privacy")
            | {
                "limits": obj(fields("rows_per_section query_timeout_ms", INTEGER)),
                "sections": obj({k: section(v) for k, v in diagnostic_rows.items()}),
                "guidance": obj(fields("held failed unavailable")),
                "status": {"enum": ["collected", "partial"]},
            }
        ),
    )

    # Manually decoded storage callbacks. These are strict protocol messages,
    # with additional digest/equality/custody checks documented at request level.
    base = "/api/v1/agents/backups/{backup_id}/"
    binding = named(
        "AttemptBinding",
        obj(
            fields("reservation_id attempt_id")
            | {"plan_sha256": H, "key_ref": nullable(S)}
        ),
    )
    retirement_binding = obj(
        fields("reservation_id attempt_id") | fields("plan_sha256 journal_sha256", H)
    )
    request(base + "storage-retirement", "post", retirement_binding)
    post(
        base + "storage-retirement",
        obj(
            {"schema": const(1)}
            | fields(
                "org_id backup_id reservation_id attempt_id operation_id capacity_id"
            )
            | fields("plan_sha256 journal_sha256 release_sha256", H)
        ),
    )
    request(base + "transaction-key", "post", binding)
    key_none = obj(
        fields("reservation_id attempt_id")
        | {
            "plan_sha256": H,
            "key_ref": nullable(S),
            "format": const("none"),
            "dek": {"type": "null"},
        }
    )
    key_encrypted = obj(
        fields("reservation_id attempt_id key_ref")
        | {
            "plan_sha256": H,
            "format": const("vnbu1-aes256gcm-chunk5242880"),
            "dek": {
                "type": "string",
                "description": (
                    "Base64 encoded 32 byte attempt data key; memory-only, no-store"
                    " delivery."
                ),
            },
        }
    )
    post(base + "transaction-key", {"oneOf": [key_none, key_encrypted]})
    admission = obj(
        fields("attempt_id") | fields("intent_sha256 producer_request_sha256", H)
    )
    request(base + "native-admission", "post", admission)
    post(
        base + "native-admission",
        obj(admission["properties"] | {"admitted": const(True)}),
    )
    for endpoint, evidence in (
        ("native-no-effect", "refusal"),
        ("native-closed-failure", "closure"),
        ("native-fenced-failure", "fence"),
    ):
        body = obj(
            fields("intent_canonical " + evidence + "_canonical")
            | fields("intent_sha256 " + evidence + "_sha256", H)
        )
        request(
            base + endpoint,
            "post",
            body,
            description=(
                "Canonical JSON strings and SHA256 digests must match the original"
                " admitted intent and exact versioned evidence certificate. Equality,"
                " producer identity, and database custody gates are enforced"
                " separately."
            ),
        )
        post(
            base + endpoint,
            obj(
                {"settled": const(True)}
                | fields("attempt_id capacity_id")
                | fields("intent_sha256 " + evidence + "_sha256", H)
            ),
        )
    uuid = {
        "type": "string",
        "pattern": (
            "^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
        ),
    }
    name = {"type": "string", "pattern": "^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$"}
    positive_size = {"type": "integer", "minimum": 1, "maximum": 2**63 - 1}

    def bounded_array(item, maximum):
        return {"type": "array", "items": item, "minItems": 1, "maxItems": maximum}

    native_disk = obj(
        fields("bus id target", name)
        | {"serial": dict(S, description="At most 256 UTF-8 bytes.")}
    )
    native_file = obj(
        {
            "artifact_id": H,
            "path": dict(
                S,
                minLength=1,
                maxLength=1024,
                description=(
                    "Relative path with at most 16 safe components; case collisions are"
                    " refused."
                ),
            ),
            "member_backup_id": uuid,
            "member_checkpoint": name,
            "role": {
                "enum": [
                    "disk_payload",
                    "disk_checksum",
                    "disk_metadata",
                    "domain_config",
                    "checkpoint",
                    "autostart",
                    "backup_metadata",
                ]
            },
            "disk_id": nullable(name),
            "ctime_ns": dict(INTEGER, minimum=-(2**63), maximum=2**63 - 1),
            "mtime_ns": dict(INTEGER, minimum=-(2**63), maximum=2**63 - 1),
            "device": dict(INTEGER, minimum=0, maximum=2**64 - 1),
            "inode": dict(INTEGER, minimum=1, maximum=2**64 - 1),
            "size": dict(INTEGER, minimum=0, maximum=2**50),
        }
    )
    native_inventory = named(
        "NativeInventory",
        obj(
            fields("attempt_id backup_id domain_uuid", uuid)
            | fields("checkpoint job_id", name)
            | {
                "format": const("libvirt-native-fileset/1"),
                "disks": bounded_array(native_disk, 128),
                "files": bounded_array(native_file, 4096),
            }
        ),
    )
    source_disk = obj(
        fields("target bus", name)
        | {
            "source": dict(S, minLength=1, maxLength=4096, pattern="^/"),
            "format": {"enum": ["qcow2", "raw"]},
        }
    )
    manifest = obj(
        {"schema": const("libvirt-push-qcow2/1")}
        | fields("backup_id attempt_id domain_uuid", uuid)
        | {"checkpoint": name}
        | fields("checkpoint_sha256 domain_xml_sha256", H)
        | {"parent_backup_id": nullable(uuid), "parent_manifest_sha256": nullable(H)}
        | {
            "source": bounded_array(source_disk, 128),
            "exclusions": SS,
            "disks": bounded_array(
                obj(
                    fields("target file")
                    | fields("size_bytes virtual_size", positive_size)
                    | {"sha256": H}
                ),
                128,
            ),
        }
    )
    push_result = named(
        "NativePushResult", obj({"manifest": manifest, "manifest_sha256": H})
    )
    closed_job = obj(
        fields("job_id attempt_id")
        | {
            "invocation_id": dict(S, pattern="^[0-9a-f]{32}$"),
            "exit_code": const(0),
            "state": {"enum": ["exited", "sealed"]},
        }
    )
    request(
        base + "native-inventory",
        "post",
        obj(
            {
                "intent_sha256": H,
                "inventory": native_inventory,
                "closed_job": closed_job,
                "push_result": push_result,
            }
        ),
        description=(
            "Inventory, producer manifest and closed job must bind exactly to the"
            " admitted intent, domain and selected disks. Canonical digest and"
            " cross-field checks remain runtime requirements."
        ),
    )
    post(
        base + "native-inventory",
        obj(
            {
                "accepted": const(True),
                "inventory_sha256": H,
                "attempt_id": S,
                "completed": const(False),
            }
        ),
    )
    request(
        base + "native-transaction",
        "post",
        obj({"attempt_id": S, "inventory_sha256": H}),
    )
    from core.native_storage_wire import NativeTransactionRequest

    native_transaction = model(NativeTransactionRequest)
    # The Python model uses dict[str, Any] but validate_source closes its fields.
    components["ProtocolWireNativePlan"]["properties"]["source"] = obj(
        {
            "representation": const("libvirt-native-fileset/1"),
            "agent_id": S,
            "vm_id": S,
            "inventory_sha256": H,
            "inventory": native_inventory,
        }
    )
    native_transaction = named("NativeTransaction", native_transaction)
    from core.storage_wire import TransactionRequest

    kubevirt_transaction = named("KubeVirtTransaction", model(TransactionRequest))
    source_schema = components["ProtocolWireSource"]
    source_schema["properties"]["schema"] = const(1)
    if "schema" not in source_schema["required"]:
        source_schema["required"].append("schema")
    named("StorageTransaction", {"oneOf": [kubevirt_transaction, native_transaction]})
    post(base + "native-transaction", native_transaction)
    request(
        base + "native-publication",
        "post",
        obj(fields("reservation_id acceptance_id") | {"receipt_sha256": H}),
    )
    post(
        base + "native-publication",
        obj(
            {
                "reservation_id": S,
                "status": const("completed"),
                "completed": const(True),
            }
        ),
    )

    from core.storage_wire import Volume, Parent

    volume = model(Volume)
    parent = model(Parent)
    finalize_binding = named(
        "FinalizeBinding",
        obj(
            fields(
                "protocol reservation_id attempt_id acceptance_id namespace vm_uid"
                " tracker_name tracker_uid vmb_name vmb_uid checkpoint started_at"
                " guest_evidence_source"
            )
            | fields("plan_sha256 receipt_sha256", H)
            | {
                "vmi_uid": nullable(S),
                "parent": nullable(parent),
                "volumes": array(volume),
                "guest_consistency": {
                    "enum": ["quiesced", "failed", "crash-consistent", "unknown"]
                },
            }
        ),
    )
    request(
        base + "finalize-intent",
        "post",
        finalize_binding,
        description=(
            "Exact accepted receipt and immutable source binding; started_at must"
            " include timezone. No publication authority is granted by intent"
            " acceptance."
        ),
    )
    post(base + "finalize-intent", obj({"intent_id": S, "binding": finalize_binding}))
    request(
        base + "checkpoint-proof",
        "post",
        obj(
            fields(
                "intent_id checkpoint tracker_resource_version"
                " terminal_resource_version checkpoint_creation_time guest_consistency"
            )
            | {"vmb_absent": const(True)}
        ),
    )
    op = operation(base + "checkpoint-proof", "post")
    if op is not None:
        op.setdefault("responses", {}).pop("200", None)
    response(
        base + "checkpoint-proof",
        "post",
        {
            "oneOf": [
                obj(
                    {
                        "intent_id": S,
                        "status": const("awaiting_manifest"),
                        "completed": const(False),
                    }
                ),
                obj(
                    {
                        "intent_id": S,
                        "status": const("completed"),
                        "completed": const(True),
                    }
                ),
            ]
        },
        "202",
        description=(
            "Checkpoint evidence durably accepted; publication may still await"
            " manifest. Completed replay also returns 202."
        ),
    )

    part = obj(
        {
            "upload_id": S,
            "number": {"type": "integer", "minimum": 1, "maximum": 10000},
            "bytes": {"type": "integer", "minimum": 0},
            "sha256": H,
        }
    )
    acknowledged_part = obj(part["properties"] | {"etag": S})
    control_variants = []
    for name, args in (
        ("create", obj({})),
        ("part", part),
        ("part_ack", acknowledged_part),
        (
            "complete",
            obj(
                {
                    "upload_id": S,
                    "parts": array(
                        obj(
                            {
                                k: v
                                for k, v in acknowledged_part["properties"].items()
                                if k != "upload_id"
                            }
                        )
                    ),
                }
            ),
        ),
        ("head", obj({"etag": S, "version_id": nullable(S)})),
        (
            "compensate_pre_finalize",
            obj(
                fields("abort_id acceptance_id")
                | {
                    "receipt_sha256": H,
                    "reason": const("original_native_identity_lost"),
                }
            ),
        ),
    ):
        control_variants.append(
            obj(
                {
                    "schema": const(1),
                    "binding": binding,
                    "artifact_key": (
                        const("") if name == "compensate_pre_finalize" else S
                    ),
                    "operation": const(name),
                    "args": args,
                }
            )
        )
    request(
        base + "storage-control",
        "post",
        {"oneOf": control_variants},
        description=(
            "Exact attempt binding required; part sizes and sequence, object"
            " identities, signed authority lifetime and compensation custody are"
            " checked against the committed plan."
        ),
    )
    storage_metadata = obj(
        fields(
            "vnbui-protocol vnbui-org-id vnbui-backup-id vnbui-reservation-id"
            " vnbui-plan-sha256 vnbui-artifact-id"
        )
    )
    object_info = obj(
        {
            "etag": S,
            "version_id": nullable(S),
            "bytes": INTEGER,
            "sha256": S,
            "checksum_type": {"enum": ["", "FULL_OBJECT", "COMPOSITE"]},
            "metadata": {"oneOf": [obj({}), storage_metadata]},
        }
    )
    authority = obj(
        {"method": const("PUT"), "url": S, "headers": stringmap, "expires_at": INTEGER}
    )
    control_response = {
        "oneOf": [
            obj({"schema": const(1), "upload_id": S}),
            obj({"schema": const(1), "acknowledged": const(True)}),
            obj({"schema": const(1), "authority": authority}),
            obj({"schema": const(1), "object": object_info}),
            obj(
                {
                    "schema": const(1),
                    "intent_id": S,
                    "s3_absent": B,
                    "cleanup_required": const(True),
                    "capacity_state": const("reserved"),
                }
            ),
        ]
    }
    post(base + "storage-control", control_response)

    # Receipt versions are separate closed shapes, not arbitrary verification JSON.
    receipt_object_properties = (
        fields("key etag volume_id role")
        | {"version_id": nullable(S)}
        | fields("plaintext_bytes ciphertext_bytes", dict(INTEGER, minimum=0))
        | fields("plaintext_sha256 ciphertext_sha256", H)
    )
    old_receipt = obj(
        {"schema": const(1)}
        | fields("reservation_id backup_id endpoint bucket")
        | {"objects": bounded_array(obj(receipt_object_properties), 4096)}
    )
    transaction_receipt = obj(
        {"protocol": const("vnbui-storage-transaction/1"), "schema": const(2)}
        | fields("reservation_id backup_id endpoint bucket")
        | {"objects": bounded_array(obj(receipt_object_properties), 4096)}
    )
    native_receipt_properties = {
        k: v for k, v in receipt_object_properties.items() if k != "volume_id"
    } | {"artifact_id": H, "disk_id": nullable(S)}
    native_receipt = obj(
        {
            "protocol": const("vnbui-storage-transaction/1"),
            "schema": const(2),
            "representation": const("libvirt-native-fileset/1"),
        }
        | fields("reservation_id backup_id endpoint bucket")
        | {"objects": bounded_array(obj(native_receipt_properties), 4096)}
    )
    old_receipt = named("LegacyStorageReceipt", old_receipt)
    transaction_receipt = named("KubeVirtStorageReceipt", transaction_receipt)
    native_receipt = named("NativeStorageReceipt", native_receipt)
    receipt = named(
        "StorageReceipt", {"oneOf": [old_receipt, transaction_receipt, native_receipt]}
    )
    named("TransactionReceipt", {"oneOf": [transaction_receipt, native_receipt]})
    request(
        base + "prepared-receipt",
        "post",
        receipt,
        description=(
            "Receipt must match all committed artifacts and target; canonical ordering,"
            " byte counts and digest bindings are verified. Acceptance does not imply"
            " backup visibility or completion."
        ),
    )
    verification_properties = {
        "key": S,
        "version_id": nullable(S),
        "assurance": {"enum": ["provider_checksum_verified", "identity_metadata_only"]},
        "reason": nullable(S),
    }
    verification = array(obj(verification_properties))
    old_verification = array(
        obj(
            verification_properties
            | fields("checksum_type checksum_sha256", nullable(S))
        )
    )
    post(
        base + "prepared-receipt",
        {
            "oneOf": [
                obj(
                    {
                        "reservation_id": S,
                        "accepted": const(True),
                        "verification": obj(
                            {
                                "receipt": old_receipt,
                                "verification": old_verification,
                                "scrub_required": B,
                            }
                        ),
                    }
                ),
                obj(
                    {
                        "protocol": const("vnbui-storage-transaction/1"),
                        "reservation_id": S,
                        "receipt_sha256": H,
                        "accepted": const(True),
                        "acceptance_id": S,
                        "verification": verification,
                        "scrub_required": B,
                    }
                ),
            ]
        },
    )
    return document
