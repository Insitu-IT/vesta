"""Source-audited UI/operator response descriptions; no runtime filtering."""

from copy import deepcopy


def apply_surface_contracts(document):
    from operator_contracts import obj, nullable, page

    S = {"type": "string"}
    INTEGER = {"type": "integer"}
    N = {"type": "number"}
    B = {"type": "boolean"}
    T = nullable({"type": "string", "format": "date-time"})

    def arr(item):
        return {"type": "array", "items": deepcopy(item)}

    def const(value):
        return {
            "const": value,
            "type": "boolean" if isinstance(value, bool) else "string",
        }

    def free(reason, *, mapping=False, values=None):
        schema = {"description": reason, "x-open-schema-reason": reason}
        if mapping:
            schema.update(
                type="object",
                additionalProperties=values if values is not None else True,
            )
        return schema

    JSON = free(
        "Persisted JSON from an unvalidated dict input; arbitrary JSON values are"
        " retained."
    )
    TAGS = free("User-defined tag keys and JSON values.", mapping=True)
    paths = document.get("paths", {})

    def put(path, method, schema, status="200"):
        op = paths.get("/api/v1" + path, {}).get(method)
        if op is not None:
            response = op.setdefault("responses", {}).setdefault(
                status, {"description": "Successful Response"}
            )
            response["content"] = {"application/json": {"schema": deepcopy(schema)}}

    def body(path, method, properties, required=(), *, extra=True, description=None):
        op = paths.get("/api/v1" + path, {}).get(method)
        if op is not None:
            schema = obj(properties, required=list(required), extra=extra)
            if extra:
                schema["x-open-schema-reason"] = (
                    "Unknown input keys are ignored by this legacy dict handler."
                )
            if description:
                schema["description"] = description
            op["requestBody"] = {
                "required": True,
                "content": {"application/json": {"schema": schema}},
            }

    message = obj({"message": S})
    ok = obj({"status": const("ok")})
    strings = arr(S)
    rule = obj(
        {
            "field": {"type": "string", "enum": ["name", "state", "agent_id"]},
            "op": {"type": "string", "enum": ["eq", "neq", "regex", "glob", "in"]},
            "value": JSON,
        },
        extra=True,
    )
    rule["x-open-schema-reason"] = (
        "Group validators inspect field/op/value and retain additional rule metadata."
    )
    group_vm = obj({"id": S, "name": S, "state": nullable(S), "agent_hostname": S})
    group = obj(
        {
            "id": S,
            "name": S,
            "description": nullable(S),
            "tags": strings,
            "group_type": S,
            "vm_count": INTEGER,
            "created_at": T,
        }
    )
    put("/groups", "get", page(group))
    for path, method in (("/groups", "post"), ("/groups/{group_id}", "put")):
        put(path, method, group)
    detail = obj({k: v for k, v in group["properties"].items() if k != "vm_count"})
    detail["properties"].update(
        rules=nullable(arr(rule)),
        rules_match={"type": "string", "enum": ["all", "any"]},
        vms=page(group_vm),
    )
    detail["required"] += ["rules", "rules_match", "vms"]
    put("/groups/{group_id}", "get", detail)
    put("/groups/{group_id}", "delete", obj({"message": S, "deleted_id": S}))
    put(
        "/groups/{group_id}/vms",
        "post",
        obj(
            {
                "group_id": S,
                "group_name": S,
                "added": strings,
                "already_in_group": strings,
                "not_found": strings,
                "total_vms": INTEGER,
            }
        ),
    )
    put(
        "/groups/{group_id}/vms/{vm_id}",
        "delete",
        obj({"message": S, "group_id": S, "vm_id": S}),
    )
    put(
        "/groups/{group_id}/preview",
        "post",
        obj({"vms": arr(group_vm), "total": INTEGER, "truncated": B}),
    )
    body(
        "/groups/{group_id}/preview",
        "post",
        {
            "rules": arr(rule),
            "rules_match": free(
                "Only the value any selects OR; all other JSON values select AND in the"
                " preview handler."
            ),
        },
        ["rules"],
    )

    # Notification JSONB fields are not constrained by the manual dict handlers.
    nr = {
        "id": S,
        "name": S,
        "event_type": S,
        "enabled": nullable(B),
        "recipients": JSON,
        "created_at": T,
    }
    put("/notifications/rules", "post", obj(nr), "201")
    nr = {**nr, "notification_type": nullable(S)}
    put("/notifications/rules", "get", arr(obj(nr)))
    put(
        "/notifications/rules/{rule_id}",
        "get",
        obj({**nr, "conditions": JSON, "template": nullable(S)}),
    )
    put("/notifications/rules/{rule_id}", "put", obj({"message": S, "id": S}))
    put("/notifications/rules/{rule_id}", "delete", message)
    nfields = {
        "name": S,
        "event_type": S,
        "enabled": nullable(B),
        "notification_type": nullable(S),
        "recipients": JSON,
        "conditions": JSON,
        "template": nullable(S),
    }
    for path, method in (
        ("/notifications/rules", "post"),
        ("/notifications/rules/{rule_id}", "put"),
    ):
        body(
            path,
            method,
            nfields,
            description="Legacy dict input; database constraints apply after decoding.",
        )
    log = obj(
        {
            "id": S,
            "rule_id": nullable(S),
            "event_type": S,
            "recipient": S,
            "subject": nullable(S),
            "status": nullable(S),
            "created_at": T,
        }
    )
    put("/notifications/logs", "get", page(log, has_more=False))
    inbox = obj(
        {
            "id": S,
            "type": S,
            "title": nullable(S),
            "message": nullable(S),
            "status": nullable(S),
            "read": B,
            "created_at": T,
        }
    )
    put("/notifications", "get", page(inbox, "notifications", paged=False))
    prefs = dict.fromkeys(
        (
            "email_enabled",
            "backup_success",
            "backup_failure",
            "agent_offline",
            "storage_low",
        ),
        B,
    )
    put("/notifications/settings", "get", obj({"settings": obj(prefs)}))
    body(
        "/notifications/settings",
        "put",
        dict.fromkeys(prefs, JSON),
        description="Known keys use JSON truthiness to store booleans.",
    )
    for path, method in (
        ("/notifications/settings", "put"),
        ("/notifications/{notification_id}/read", "put"),
        ("/notifications/mark-all-read", "post"),
        ("/notifications/{notification_id}", "delete"),
    ):
        put(path, method, ok)
    for path in ("/notifications/test", "/settings/test-email"):
        put(path, "post", obj({"message": S, "recipient": JSON}))
        body(
            path,
            "post",
            {"recipient": JSON},
            description=(
                "Recipient passed through to email helper; settings test defaults to"
                " current user email when omitted."
            ),
        )

    backup_search = obj({"id": S, "vm_name": S, "status": S, "created_at": T})
    vm_search = obj(
        {"id": S, "name": S, "state": nullable(S), "agent_hostname": nullable(S)}
    )
    global_vm = obj({"id": S, "name": S, "state": nullable(S), "hostname": nullable(S)})
    put("/search", "post", obj({"vms": arr(global_vm), "backups": arr(backup_search)}))
    body(
        "/search",
        "post",
        {
            "query": nullable(S),
            "filters": free(
                "Search switches vms/backups use JSON truthiness; unknown switches"
                " ignored.",
                mapping=True,
            ),
        },
    )
    saved = {
        "id": S,
        "name": S,
        "search_type": S,
        "filters": JSON,
        "is_public": B,
        "created_at": T,
    }
    put("/saved-searches", "post", obj(saved))
    saved = {**saved, "description": nullable(S)}
    put("/saved-searches", "get", arr(obj({**saved, "is_owner": B})))
    put("/saved-searches/{search_id}", "get", obj(saved))
    put("/saved-searches/{search_id}", "delete", message)
    body(
        "/saved-searches",
        "post",
        {
            "name": S,
            "description": nullable(S),
            "search_type": S,
            "filters": JSON,
            "is_public": B,
        },
    )
    result = page({"anyOf": [backup_search, vm_search]}, has_more=False)
    result["properties"]["search_name"] = S
    result["description"] = (
        "backup/vm searches include search_name; unsupported stored types return an"
        " empty page without search_name."
    )
    put("/saved-searches/{search_id}/execute", "post", result)

    # Schedule serializers vary: create has fewer times/names; update omits names.
    policy = obj(
        {
            "schema": {"type": "integer", "const": 1},
            "full_every_days": {"type": "integer", "minimum": 1, "maximum": 36500},
            "max_incrementals": {"type": "integer", "minimum": 1, "maximum": 255},
        }
    )
    authority = {
        "authority_revision": INTEGER,
        "current_grant_id": nullable(S),
        "authority_state": {
            "type": "string",
            "enum": [
                "retired",
                "unenrolled",
                "binding_invalid",
                "revoked",
                "org_epoch_held",
                "active",
                "paused",
            ],
        },
    }
    schedule = {
        **authority,
        "id": S,
        "name": S,
        "vm_id": nullable(S),
        "vm_group_id": nullable(S),
        "cron_expression": S,
        "backup_type": S,
        "backup_policy": nullable(policy),
        "exclude_disks": strings,
        "workers": nullable(INTEGER),
        "retention_days": nullable(INTEGER),
        "tags": nullable(TAGS),
        "enabled": nullable(B),
        "next_run_at": T,
        "created_at": T,
    }
    put("/schedules", "post", obj(schedule), "201")
    update = {**schedule, "last_run_at": T, "updated_at": T}
    put("/schedules/{schedule_id}", "put", obj(update))
    schedule_detail = obj(
        {**update, "vm_name": nullable(S), "vm_group_name": nullable(S)}
    )
    put("/schedules/{schedule_id}", "get", schedule_detail)
    put("/schedules", "get", page(schedule_detail))
    put("/schedules/{schedule_id}", "delete", message)
    put(
        "/schedules/{schedule_id}/run-now",
        "post",
        obj({"message": S, "schedule_id": S}),
    )
    SHA = {"type": "string", "pattern": "^[0-9a-f]{64}$"}
    revision = {"type": "integer", "minimum": 1, "maximum": 2**63 - 1}
    member = obj(
        {
            **dict.fromkeys(("vm_id", "agent_id", "vm_uid", "namespace"), S),
            "provider": {"type": "string", "enum": ["libvirt", "kubevirt"]},
            "source_sha256": SHA,
        }
    )
    scope_options = obj(
        {
            "backup_type": {
                "type": "string",
                "enum": ["full", "incremental", "automatic"],
            },
            "retention_days": {"type": "integer", "minimum": 1, "maximum": 36500},
            "exclude_disks": strings,
            "workers": nullable({"type": "integer", "minimum": 1, "maximum": 256}),
            "backup_policy": policy,
        },
        required=["backup_type", "retention_days", "exclude_disks", "workers"],
    )
    scope = obj(
        {
            "schema": {"const": 1, "type": "integer"},
            "org_id": S,
            "schedule_id": S,
            "revision": revision,
            "configuration_sha256": SHA,
            "members": {
                "type": "array",
                "items": member,
                "minItems": 1,
                "maxItems": 256,
            },
            "target": obj(
                dict.fromkeys(
                    ("endpoint", "bucket", "region", "prefix", "capability_profile"), S
                )
            ),
            "encryption": obj({"format": S, "key_ref": nullable(S)}),
            "options": scope_options,
        }
    )
    put(
        "/schedules/{schedule_id}/grant",
        "get",
        obj({**authority, "scope": scope, "scope_sha256": SHA, "revision": revision}),
    )
    put(
        "/schedules/{schedule_id}/grant",
        "post",
        obj({**authority, "grant_id": S, "enabled": B}),
    )
    put("/schedules/{schedule_id}/grant", "delete", obj({**authority, "enabled": B}))

    # Reuse already audited report list and execution item schemas without altering them.
    reports_op = paths.get("/api/v1/reports", {}).get("get", {})
    report_list = (
        reports_op.get("responses", {})
        .get("200", {})
        .get("content", {})
        .get("application/json", {})
        .get("schema", {})
    )
    report_item = report_list.get("properties", {}).get("reports", {}).get("items")
    if report_item:
        props = deepcopy(report_item["properties"])
        create = {
            k: v
            for k, v in props.items()
            if k not in ("last_run_at", "next_run_at", "created_by_user")
        }
        put("/reports", "post", obj(create))
        detail = {
            **props,
            "last_execution": nullable(S),
            "updated_at": T,
            "created_by_user": nullable(obj({"id": S, "username": S, "role": S})),
        }
        put("/reports/{report_id}", "get", obj(detail))
        update = {k: v for k, v in create.items() if k != "created_at"}
        put("/reports/{report_id}", "put", obj({**update, "updated_at": T}))
    put("/reports/{report_id}", "delete", message)
    generated = {
        "execution_id": S,
        "report_id": S,
        "status": S,
        "file_path": nullable(S),
        "started_at": T,
        "completed_at": T,
        "file_size_bytes": INTEGER,
        "file_size_mb": N,
        "error": S,
    }
    put(
        "/reports/{report_id}/generate",
        "post",
        obj(
            generated,
            required=[
                "execution_id",
                "report_id",
                "status",
                "file_path",
                "started_at",
                "completed_at",
            ],
        ),
    )
    executions_op = paths.get("/api/v1/reports/{report_id}/executions", {}).get(
        "get", {}
    )
    execution_page = (
        executions_op.get("responses", {})
        .get("200", {})
        .get("content", {})
        .get("application/json", {})
        .get("schema", {})
    )
    execution_item = (
        execution_page.get("properties", {}).get("executions", {}).get("items")
    )
    if execution_item:
        put(
            "/report-executions/{execution_id}",
            "get",
            obj(
                {
                    **deepcopy(execution_item["properties"]),
                    "report_id": S,
                    "report_name": S,
                }
            ),
        )

    legacy_settings = free(
        "Legacy settings are keyed by arbitrary database setting names; values decode"
        " according to each stored value_type.",
        mapping=True,
    )
    put("/settings", "get", obj({"settings": legacy_settings}))
    put("/settings", "put", obj({"message": S, "updated_count": INTEGER}))
    op = paths.get("/api/v1/settings", {}).get("put")
    if op:
        op["requestBody"] = {
            "required": True,
            "content": {"application/json": {"schema": deepcopy(legacy_settings)}},
        }
    put(
        "/settings/{setting_id}",
        "put",
        obj({"message": S, "setting": obj({"id": S, "key": S, "value": nullable(S)})}),
    )
    body("/settings/{setting_id}", "put", {"value": JSON})
    put(
        "/settings/test-s3",
        "post",
        obj({"status": const("ok"), "message": S, "bucket": S, "endpoint": S}),
    )

    storage = obj({"total_bytes": INTEGER, "total_gb": N})
    put(
        "/stats",
        "get",
        obj(
            {
                "vms": obj({"total": INTEGER}),
                "backups": obj(
                    dict.fromkeys(("total", "running", "completed", "failed"), INTEGER)
                ),
                "storage": storage,
            }
        ),
    )
    job = obj(
        {
            "id": S,
            "vm_id": S,
            "vm_name": nullable(S),
            "status": S,
            "backup_type": nullable(S),
            "size_bytes": nullable(INTEGER),
            "progress": nullable(INTEGER),
            "created_at": T,
            "agent_name": nullable(S),
        }
    )
    put(
        "/dashboard/summary",
        "get",
        obj(
            {
                "vms": obj(
                    {
                        "total": INTEGER,
                        "running": INTEGER,
                        "stopped": INTEGER,
                        "by_status": free(
                            "Current VM state strings mapped to counts; null state normalizes"
                            " to unknown.",
                            mapping=True,
                            values=INTEGER,
                        ),
                        "by_agent": arr(
                            obj({"agent_id": S, "name": S, "count": INTEGER})
                        ),
                    }
                ),
                "agents": obj(dict.fromkeys(("total", "online", "offline"), INTEGER)),
                "backups": obj(
                    {
                        **dict.fromkeys(
                            (
                                "total",
                                "last_24h",
                                "completed_24h",
                                "failed_24h",
                                "uploads_pending",
                                "running_count",
                            ),
                            INTEGER,
                        ),
                        "success_rate_24h": nullable(N),
                        "period_start": T,
                        "period_end": T,
                        "by_status": obj(
                            dict.fromkeys(
                                (
                                    "completed",
                                    "running",
                                    "queued",
                                    "failed",
                                    "held",
                                    "other",
                                ),
                                INTEGER,
                            )
                        ),
                    }
                ),
                "storage": storage,
                "schedules": obj({"active": INTEGER, "upcoming": INTEGER}),
                "attention": obj(
                    dict.fromkeys(
                        (
                            "offline_agents",
                            "failed_backups",
                            "held_jobs",
                            "held_backups",
                        ),
                        INTEGER,
                    )
                ),
                "recent_backups": arr(job),
                "running_backups": arr(job),
                "generated_at": T,
            }
        ),
    )
    put(
        "/dashboard/backup-trends",
        "get",
        obj(
            {
                "period_days": INTEGER,
                "data": arr(
                    obj(
                        {
                            "date": {"type": "string", "format": "date"},
                            "completed": INTEGER,
                            "failed": INTEGER,
                            "total": INTEGER,
                        }
                    )
                ),
            }
        ),
    )
    put(
        "/dashboard/storage-usage",
        "get",
        obj(
            {
                "by_agent": arr(
                    obj(
                        {
                            "agent_id": S,
                            "hostname": S,
                            "size_bytes": INTEGER,
                            "size_gb": N,
                            "backup_count": INTEGER,
                        }
                    )
                )
            }
        ),
    )

    _demo_contracts(put, obj, nullable, arr, S, INTEGER, B, T, const)
    _licensing_contracts(put, obj, nullable, arr, S, INTEGER, B, T, const, free)
    return document


def _licensing_contracts(put, obj, nullable, arr, S, INTEGER, B, T, const, free):
    status = obj(
        {
            "schema_version": {"type": "integer", "const": 1},
            "status": S,
            "reason_code": S,
            "notice_required": B,
            "acknowledged": B,
            "can_manage": B,
            "registration_url": S,
            "notice_scope": S,
            "policy": obj({"version": S, "usage_rules_configured": B}),
        }
    )
    actor = obj({"user_id": S, "label": S, "kind": S})
    certificate = obj(
        {
            "product": const("vesta"),
            "license_id": S,
            "customer_id": S,
            "class": {"type": "string", "enum": ["free", "paid"]},
            "issued_at": S,
            "coverage": obj({"modules": arr(S)}),
            "not_before": S,
            "expires_at": S,
            "installation_id": S,
            "policy_version": S,
        },
        required=[
            "product",
            "license_id",
            "customer_id",
            "class",
            "issued_at",
            "coverage",
        ],
    )
    # UTC registration service timestamps include offsets; certificate timestamps
    # are validated by datetime.fromisoformat.
    ack = obj(
        {
            "schema_version": INTEGER,
            "notice_scope": S,
            "actor": actor,
            "acknowledged_at": T,
            "policy_version": S,
        }
    )
    details = obj(
        {
            "status": status,
            "community_usage": nullable(
                obj(
                    {
                        "schedule_version": S,
                        "successful_backups": INTEGER,
                        "inventoried_vms": INTEGER,
                        "registered_agents": INTEGER,
                        "threshold_reached": B,
                    }
                )
            ),
            "certificate": nullable(certificate),
            "installation_id": nullable(S),
            "trust_store": obj(
                {
                    "state": S,
                    "key_ids": arr(S),
                    "fingerprints": free(
                        "Trusted key IDs mapped to SHA-256 public-key fingerprints.",
                        mapping=True,
                        values=S,
                    ),
                }
            ),
            "acknowledgement": nullable(ack),
        }
    )
    put("/licensing/status", "get", status)
    for path, method in (
        ("/licensing", "get"),
        ("/licensing/import", "post"),
        ("/licensing/registration-url", "put"),
    ):
        put(path, method, details)
    put(
        "/licensing/acknowledgement/prepare",
        "post",
        obj(
            {
                "challenge": S,
                "expected_phrase": S,
                "notice_scope": S,
                "expires_at": T,
                "status": status,
            }
        ),
    )
    put("/licensing/acknowledgement/confirm", "post", status)
    put("/licensing/acknowledgement", "delete", status)


def _demo_contracts(put, obj, nullable, arr, S, INTEGER, B, T, const):
    sim = const(True)
    summary = {
        "session_id": S,
        "fixture_version": S,
        "expires_at": T,
        "absolute_expires_at": T,
        "environment": const("demo"),
        "simulated": sim,
    }
    rule = obj({"field": S, "op": S, "value": {"anyOf": [S, arr(S)]}})
    event = obj(
        {
            "status": S,
            "progress": INTEGER,
            "stage": S,
            "message": S,
            "simulated": sim,
            "environment": const("demo"),
        }
    )
    vm = obj(
        {
            "id": S,
            "uuid": S,
            "name": S,
            "agent_id": S,
            "state": S,
            "memory_kb": INTEGER,
            "vcpu_count": INTEGER,
            "disks": arr(
                obj({"target": S, "format": S, "size_bytes": INTEGER, "source": S})
            ),
            "metadata": obj(
                {"environment": S, "supports_incremental": B, "simulated": sim}
            ),
        }
    )
    group_props = {
        "id": S,
        "name": S,
        "group_type": S,
        "rules": arr(rule),
        "rules_match": S,
        "member_count": INTEGER,
        "vm_ids": arr(S),
        "simulated": sim,
    }
    group = obj(group_props, required=["id", "name", "group_type", "simulated"])
    group_mutation = obj({k: v for k, v in group_props.items() if k != "vm_ids"})
    schedule = obj(
        {
            "id": S,
            "name": S,
            "vm_id": nullable(S),
            "vm_group_id": nullable(S),
            "cron_expression": S,
            "retention_days": INTEGER,
            "backup_type": S,
            "enabled": B,
            "simulated": sim,
        },
        required=[
            "id",
            "name",
            "cron_expression",
            "retention_days",
            "backup_type",
            "enabled",
            "simulated",
        ],
    )
    backup_props = {
        "id": S,
        "vm_id": S,
        "vm_name": S,
        "backup_type": S,
        "status": S,
        "progress": INTEGER,
        "parent_backup_id": nullable(S),
        "chain_id": S,
        "chain_position": INTEGER,
        "created_at": T,
        "completed_at": T,
        "error_message": nullable(S),
        "simulated": sim,
        "size_bytes": nullable(INTEGER),
        "storage_path": S,
        "events": arr(event),
    }
    backup = obj(
        backup_props,
        required=[
            k for k in backup_props if k not in ("size_bytes", "storage_path", "events")
        ],
    )
    backup_mutation = obj(
        {
            k: v
            for k, v in backup_props.items()
            if k not in ("size_bytes", "storage_path")
        }
    )
    # Retrying a seeded backup retains size/path, whereas newly-created backups have neither.
    retry_backup = deepcopy(backup)
    retry_backup["required"].append("events")
    restore_props = {
        "id": S,
        "backup_id": S,
        "target_vm_id": S,
        "status": S,
        "progress": INTEGER,
        "created_at": T,
        "completed_at": T,
        "events": arr(event),
        "message": S,
        "simulated": sim,
    }
    restore = obj(
        restore_props,
        required=[k for k in restore_props if k not in ("events", "message")],
    )
    activity = obj(
        {
            "id": S,
            "action": S,
            "resource_type": S,
            "resource_id": S,
            "created_at": T,
            "details": obj(
                {"vm_name": S, "name": S, "simulated": sim}, required=["simulated"]
            ),
            "simulated": sim,
        },
        required=[
            "id",
            "action",
            "resource_type",
            "resource_id",
            "created_at",
            "details",
        ],
    )
    agent = obj(
        {
            "id": S,
            "hostname": S,
            "display_name": S,
            "status": S,
            "provider": S,
            "last_heartbeat": T,
            "capabilities": obj(
                {
                    "incremental": B,
                    "checkpoints": B,
                    "snapshots": B,
                    "backup_method": S,
                },
                required=["incremental", "backup_method"],
            ),
            "health_reasons": obj(
                {
                    "storage_low": INTEGER,
                    "load_high": INTEGER,
                    "libvirt_unavailable": INTEGER,
                }
            ),
            "simulated": sim,
        },
        required=[
            "id",
            "hostname",
            "display_name",
            "status",
            "provider",
            "last_heartbeat",
            "capabilities",
            "simulated",
        ],
    )
    state = obj(
        {
            "fixture_version": S,
            "generated_at": T,
            "environment": const("demo"),
            "simulated": sim,
            "persona": obj({"hands_on": S, "msp_context": S, "msp_message": S}),
            "agents": arr(agent),
            "vms": arr(vm),
            "groups": arr(group),
            "schedules": arr(schedule),
            "backups": arr(backup),
            "restores": arr(restore),
            "activity": arr(activity),
        }
    )
    put("/demo/sessions", "post", obj(summary), "201")
    put("/demo/sessions/current", "get", obj(summary))
    put("/demo/state", "get", state)
    put("/demo/reset", "post", obj({**summary, "state": state}))
    put(
        "/demo/groups/preview",
        "post",
        obj({"items": arr(vm), "total": INTEGER, "simulated": sim}),
    )
    put("/demo/groups", "post", group_mutation, "201")
    put("/demo/groups/{group_id}", "put", group_mutation)
    put("/demo/schedules", "post", schedule, "201")
    put("/demo/backups", "post", backup_mutation, "201")
    put("/demo/schedules/{schedule_id}/run", "post", backup_mutation, "201")
    put("/demo/backups/{backup_id}/retry", "post", retry_backup)
    put("/demo/restores", "post", obj(restore_props), "201")
