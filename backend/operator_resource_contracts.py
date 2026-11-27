"""Descriptions of backup, restore, verification and administrative wire values.

These schemas follow the serializers. They do not add response filtering, retries
or execution authority. Protocol receipts remain separate from resource status.
"""

from copy import deepcopy

from operator_contracts import (
    BOOLEAN,
    INTEGER,
    METADATA,
    STRING,
    STRINGS,
    TIME,
    nullable,
    obj,
)


def array(item):
    return {"type": "array", "items": item}


def ref(name):
    return {"$ref": "#/components/schemas/" + name}


def apply_resource_contracts(document):
    paths = document.get("paths", {})
    components = document.setdefault("components", {}).setdefault("schemas", {})

    def publish(path, method, schema, *, status=200, source):
        operation = paths.get(path, {}).get(method)
        if operation is None:
            return
        operation.setdefault("responses", {})[str(status)] = {
            "description": (
                "Successful response; resource state is separate from HTTP acceptance."
            ),
            "content": {"application/json": {"schema": deepcopy(schema)}},
        }
        operation["x-response-source"] = source

    def error(path, method, status, detail, description):
        operation = paths.get(path, {}).get(method)
        if operation is not None:
            operation.setdefault("responses", {})[str(status)] = {
                "description": description,
                "content": {"application/json": {"schema": obj({"detail": detail})}},
            }

    message = obj({"message": STRING})
    bundle_members = {
        "request": ref("ProtocolKubeVirtTransaction"),
        "receipt": ref("ProtocolKubeVirtStorageReceipt"),
    }
    components["AcceptedRestoreBundle"] = {
        "oneOf": [
            obj(
                {
                    "schema": {"const": "vnbui-kubevirt-restore/1"},
                    "members": {
                        "type": "array",
                        "minItems": 1,
                        "maxItems": 256,
                        "items": obj(bundle_members),
                    },
                }
            ),
            obj(
                {
                    "schema": {"const": "vnbui-native-restore/1"},
                    "members": {
                        "type": "array",
                        "minItems": 1,
                        "maxItems": 256,
                        "items": obj(
                            {
                                "request": ref("ProtocolNativeTransaction"),
                                "receipt": ref("ProtocolNativeStorageReceipt"),
                                "push_result": ref("ProtocolNativePushResult"),
                            }
                        ),
                    },
                }
            ),
        ],
        "description": (
            "Accepted root-to-selected ancestry. Each member's original plan and"
            " exact-object receipt remain bound; presence is not restore execution"
            " evidence."
        ),
    }
    publish(
        "/api/v1/backups/{backup_id}/restore-bundle",
        "get",
        ref("AcceptedRestoreBundle"),
        source="core/storage_restore.py:build_restore_bundle;core/native_restore_bundle.py:build_native_bundle",
    )
    for path, source in (
        ("/api/v1/backups/queue/{queue_id}", "routers/queue.py:cancel_queued_backup"),
        (
            "/api/v1/orchestrator-keys/{key_id}",
            "routers/api_keys.py:delete_orchestrator_key",
        ),
        (
            "/api/v1/registration-keys/{key_id}",
            "routers/api_keys.py:delete_registration_key",
        ),
        ("/api/v1/users/{user_id}", "routers/users.py:delete_user"),
    ):
        publish(path, "delete", message, source=source)
    publish(
        "/api/v1/backups/{backup_id}",
        "delete",
        obj(
            {
                "message": STRING,
                "deleted_id": STRING,
                "deleted_bytes": INTEGER,
            }
        ),
        source="routers/backups.py:delete_backup",
    )
    publish(
        "/api/v1/backups/cleanup",
        "post",
        obj(
            {
                "deleted_count": INTEGER,
                "deleted_bytes": INTEGER,
                "deleted_gb": {"type": "number"},
                "dry_run": BOOLEAN,
            }
        ),
        source="routers/backups.py:cleanup_expired_backups",
    )

    retry = paths.get("/api/v1/backups/{backup_id}/retry-upload", {}).get("post")
    if retry is not None:
        # The handler always refuses; an invented 200 would invite unsafe retry.
        retry["responses"] = {
            k: v for k, v in retry.get("responses", {}).items() if not k.startswith("2")
        }
        retry["x-no-success-response"] = (
            "Always returns a hold/refusal; never grants upload dispatch authority."
        )
        retry["x-response-source"] = "routers/backups.py:retry_upload"
        error(
            "/api/v1/backups/{backup_id}/retry-upload",
            "post",
            423,
            obj({"status": {"const": "held"}, "reason": STRING}),
            "Original custody retained; no upload is dispatched.",
        )
    publish(
        "/api/v1/backups/{backup_id}/resume",
        "post",
        obj(
            {
                "status": {"const": "accepted"},
                "backup_id": STRING,
                "resumed": {"const": True},
                "attempt_id": STRING,
            }
        ),
        status=202,
        source="core/backup_recovery.py:_deliver_original",
    )
    publish(
        "/api/v1/backups/{backup_id}/resume",
        "post",
        obj(
            {
                "status": {"const": "completed"},
                "backup_id": STRING,
                "resumed": {"const": False},
            }
        ),
        source="core/backup_recovery.py:_resume_backup_attempt_worker",
    )
    error(
        "/api/v1/backups/{backup_id}/resume",
        "post",
        423,
        obj(
            {
                "status": {"const": "held"},
                "backup_id": STRING,
                "reason": STRING,
                "capacity_retained": {"const": True},
            }
        ),
        "Original attempt remains held; this response does not authorize replacement or"
        " release.",
    )

    failed = obj({"backup_id": STRING, "reason": STRING})
    for name, details in (
        (
            "delete",
            {
                "deleted": array(
                    obj(
                        {
                            "backup_id": STRING,
                            "vm_name": STRING,
                            "deleted_bytes": INTEGER,
                        }
                    )
                ),
                "skipped": array(
                    obj({"backup_id": STRING, "vm_name": STRING, "reason": STRING})
                ),
                "failed": array(failed),
            },
        ),
        (
            "tag",
            {
                "updated": array(
                    obj(
                        {
                            "backup_id": STRING,
                            "vm_name": STRING,
                            "old_tags": METADATA,
                            "new_tags": METADATA,
                        }
                    )
                ),
                "failed": array(failed),
            },
        ),
    ):
        publish(
            "/api/v1/backups/bulk-" + name,
            "post",
            obj(
                {
                    "summary": obj(
                        {"total": INTEGER, **{key: INTEGER for key in details}}
                    ),
                    "details": obj(details),
                }
            ),
            source="routers/bulk.py:bulk_" + name + "_backups",
        )

    publish(
        "/api/v1/restores/{restore_id}/resume",
        "post",
        obj(
            {
                "id": STRING,
                "status": {"enum": ["pending", "dispatching", "running"]},
                "message": STRING,
            }
        ),
        status=202,
        source="routers/restores.py:resume_kubevirt_restore",
    )
    publish(
        "/api/v1/restores/{restore_id}/cancel",
        "patch",
        obj(
            {
                "message": STRING,
                "restore_id": STRING,
                "status": {"const": "cancelled"},
            }
        ),
        source="routers/restores.py:cancel_restore",
    )
    for path in (
        "/api/v1/restores/{restore_id}/resume",
        "/api/v1/restores/{restore_id}/cancel",
    ):
        for operation in paths.get(path, {}).values():
            operation["x-required-roles"] = ["admin", "operator"]
    resume = paths.get("/api/v1/restores/{restore_id}/resume", {}).get("post")
    if resume is not None:
        resume["x-additional-authorization"] = (
            "Caller must be the original enrolled restore principal."
        )

    evidence = {
        "status": STRING,
        "recorded_status": STRING,
        "created_by": nullable(STRING),
        "read_attempts": nullable(INTEGER),
        "read_limit": nullable(INTEGER),
        "cancel_requested": BOOLEAN,
        "result_message": nullable(STRING),
    }
    verification = {
        "id": STRING,
        **evidence,
        "verification_type": STRING,
        "started_at": TIME,
        "completed_at": TIME,
        "created_at": TIME,
    }
    admission = obj(
        {"id": STRING, "backup_id": STRING, "verification_type": STRING, **evidence},
        required=["id", "backup_id", *evidence],
    )
    publish(
        "/api/v1/backups/{backup_id}/verify",
        "post",
        admission,
        status=202,
        source="routers/verification.py:verify_backup",
    )
    publish(
        "/api/v1/backups/{backup_id}/verifications",
        "get",
        array(obj(verification)),
        source="routers/verification.py:list_backup_verifications",
    )
    publish(
        "/api/v1/verifications",
        "get",
        obj(
            {
                "items": array(obj({**verification, "backup_id": STRING})),
                "total": INTEGER,
                "skip": INTEGER,
                "limit": INTEGER,
            }
        ),
        source="routers/verification.py:list_all_verifications",
    )
    components["VerificationResult"] = obj(
        {
            "schema": {"const": "vnbui-chain-verification/1"},
            "provider": STRING,
            "org_id": STRING,
            "agent_id": STRING,
            "vm_id": STRING,
            "members": array(
                obj(
                    {
                        "backup_id": STRING,
                        "reservation_id": STRING,
                        "plan_sha256": STRING,
                        "receipt_sha256": STRING,
                        "objects": INTEGER,
                    }
                )
            ),
        }
    )
    publish(
        "/api/v1/verifications/{verification_id}",
        "get",
        obj(
            {
                **verification,
                "backup_id": STRING,
                "result": nullable(
                    {
                        "anyOf": [
                            ref("VerificationResult"),
                            {
                                **METADATA,
                                "x-open-schema-reason": (
                                    "Historical verification rows predate receipt-bound"
                                    " results; recorded JSON is returned without normalization"
                                    " and is not accepted evidence."
                                ),
                            },
                        ]
                    }
                ),
                "backup": nullable(
                    obj(
                        {
                            "id": STRING,
                            "vm_id": STRING,
                            "vm_name": STRING,
                            "status": STRING,
                            "size_bytes": nullable(INTEGER),
                            "created_at": TIME,
                        }
                    )
                ),
                "created_by_user": nullable(
                    obj({"id": STRING, "username": STRING, "role": STRING})
                ),
            }
        ),
        source="routers/verification.py:get_verification",
    )

    # The list and detail handlers use the same _key_to_response serializer.
    key_list = paths.get("/api/v1/encryption/keys", {}).get("get", {})
    try:
        key = deepcopy(
            key_list["responses"]["200"]["content"]["application/json"]["schema"][
                "properties"
            ]["items"]["items"]
        )
    except KeyError:
        key = None
    if key is not None:
        components["EncryptionKeyMetadata"] = key
        publish(
            "/api/v1/encryption/keys/{key_id}",
            "get",
            ref("EncryptionKeyMetadata"),
            source="routers/encryption.py:_key_to_response",
        )
        publish(
            "/api/v1/encryption/provider",
            "get",
            obj(
                {
                    "provider": {"const": "local"},
                    "supports_export": BOOLEAN,
                    "active_key": nullable(ref("EncryptionKeyMetadata")),
                    "total_keys": INTEGER,
                    "keys_not_backed_up": INTEGER,
                    "error": STRING,
                },
                required=[
                    "provider",
                    "supports_export",
                    "active_key",
                    "total_keys",
                    "keys_not_backed_up",
                ],
            ),
            source="routers/encryption.py:get_provider_info",
        )
    publish(
        "/api/v1/encryption/keys/{key_id}/revoke",
        "post",
        obj(
            {
                "status": {"const": "revoked"},
                "key_id": STRING,
            }
        ),
        source="routers/encryption.py:revoke_key",
    )
    publish(
        "/api/v1/encryption/keys/import",
        "post",
        obj(
            {
                "imported_key_ids": STRINGS,
                "count": INTEGER,
                "recovery_trust": obj(
                    {
                        "schema": {"const": "vesta-recovery-trust/1"},
                        "installation_id": STRING,
                        "org_id": STRING,
                        "public_key": {
                            "type": "string",
                            "pattern": "^[A-Za-z0-9_-]{43}$",
                        },
                        "key_id": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
                    }
                ),
            },
            required=["imported_key_ids", "count"],
        ),
        source="routers/encryption.py:import_keys",
    )
    publish(
        "/api/v1/encryption/keys/confirm-export",
        "post",
        obj(
            {
                "key_ids": STRINGS,
                "sha256": STRING,
                "location": STRING,
            }
        ),
        source="routers/encryption.py:confirm_export_custody",
    )

    for path, methods in paths.items():
        if path.startswith(("/api/v1/encryption/", "/api/v1/s3/")):
            for method, operation in methods.items():
                if method in {"get", "post", "put", "patch", "delete"}:
                    operation["x-required-roles"] = ["admin"]

    for kind in ("orchestrator", "registration"):
        properties = {
            "id": STRING,
            "name": STRING,
            "key_prefix": STRING,
            "expires_at": TIME,
            "enabled": BOOLEAN,
            "is_valid": BOOLEAN,
            "message": STRING,
        }
        if kind == "registration":
            properties.update(max_uses=nullable(INTEGER), use_count=INTEGER)
        publish(
            f"/api/v1/{kind}-keys/{{key_id}}",
            "patch",
            obj(properties),
            source=f"routers/api_keys.py:update_{kind}_key",
        )

    user = {
        "id": STRING,
        "username": STRING,
        "role": STRING,
        "is_active": BOOLEAN,
        "created_at": TIME,
        **{
            key: nullable(STRING)
            for key in (
                "full_name",
                "email",
                "auth_source",
                "role_source",
                "oidc_subject",
                "oidc_issuer",
            )
        },
    }
    publish(
        "/api/v1/users",
        "post",
        obj({key: user[key] for key in ("id", "username", "role", "created_at")}),
        status=201,
        source="routers/users.py:create_user",
    )
    publish(
        "/api/v1/users/{user_id}",
        "get",
        obj({**user, "last_login": TIME}),
        source="routers/users.py:get_user",
    )
    publish(
        "/api/v1/users/{user_id}",
        "put",
        obj(user),
        source="routers/users.py:update_user",
    )
