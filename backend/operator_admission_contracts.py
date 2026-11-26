"""Version-one operator admission and reconciliation response descriptions.

Only the affected routes are classified here. This describes admission receipts,
not exactly-once external execution or completed backup/restore operations.
"""

from copy import deepcopy

from operator_contracts import (
    obj,
    nullable,
    STRING,
    INTEGER,
    BOOLEAN,
    TIME,
    STRINGS,
)

ACTIONS = {
    ("/api/v1/backups/{backup_id}/close-unreserved", "post"): "backup.close_unreserved",
    ("/api/v1/backups", "post"): "backup.create",
    ("/api/v1/backups/queue", "post"): "queue.create",
    ("/api/v1/restores", "post"): "restore.create",
    ("/api/v1/backups/bulk-create", "post"): "backup.bulk_create",
    ("/api/v1/orchestrator-keys", "post"): "credential.orchestrator.create",
    ("/api/v1/registration-keys", "post"): "credential.registration.create",
    ("/api/v1/agents/{agent_id}/rotate-key", "post"): "credential.agent.rotate",
    ("/api/v1/encryption/keys", "post"): "encryption.create",
    ("/api/v1/encryption/keys/{key_id}/rotate", "post"): "encryption.rotate",
}
UUID = {"type": "string", "format": "uuid"}
COUNT = {"type": "integer", "minimum": 0}


def array(item, **constraints):
    return {"type": "array", "items": item, **constraints}


def identified(schema):
    value = deepcopy(schema)
    value["properties"]["request_id"] = UUID
    value["required"].append("request_id")
    return value


def credential_variants(metadata, secrets):
    first, replay = identified(metadata), identified(metadata)
    for schema, delivery in ((first, "one_time"), (replay, "unavailable")):
        schema["properties"]["secret_delivery"] = {"type": "string", "const": delivery}
        schema["required"].append("secret_delivery")
    for secret in secrets:
        first["properties"][secret] = {
            "type": "string",
            "writeOnly": True,
            "description": (
                "First response only. Permanently absent from replay and outcome"
                " lookup."
            ),
        }
        first["required"].append(secret)
    return {
        "oneOf": [first, replay],
        "discriminator": {"propertyName": "secret_delivery"},
    }, replay


def catalog():
    """Closed receipt fields with explicitly extensible provider metadata."""
    from operator_restore_contracts import restore_shapes

    targets = restore_shapes()
    pending = identified(
        obj(
            {
                "id": STRING,
                "vm_id": STRING,
                "vm_name": STRING,
                "status": {"type": "string", "const": "pending"},
                "message": STRING,
                "executor": {"type": "string", "enum": ["real", "mock"]},
            }
        )
    )
    queued = identified(
        obj(
            {
                "status": {"type": "string", "const": "queued"},
                "queue_id": STRING,
                "vm_id": STRING,
                "vm_name": STRING,
                "message": STRING,
            }
        )
    )
    backup = {"oneOf": [pending, queued], "discriminator": {"propertyName": "status"}}
    queue = identified(
        obj(
            {
                "id": STRING,
                "vm_id": STRING,
                "vm_name": STRING,
                "position": INTEGER,
                "priority": INTEGER,
                "queued_at": TIME,
                "status": STRING,
                "hold_reason": nullable(STRING),
                "started_backup_id": nullable(STRING),
                "message": STRING,
            }
        )
    )
    restore_base = {
        "id": STRING,
        "backup_id": STRING,
        "status": {"type": "string", "const": "pending"},
        "progress": INTEGER,
        "restore_to_original": BOOLEAN,
        "target_vm_name": nullable(STRING),
        "message": STRING,
    }
    legacy = identified(
        obj({**restore_base, "target_vm_id": nullable(STRING), "created_at": TIME})
    )
    native = identified(
        obj({**restore_base, "native_target": targets["NativeRestoreTarget"]})
    )
    kubevirt = identified(
        obj({**restore_base, "kubevirt_target": targets["KubeVirtRestoreTarget"]})
    )
    restore = {"oneOf": [legacy, native, kubevirt]}
    rejected = obj({"vm_id": STRING, "reason": nullable(STRING)})
    bulk = identified(
        obj(
            {
                "targets": array(STRING, uniqueItems=True, minItems=1, maxItems=200),
                "summary": obj(
                    {key: COUNT for key in ("total", "created", "skipped", "failed")}
                ),
                "details": obj(
                    {
                        "created": array(
                            obj(
                                {
                                    "backup_id": STRING,
                                    "vm_id": STRING,
                                    "vm_name": STRING,
                                }
                            )
                        ),
                        "skipped": array(rejected),
                        "failed": array(rejected),
                    }
                ),
            }
        )
    )
    orchestrator = obj(
        {
            "id": STRING,
            "name": STRING,
            "key_prefix": STRING,
            "expires_at": TIME,
            "created_at": TIME,
            "message": STRING,
        }
    )
    registration = obj(
        {
            **orchestrator["properties"],
            "agent_hostname": nullable(STRING),
            "max_uses": nullable(INTEGER),
        }
    )
    rotation = obj(
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
    orchestrator_response, orchestrator_receipt = credential_variants(
        orchestrator, ("api_key", "usage_snippet")
    )
    registration_response, registration_receipt = credential_variants(
        registration, ("api_key",)
    )
    rotation_response, rotation_receipt = credential_variants(rotation, ("api_key",))
    key = identified(
        obj(
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
    )
    responses = {
        "backup.create": backup,
        "backup.close_unreserved": identified(
            obj(
                {
                    "backup_id": STRING,
                    "status": {"type": "string", "const": "failed"},
                    "reason": {"type": "string", "const": "pre_dispatch_no_effect"},
                    "capacity_state": {"type": "string", "const": "unreserved"},
                }
            )
        ),
        "queue.create": queue,
        "restore.create": restore,
        "backup.bulk_create": bulk,
        "credential.orchestrator.create": orchestrator_response,
        "credential.registration.create": registration_response,
        "credential.agent.rotate": rotation_response,
        "encryption.create": key,
        "encryption.rotate": key,
    }
    receipts = [
        backup,
        queue,
        restore,
        bulk,
        orchestrator_receipt,
        registration_receipt,
        rotation_receipt,
        key,
    ]
    queue_state = obj(
        {
            "id": STRING,
            "vm_id": STRING,
            "status": STRING,
            "hold_reason": nullable(STRING),
            "started_backup_id": nullable(STRING),
            "backup_status": nullable(STRING),
            "position": nullable(INTEGER),
            "priority": INTEGER,
            "queued_at": TIME,
            "started_at": TIME,
        }
    )
    absent = obj(
        {
            "id": nullable(STRING),
            "resource_present": {"type": "boolean", "const": False},
        },
        required=["resource_present"],
    )
    present = {"id": STRING, "resource_present": {"type": "boolean", "const": True}}
    current = {
        "anyOf": [
            absent,
            rotation,
            obj(
                {**present, "enabled": BOOLEAN, "is_valid": BOOLEAN, "expires_at": TIME}
            ),
            obj({**present, "status": STRING, "replaced_by_id": nullable(STRING)}),
            obj(
                {
                    **present,
                    "status": STRING,
                    "hold_reason": nullable(STRING),
                    "started_backup_id": nullable(STRING),
                }
            ),
            {"type": "null"},
        ]
    }
    lookup = obj(
        {
            "request_id": UUID,
            "action": {"type": "string", "enum": sorted(set(ACTIONS.values()))},
            "contract_version": {"type": "integer", "const": 1},
            "state": {"type": "string", "enum": ["admitted", "unresolved"]},
            "created_at": TIME,
            "completed_at": TIME,
            "response_status": nullable(INTEGER),
            "receipt": {"anyOf": receipts + [{"type": "null"}]},
            "secret_delivery": {
                "type": "string",
                "enum": ["unavailable", "not_applicable"],
            },
            "dispatches": array(
                obj(
                    {
                        "kind": {"type": "string", "enum": ["backup", "restore"]},
                        "resource_id": STRING,
                        "state": {
                            "type": "string",
                            "enum": ["pending", "dispatching", "delivered", "held"],
                        },
                        "reason": nullable(STRING),
                        "resource_status": nullable(STRING),
                        "resource_present": BOOLEAN,
                    }
                )
            ),
            "current_resource": current,
            "retention": {"type": "string", "const": "permanent-no-reuse"},
        }
    )
    capabilities = obj(
        {
            "contract_version": {"type": "integer", "const": 1},
            "request_header": {"const": "Idempotency-Key"},
            "request_identity": {"const": "uuid"},
            "caller_identity_required_for_lost_reply_recovery": {"const": True},
            "scope": {"const": "organization-and-original-principal"},
            "actions": array(
                {"type": "string", "enum": sorted(set(ACTIONS.values()))},
                uniqueItems=True,
            ),
            "encryption_admission_provider": {"const": "local"},
            "retention": {"const": "permanent-no-reuse"},
            "secret_replay": {"const": False},
            "max_bulk_targets": {"type": "integer", "const": 200},
            "agent_key_rotation": {"const": "staged-candidate-activation"},
            "polling_contract": {"const": 2},
            "external_effects": {"const": "original-attempt-reconciliation"},
        }
    )
    return responses, queue_state, lookup, capabilities


def error_schema():
    coded = obj(
        {
            "code": STRING,
            "message": STRING,
            "outcome": STRING,
            "max_targets": INTEGER,
            "rotation_id": STRING,
        },
        required=["code"],
        extra=True,
    )
    validation = obj(
        {"loc": array({"anyOf": [STRING, INTEGER]}), "msg": STRING, "type": STRING},
        extra=True,
    )
    return obj({"detail": {"anyOf": [STRING, coded, array(validation)]}})


def apply_admission_contracts(document):
    paths = document.get("paths", {})
    responses, queue_state, lookup, capabilities = catalog()
    components = document.setdefault("components", {}).setdefault("schemas", {})
    components["OperatorAdmissionError"] = error_schema()
    for (path, method), action in ACTIONS.items():
        operation = paths.get(path, {}).get(method)
        if operation is None:
            continue
        operation["x-operator-action"] = action
        operation["x-admission-contract"] = {
            "version": 1,
            "identity_header": "Idempotency-Key",
            "scope": "organization-and-original-principal",
            "retention": "permanent-no-reuse",
            "external_effects": "original-attempt-reconciliation",
            "legacy_header_omission": (
                "Server allocates an identity; lost first responses cannot be "
                "correlated by the caller."
            ),
            "reauthorization": (
                "Current principal, organization and action authority are rechecked on "
                "replay and lookup."
            ),
        }
        parameters = operation.setdefault("parameters", [])
        identity = next(
            (
                p
                for p in parameters
                if p.get("in") == "header"
                and p.get("name", "").lower() == "idempotency-key"
            ),
            None,
        )
        if identity is None:
            identity = {"in": "header", "name": "Idempotency-Key", "required": False}
            parameters.append(identity)
        identity["schema"] = UUID
        identity["description"] = (
            "Caller-supplied UUID identifying this intent permanently. Reuse only "
            "for the same original principal, organization, action and normalized "
            "input. Not HTTP X-Request-ID."
        )
        status = (
            "201"
            if action
            in {
                "restore.create",
                "credential.orchestrator.create",
                "credential.registration.create",
            }
            else "200"
        )
        operation.setdefault("responses", {})[status] = {
            "description": (
                "Durable admission receipt; pending/queued is not proof of external "
                "execution or success. A replay returns the original nonsecret receipt."
            ),
            "content": {"application/json": {"schema": deepcopy(responses[action])}},
            "headers": {
                "Idempotency-Key": {"schema": UUID},
                "Idempotency-Replayed": {
                    "schema": {"type": "string", "enum": ["true", "false"]}
                },
                "Cache-Control": {"schema": {"const": "no-store"}},
                "X-Request-ID": {
                    "schema": STRING,
                    "description": (
                        "Per-HTTP-request correlation, separate from durable admission"
                        " identity."
                    ),
                },
            },
        }
        for code, description in (
            ("400", "Invalid domain request."),
            ("401", "Authentication unavailable."),
            ("403", "Current action authority unavailable."),
            ("404", "Authorized resource unavailable."),
            (
                "409",
                (
                    "Identity conflict, unresolved/retired outcome, pending agent"
                    " rotation, stale KEK predecessor or unsupported provider contract."
                ),
            ),
            ("413", "Normalized intent exceeds admission limit."),
            ("422", "Malformed identity, request validation or bulk target limit."),
            ("423", "Existing source or operation custody prevents admission."),
            ("503", "Admission dependency unavailable."),
        ):
            operation["responses"][code] = {
                "description": description,
                "content": {
                    "application/json": {
                        "schema": {
                            "$ref": "#/components/schemas/OperatorAdmissionError"
                        }
                    }
                },
            }
        operation["responses"]["500"] = {
            "description": (
                "Outcome may be unknown after a lost/failing commit response. Reconcile"
                " the same request identity."
            ),
            "content": {
                "application/json": {
                    "schema": {"$ref": "#/components/schemas/OperatorAdmissionError"}
                },
                "text/plain": {"schema": STRING},
            },
        }
    for path, schema in (
        ("/api/v1/backups/queue/{queue_id}", queue_state),
        ("/api/v1/operator/requests/{request_id}", lookup),
        ("/api/v1/operator/capabilities", capabilities),
    ):
        operation = paths.get(path, {}).get("get")
        if operation is None:
            continue
        operation.setdefault("responses", {})["200"] = {
            "description": (
                "Authorized current state; the immutable receipt remains separate from "
                "current dispatch/resource state."
            ),
            "content": {"application/json": {"schema": schema}},
        }
        for code in ("401", "403", "404"):
            operation["responses"][code] = {
                "description": (
                    "Unavailable authority/resource. Lookup 404 means unknown at "
                    "observation time, not permission to submit another identity."
                ),
                "content": {
                    "application/json": {
                        "schema": {
                            "$ref": "#/components/schemas/OperatorAdmissionError"
                        }
                    }
                },
            }
    for path, methods in paths.items():
        if "/key-rotations" not in path:
            continue
        for method, operation in methods.items():
            if method not in {"get", "post", "delete"}:
                continue
            for status in ("401", "403", "404", "409", "410", "422", "500"):
                operation.setdefault("responses", {}).setdefault(
                    status,
                    {
                        "description": (
                            "Candidate or current administrator authority, lifecycle"
                            " state or validated input unavailable. A refused candidate"
                            " does not replace the active key."
                        ),
                        "content": {
                            "application/json": {
                                "schema": {
                                    "$ref": (
                                        "#/components/schemas/OperatorAdmissionError"
                                    )
                                }
                            }
                        },
                    },
                )
    document["x-operator-first-support"] = {"version": "6.1.0"}
    return document
