"""Closed restore mappings/results and the saved automatic-backup decision."""

from copy import deepcopy


def restore_shapes():
    from operator_contracts import obj

    string = {"type": "string"}
    dns = {
        "type": "string",
        "minLength": 1,
        "maxLength": 63,
        "pattern": "^[a-z0-9](?:[-a-z0-9]*[a-z0-9])?$",
    }
    native_name = {"type": "string", "pattern": "^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$"}

    def array(item, maximum, minimum=0):
        return {
            "type": "array",
            "items": item,
            "minItems": minimum,
            "maxItems": maximum,
        }

    disk = obj(
        {
            "volume_name": string,
            "pvc_name": dns,
            "storage_class": dns,
            "access_mode": {"enum": ["ReadWriteOnce", "ReadWriteMany"]},
            "volume_mode": {"enum": ["Filesystem", "Block"]},
            "capacity_bytes": {"type": "integer", "minimum": 1},
        }
    )
    network = {
        "oneOf": [
            obj({"name": dns, "type": {"const": "pod"}, "network_name": {"const": ""}}),
            obj({"name": dns, "type": {"const": "multus"}, "network_name": dns}),
        ]
    }
    kubevirt = obj(
        {
            "namespace": dns,
            "vm_name": dns,
            "disks": array(disk, 32, 1),
            "networks": array(network, 32),
            "dependencies": {
                "type": "object",
                "additionalProperties": dns,
                "propertyNames": {
                    "pattern": "^(secret|configMap)/[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?$"
                },
            },
        }
    )
    kubevirt["description"] = (
        "Fresh stopped target mapping for every protected source.volumes disk. "
        "Schema-2 known unprotected native participants are omitted from the new "
        "VM's volumes and disk devices after exact captured-identity validation. "
        "Unknown/duplicate/missing identities refuse work; schema 1 retains its "
        "unprotected-persistent-disk guard. Runtime checks fresh names against all "
        "native source PVCs, disk capacity and at most one pod network. Excluding "
        "boot/application dependencies does not promise guest or application recovery."
    )
    native = obj(
        {
            "vm_name": native_name,
            "disks": array(string, 128, 1),
            "drop_excluded_disks": array(string, 128),
            "networks": array(
                obj(
                    {
                        "source_mac": {
                            "type": "string",
                            "pattern": "^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$",
                        },
                        "network": native_name,
                    }
                ),
                128,
            ),
        }
    )
    native["description"] = (
        "Fresh native target input. Runtime binds all protected and excluded disks to"
        " the accepted manifest and rejects source-name reuse and duplicate source"
        " MACs."
    )
    native_saved = deepcopy(native)
    native_saved["properties"]["vm_uuid"] = {"type": "string", "format": "uuid"}
    native_saved["required"].append("vm_uuid")
    native_saved["description"] = (
        "Accepted native target with its server-allocated fresh VM UUID."
    )
    kubevirt_result = obj(
        {
            **{
                key: {"type": "string", "minLength": 1}
                for key in (
                    "namespace",
                    "vm_name",
                    "vm_uid",
                    "job_uid",
                    "job_name",
                    "plan_sha256",
                )
            },
            "run_strategy": {"const": "Halted"},
            "pvc_uids": {
                "type": "object",
                "minProperties": 1,
                "additionalProperties": {"type": "string", "minLength": 1},
            },
        }
    )
    native_result = obj(
        {
            "vm_name": string,
            "vm_uuid": {"type": "string", "format": "uuid"},
            "state": {"const": "shutoff"},
            "plan_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "disks": array(
                obj(
                    {
                        "target": string,
                        "path": {"type": "string", "pattern": "^/"},
                        "size_bytes": {"type": "integer", "minimum": 1},
                        "sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
                    }
                ),
                128,
                1,
            ),
        }
    )
    return {
        "KubeVirtRestoreTarget": kubevirt,
        "NativeRestoreInput": native,
        "NativeRestoreTarget": native_saved,
        "KubeVirtRestoreResult": kubevirt_result,
        "NativeRestoreResult": native_result,
    }


def scheduler_decision():
    from operator_contracts import obj

    date = {"type": "string", "format": "date"}
    identifier = {
        "type": "string",
        "pattern": "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    }
    base = {
        "schema": {"type": "integer", "const": 1},
        "policy": obj(
            {
                "schema": {"type": "integer", "const": 1},
                "full_every_days": {"type": "integer", "minimum": 1, "maximum": 36500},
                "max_incrementals": {"type": "integer", "minimum": 1, "maximum": 255},
            }
        ),
        "observed_date": date,
    }
    parent = {
        "generation_id": identifier,
        "root_backup_id": identifier,
        "root_date": date,
        "incremental_count": {"type": "integer", "minimum": 0},
    }
    return {
        "oneOf": [
            obj(
                {
                    **base,
                    **{key: {"type": "null"} for key in parent},
                    "backup_type": {"const": "full"},
                    "reason": {
                        "enum": [
                            "parent_unavailable",
                            "new_grant",
                            "source_changed",
                            "root_time_unavailable",
                            "previous_failure",
                        ]
                    },
                }
            ),
            obj(
                {
                    **base,
                    **parent,
                    "backup_type": {"const": "full"},
                    "reason": {"enum": ["max_incrementals", "full_interval"]},
                }
            ),
            obj(
                {
                    **base,
                    **parent,
                    "backup_type": {"const": "incremental"},
                    "reason": {"const": "within_policy"},
                }
            ),
        ],
        "description": (
            "Saved nine-field automatic-policy decision. Runtime also validates"
            " calendar chronology and recomputes the type/reason against the sealed"
            " policy; reading it grants no execution authority."
        ),
    }
