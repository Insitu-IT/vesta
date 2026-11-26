"""Deterministic C01 wire examples; no provider or production implementation."""

import copy
import hashlib
import json
from pathlib import Path


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def digest(value):
    return hashlib.sha256(value).hexdigest()


def example(kind):
    base = json.loads(
        (Path(__file__).parent / "fixtures/storage-contract-v1/1-disk.json").read_text()
    )
    value = copy.deepcopy(base)
    request = value["request"]
    plan = request["plan"]
    old_backup = request["backup_id"]
    request["backup_id"] = old_backup[:-1] + ("3" if kind == "incremental" else "4")
    request["reservation_id"] = request["reservation_id"][:-1] + (
        "3" if kind == "incremental" else "4"
    )
    protocol = request["protocol"]
    root = value["completion"]["pointer_key"].removesuffix("chain.json")
    child = root.replace(
        digest(old_backup.encode()), digest(request["backup_id"].encode())
    )
    if kind == "incremental":
        plan["backup_type"] = "incremental"
        plan["parent"] = {
            "backup_id": old_backup,
            "root_backup_id": old_backup,
            "receipt_sha256": base["acceptance"]["receipt_sha256"],
            "generation_id": base["generation"]["generation_id"],
            "tracker_uid": base["checkpoint_proof"]["tracker_uid"],
            "checkpoint": base["checkpoint_proof"]["checkpoint"],
        }
        proof = value["checkpoint_proof"]
        proof.update(
            parent_checkpoint="checkpoint-1",
            checkpoint="checkpoint-3",
            backup_type="Incremental",
            vmb_name="vnbui-" + request["backup_id"],
            vmb_uid="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb3",
        )
    else:
        root = child
        plan["provider"] = "libvirt"
        plan["exclusions"] = []
        plan["source"] = {
            "schema": 1,
            "agent_id": request["agent_id"],
            "vm_id": plan["source"]["vm_id"],
            "vm_uid": plan["source"]["vm_uid"],
            "namespace": "",
            "volumes": [
                {
                    "disk_id": "vda",
                    "serial": "fixture-disk-1",
                    "mapping": {
                        "target_dev": "vda",
                        "device": "disk",
                        "bus": "virtio",
                        "serial": "fixture-disk-1",
                    },
                    "capacity_bytes": 100663296,
                }
            ],
        }
        del value["checkpoint_proof"]
        proof = {
            "protocol": protocol,
            "domain_uuid": plan["source"]["vm_uid"],
            "job_id": "vnbui-backup-" + request["backup_id"],
            "exit_code": 0,
            "inventory_closed": True,
        }
        value["local_completion_proof"] = proof
    bodies = [bytes([3 if kind == "incremental" else 4]) * (4 << 20)]
    manifest = {
        "protocol": protocol,
        "backup_type": plan["backup_type"],
        "volume_id": (
            "vda" if kind == "libvirt" else plan["source"]["volumes"][0]["pvc_uid"]
        ),
        "extents": [
            {
                "offset": 16777216 if kind == "incremental" else 0,
                "length": 4194304,
                "payload_offset": 0,
            }
        ],
        "parent_checkpoint": "checkpoint-1" if kind == "incremental" else None,
    }
    value["artifact_contents"] = {
        "metadata": manifest,
        "payload_recipe": {
            "repeat_byte": 3 if kind == "incremental" else 4,
            "length": 4194304,
        },
    }
    bodies.append(canonical(manifest))
    receipt = value["prepared_receipt"]
    for field in ("backup_id", "reservation_id"):
        receipt[field] = request[field]
    for index, (artifact, obj, body) in enumerate(
        zip(plan["artifacts"], receipt["objects"], bodies)
    ):
        if kind == "libvirt":
            artifact["volume_id"] = "vda"
            if index == 1:
                artifact["role"] = "backup_metadata"
        artifact["key"] = (
            child
            + "payload/"
            + digest(artifact["volume_id"].encode())
            + "/"
            + artifact["role"]
        )
        obj.update({k: artifact[k] for k in ("key", "role", "volume_id")})
        obj.update(
            plaintext_bytes=len(body),
            ciphertext_bytes=len(body),
            plaintext_sha256=digest(body),
            ciphertext_sha256=digest(body),
        )
    if kind == "libvirt":
        inventory = [
            {
                "handle": "local-artifact-" + str(i),
                "volume_id": obj["volume_id"],
                "role": obj["role"],
                "size": obj["plaintext_bytes"],
                "sha256": obj["plaintext_sha256"],
                "device": 1,
                "inode": 100 + i,
                "regular_file": True,
            }
            for i, obj in enumerate(receipt["objects"])
        ]
        plan["local_inventory"] = inventory
        proof["inventory_sha256"] = digest(canonical(inventory))
        value["local_inventory_exchange"] = {
            "method": "POST",
            "path": "/api/v1/agents/backups/"
            + request["backup_id"]
            + "/local-inventory",
            "body": {
                "protocol": protocol,
                "backup_id": request["backup_id"],
                "job_id": proof["job_id"],
                "domain_uuid": proof["domain_uuid"],
                "exit_code": 0,
                "inventory": inventory,
            },
            "response_status": 200,
            "response": {"protocol": protocol, "status": "plan_committed"},
        }
    request["plan_sha256"] = digest(canonical(plan))
    receipt_hash = digest(canonical(receipt))
    acceptance = value["acceptance"]
    acceptance.update(
        reservation_id=request["reservation_id"],
        receipt_sha256=receipt_hash,
        acceptance_id="accepted-" + kind,
    )
    acceptance["verification"] = [
        {**entry, "key": obj["key"]}
        for entry, obj in zip(acceptance["verification"], receipt["objects"])
    ]
    proof.update(
        reservation_id=request["reservation_id"],
        receipt_sha256=receipt_hash,
        acceptance_id=acceptance["acceptance_id"],
    )
    generation = value["generation"]
    generation["generation_id"] = generation["generation_id"][:-1] + (
        "3" if kind == "incremental" else "4"
    )
    generation["root_backup_id"] = (
        old_backup if kind == "incremental" else request["backup_id"]
    )
    generation["predecessor_generation_id"] = (
        base["generation"]["generation_id"] if kind == "incremental" else None
    )
    member = {
        "backup_id": request["backup_id"],
        "receipt": receipt,
        "assurance": acceptance,
        (
            "checkpoint_proof" if kind == "incremental" else "local_completion_proof"
        ): proof,
    }
    generation["members"] = (
        base["generation"]["members"] if kind == "incremental" else []
    ) + [member]
    value["pointer"].update(
        generation_id=generation["generation_id"],
        key=root + "generations/" + generation["generation_id"] + ".json",
        sha256=digest(canonical(generation)),
    )
    value["completion"].update(
        backup_id=request["backup_id"],
        reservation_id=request["reservation_id"],
        receipt_sha256=receipt_hash,
        generation_id=generation["generation_id"],
        pointer_key=root + "chain.json",
        checkpoint=proof.get("checkpoint"),
    )
    value["dispatch_ack"].update(
        reservation_id=request["reservation_id"], plan_sha256=request["plan_sha256"]
    )
    value["checkpoint_ack"]["reservation_id"] = request["reservation_id"]
    if kind == "libvirt":
        value["local_completion_ack"] = value.pop("checkpoint_ack")
        value["local_inventory_exchange"]["response"].update(
            reservation_id=request["reservation_id"], plan_sha256=request["plan_sha256"]
        )
        value["upload_exchange"] = {
            "method": "POST",
            "path": "/api/backups/" + request["backup_id"] + "/upload",
            "body": copy.deepcopy(request),
            "response_status": 202,
            "response": copy.deepcopy(value["dispatch_ack"]),
        }
        value["local_completion_exchange"] = {
            "method": "POST",
            "path": "/api/v1/agents/backups/"
            + request["backup_id"]
            + "/local-completion-proof",
            "body": copy.deepcopy(proof),
            "response_status": 202,
            "response": copy.deepcopy(value["local_completion_ack"]),
        }
    value["initiation_metadata"] = {
        obj["key"]: {
            "vnbui-protocol": "1",
            "vnbui-org-id": request["org_id"],
            "vnbui-backup-id": request["backup_id"],
            "vnbui-reservation-id": request["reservation_id"],
            "vnbui-artifact-id": digest(
                (obj["volume_id"] + ":" + obj["role"]).encode()
            ),
            "vnbui-plan-sha256": request["plan_sha256"],
        }
        for obj in receipt["objects"]
    }
    return value


if __name__ == "__main__":
    import sys

    print(json.dumps(example(sys.argv[1]), indent=2))
