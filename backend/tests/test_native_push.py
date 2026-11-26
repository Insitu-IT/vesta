"""Current native push manifest/receipt/parent bindings; no provider effects."""

from copy import deepcopy
import json
from pathlib import Path

import pytest

from core.native_inventory import digest
from core.native_manifest import (
    bind_inventory,
    validate_receipt_binding,
)
from core.native_storage_wire import NativeTransactionRequest
from core.s3_ownership import StorageOwnershipError
from core.storage_receipt_v2 import canonical
from core.storage_wire import plan_digest

ROOT = Path(__file__).resolve().parents[2]


def specimen():
    sample = json.loads(
        (ROOT / "agent/contracts/native_storage_examples.json").read_text()
    )[0]
    request, receipt = sample["request"], sample["receipt"]
    inventory = request["plan"]["source"]["inventory"]
    source_disks = [
        dict(
            target=d["target"],
            source="/vm/" + d["target"] + ".qcow2",
            bus=d["bus"],
            format="qcow2",
        )
        for d in sorted(inventory["disks"], key=lambda d: d["target"])
    ]
    payloads = {
        f["disk_id"]: f for f in inventory["files"] if f["role"] == "disk_payload"
    }
    manifest = dict(
        schema="libvirt-push-qcow2/1",
        backup_id=inventory["backup_id"],
        attempt_id=inventory["attempt_id"],
        domain_uuid=inventory["domain_uuid"],
        checkpoint=inventory["checkpoint"],
        checkpoint_sha256="c" * 64,
        parent_backup_id=None,
        parent_manifest_sha256=None,
        source=source_disks,
        exclusions=[],
        domain_xml_sha256="d" * 64,
        disks=[
            dict(
                target=d["target"],
                file=d["target"] + ".qcow2",
                size_bytes=max(1, payloads[d["id"]]["size"]),
                virtual_size=8388608,
                sha256="a" * 64,
            )
            for d in sorted(inventory["disks"], key=lambda d: d["target"])
        ],
    )
    result = dict(manifest=manifest, manifest_sha256=digest(manifest))
    names = {
        "domain_config": "domain.xml",
        "checkpoint": "checkpoint.xml",
        "backup_metadata": "manifest.json",
    }
    disk_files = {d["target"]: d for d in manifest["disks"]}
    for file in inventory["files"]:
        if file["role"] == "autostart":
            file["role"] = "backup_metadata"
        if file["role"] == "disk_payload":
            # Fixture IDs are source-bound targets in this producer.
            disk = next(d for d in inventory["disks"] if d["id"] == file["disk_id"])
            file["disk_id"] = disk["target"]
            file["path"] = disk_files[disk["target"]]["file"]
            file["size"] = disk_files[disk["target"]]["size_bytes"]
        else:
            file["path"] = names[file["role"]]
        if file["role"] == "backup_metadata":
            file["size"] = len(canonical(manifest))
    for disk in inventory["disks"]:
        disk["id"] = disk["target"]
    inventory["disks"].sort(key=lambda d: d["target"])
    hashes = {
        "domain_config": manifest["domain_xml_sha256"],
        "checkpoint": manifest["checkpoint_sha256"],
        "backup_metadata": result["manifest_sha256"],
        "disk_payload": "a" * 64,
    }
    receipt["objects"] = [
        dict(
            artifact_id=f["artifact_id"],
            role=f["role"],
            disk_id=f["disk_id"],
            plaintext_sha256=hashes[f["role"]],
            plaintext_bytes=f["size"],
        )
        for f in inventory["files"]
    ]
    saved = dict(
        inventory=inventory,
        inventory_sha256=digest(inventory),
        push_result=result,
        push_manifest_canonical=canonical(manifest).decode(),
    )
    request["plan"]["source"]["inventory_sha256"] = saved["inventory_sha256"]
    intent = dict(
        producer=manifest["schema"],
        backup_id=manifest["backup_id"],
        attempt_id=manifest["attempt_id"],
        checkpoint=manifest["checkpoint"],
        push_parent=None,
        source=dict(
            domain_uuid=manifest["domain_uuid"],
            disks=source_disks,
            exclusions=[],
            backup_type="full",
        ),
    )
    return request, receipt, saved, intent


def test_manifest_and_uploaded_plaintext_bind_to_same_native_result():
    request, receipt, saved, intent = specimen()
    assert (
        bind_inventory(saved["push_result"], saved["inventory"], intent)
        == saved["push_result"]
    )
    assert validate_receipt_binding(request, receipt, saved) == saved["push_result"]


@pytest.mark.parametrize(
    "fault",
    [
        "metadata_hash",
        "disk_hash",
        "length",
        "extra",
        "foreign_role",
        "foreign_artifact",
    ],
)
def test_native_publication_refuses_content_or_membership_drift(fault):
    request, receipt, saved, _ = specimen()
    obj = next(o for o in receipt["objects"] if o["role"] == "backup_metadata")
    if fault == "metadata_hash":
        obj["plaintext_sha256"] = "e" * 64
    elif fault == "disk_hash":
        next(o for o in receipt["objects"] if o["role"] == "disk_payload")[
            "plaintext_sha256"
        ] = ("e" * 64)
    elif fault == "length":
        obj["plaintext_bytes"] += 1
    elif fault == "extra":
        receipt["objects"].append(deepcopy(obj))
    elif fault == "foreign_role":
        obj["role"] = "unrelated"
    else:
        obj["artifact_id"] = "f" * 64
    with pytest.raises(StorageOwnershipError):
        validate_receipt_binding(request, receipt, saved)


@pytest.mark.parametrize(
    "fault", ["checkpoint", "parent", "source", "file", "size", "legacy"]
)
def test_manifest_never_substitutes_attempt_parent_or_legacy_format(fault):
    _, _, saved, intent = specimen()
    result = saved["push_result"]
    manifest = result["manifest"]
    if fault == "checkpoint":
        manifest["checkpoint"] = "vnbui-other-attempt"
    elif fault == "parent":
        manifest["parent_backup_id"] = "99999999-9999-4999-8999-999999999999"
        manifest["parent_manifest_sha256"] = "a" * 64
    elif fault == "source":
        manifest["source"] = deepcopy(manifest["source"])
        manifest["source"][0]["source"] = "/foreign/source.qcow2"
    elif fault == "file":
        manifest["disks"][0]["file"] = "../foreign.qcow2"
    elif fault == "size":
        manifest["disks"][0]["size_bytes"] = True
    else:
        manifest["schema"] = "virtnbdbackup"
    result["manifest_sha256"] = digest(manifest)
    with pytest.raises(StorageOwnershipError):
        bind_inventory(result, saved["inventory"], intent)


def test_native_incremental_wire_accepts_only_explicit_matching_parent():
    sample = json.loads(
        (ROOT / "agent/contracts/native_storage_examples.json").read_text()
    )[0]["request"]
    sample["plan"]["backup_type"] = "incremental"
    sample["plan"]["parent"] = dict(
        backup_id="99999999-9999-4999-8999-999999999999",
        root_backup_id="99999999-9999-4999-8999-999999999999",
        generation_id="88888888-8888-4888-8888-888888888888",
        receipt_sha256="a" * 64,
        tracker_uid=sample["plan"]["source"]["inventory"]["domain_uuid"],
        checkpoint="vnbui-77777777-7777-4777-8777-777777777777",
    )
    sample["plan_sha256"] = plan_digest(sample["plan"])
    assert (
        NativeTransactionRequest.model_validate(sample).plan.backup_type
        == "incremental"
    )
    for change in (
        "full_with_parent",
        "missing_parent",
        "foreign_domain",
        "old_checkpoint",
    ):
        wrong = deepcopy(sample)
        if change == "full_with_parent":
            wrong["plan"]["backup_type"] = "full"
        elif change == "missing_parent":
            wrong["plan"]["parent"] = None
        elif change == "foreign_domain":
            wrong["plan"]["parent"][
                "tracker_uid"
            ] = "99999999-9999-4999-8999-999999999999"
        else:
            wrong["plan"]["source"]["inventory"]["checkpoint"] = "virtnbdbackup.0"
        wrong["plan_sha256"] = plan_digest(wrong["plan"])
        with pytest.raises((ValueError, StorageOwnershipError)):
            NativeTransactionRequest.model_validate(wrong)
