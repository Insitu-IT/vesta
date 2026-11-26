"""Current libvirt push format and the binding from closed files to S3 receipts.

The generic native file-set container is reused. Its backup_metadata artifact is
the push manifest, not an old virtnbdbackup checkpoint/config interpretation.
"""

import re

from core.native_inventory import digest, exact, refuse
from core.storage_receipt_v2 import canonical
from core.storage_semantics import UUID

FORMAT = "libvirt-push-qcow2/1"
HASH = re.compile(r"[0-9a-f]{64}\Z")
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
MANIFEST_FIELDS = {
    "schema",
    "backup_id",
    "attempt_id",
    "domain_uuid",
    "checkpoint",
    "checkpoint_sha256",
    "parent_backup_id",
    "parent_manifest_sha256",
    "source",
    "exclusions",
    "domain_xml_sha256",
    "disks",
}


def _hash(value):
    return type(value) is str and HASH.fullmatch(value) is not None


def validate_result(value):
    exact(value, {"manifest", "manifest_sha256"})
    manifest = value["manifest"]
    exact(manifest, MANIFEST_FIELDS)
    if manifest["schema"] != FORMAT or value["manifest_sha256"] != digest(manifest):
        refuse()
    for name in ("backup_id", "attempt_id", "domain_uuid"):
        if type(manifest[name]) is not str or not UUID.fullmatch(manifest[name]):
            refuse()
    if (
        manifest["checkpoint"] != "vnbui-" + manifest["attempt_id"]
        or not _hash(manifest["checkpoint_sha256"])
        or not _hash(manifest["domain_xml_sha256"])
    ):
        refuse()
    parent = manifest["parent_backup_id"]
    if parent is None:
        if manifest["parent_manifest_sha256"] is not None:
            refuse()
    elif (
        type(parent) is not str
        or not UUID.fullmatch(parent)
        or parent == manifest["backup_id"]
        or not _hash(manifest["parent_manifest_sha256"])
    ):
        refuse()
    source, exclusions, disks = (
        manifest["source"],
        manifest["exclusions"],
        manifest["disks"],
    )
    if type(source) is not list or not 0 < len(source) <= 128:
        refuse()
    targets = []
    for disk in source:
        exact(disk, {"target", "source", "bus", "format"})
        if (
            any(type(v) is not str or not 0 < len(v) <= 4096 for v in disk.values())
            or not NAME.fullmatch(disk["target"])
            or not NAME.fullmatch(disk["bus"])
            or not disk["source"].startswith("/")
            or disk["format"] not in {"qcow2", "raw"}
        ):
            refuse()
        targets.append(disk["target"])
    if targets != sorted(set(targets)):
        refuse()
    if (
        type(exclusions) is not list
        or any(type(x) is not str for x in exclusions)
        or exclusions != sorted(set(exclusions))
        or not set(exclusions) < set(targets)
        or type(disks) is not list
        or len(disks) != len(targets) - len(exclusions)
    ):
        refuse()
    selected = [target for target in targets if target not in exclusions]
    for disk, target in zip(disks, selected):
        exact(disk, {"target", "file", "size_bytes", "virtual_size", "sha256"})
        if (
            disk["target"] != target
            or disk["file"] != target + ".qcow2"
            or not _hash(disk["sha256"])
        ):
            refuse()
        for name in ("size_bytes", "virtual_size"):
            if type(disk[name]) is not int or not 0 < disk[name] < 2**63:
                refuse()
    return value


def bind_inventory(value, inventory, intent):
    """Bind exact producer result to the admitted source and file-role set."""
    validate_result(value)
    manifest, source = value["manifest"], intent["source"]
    if (
        intent.get("producer") != FORMAT
        or any(
            manifest[k] != intent[k] for k in ("backup_id", "attempt_id", "checkpoint")
        )
        or manifest["domain_uuid"] != source["domain_uuid"]
        or manifest["source"] != source["disks"]
        or manifest["exclusions"] != source["exclusions"]
        or inventory["checkpoint"] != manifest["checkpoint"]
    ):
        refuse()
    parent = intent.get("push_parent")
    if parent is None:
        if source["backup_type"] != "full" or manifest["parent_backup_id"] is not None:
            refuse()
    else:
        validate_result(parent)
        if (
            source["backup_type"] != "incremental"
            or manifest["parent_backup_id"] != parent["manifest"]["backup_id"]
            or manifest["parent_manifest_sha256"] != parent["manifest_sha256"]
            or [d["virtual_size"] for d in manifest["disks"]]
            != [d["virtual_size"] for d in parent["manifest"]["disks"]]
        ):
            refuse()
    expected = {
        ("domain_config", None): ("domain.xml", None),
        ("checkpoint", None): ("checkpoint.xml", None),
        ("backup_metadata", None): ("manifest.json", len(canonical(manifest))),
    }
    for disk in manifest["disks"]:
        expected[("disk_payload", disk["target"])] = (disk["file"], disk["size_bytes"])
    if len(inventory["files"]) != len(expected):
        refuse()
    for file in inventory["files"]:
        spec = expected.pop((file["role"], file["disk_id"]), None)
        if (
            spec is None
            or file["path"] != spec[0]
            or (spec[1] is not None and file["size"] != spec[1])
        ):
            refuse()
    if expected:
        refuse()
    return value


def validate_receipt_binding(request, receipt, saved):
    """Publisher check after normal receipt verification, before acceptance.

    `saved` is Backup.native_inventory; hashes commit actual uploaded plaintext
    (including manifest/checkpoint/domain XML), not merely filesystem identity.
    The normal native receipt validator separately binds encryption and target.
    """
    value = validate_result(saved["push_result"])
    manifest = value["manifest"]
    inventory = request["plan"]["source"]["inventory"]
    if (
        inventory != saved["inventory"]
        or digest(inventory) != saved["inventory_sha256"]
    ):
        refuse()
    hashes = {
        ("domain_config", None): manifest["domain_xml_sha256"],
        ("checkpoint", None): manifest["checkpoint_sha256"],
        ("backup_metadata", None): value["manifest_sha256"],
    }
    hashes.update(
        {("disk_payload", disk["target"]): disk["sha256"] for disk in manifest["disks"]}
    )
    if len(receipt["objects"]) != len(hashes):
        refuse()
    files = {file["artifact_id"]: file for file in inventory["files"]}
    for obj in receipt["objects"]:
        file = files.pop(obj["artifact_id"], None)
        expected_hash = hashes.pop((obj["role"], obj["disk_id"]), None)
        if (
            file is None
            or expected_hash is None
            or obj["plaintext_sha256"] != expected_hash
            or obj["plaintext_bytes"] != file["size"]
        ):
            refuse()
    if files or hashes:
        refuse()
    return value
