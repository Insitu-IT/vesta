"""Native-file wire admission, not filesystem or completed-job attestation."""

import hashlib
import json
import posixpath
import re

from core.s3_ownership import StorageOwnershipError

# Runtime stays within the backend image; tests compare these closed shapes to
# the Go-generated contract rather than importing agent files in production.
NATIVE_FILESET_FIELDS = {
    "attempt_id",
    "backup_id",
    "checkpoint",
    "disks",
    "domain_uuid",
    "files",
    "format",
    "job_id",
}
NATIVE_DISK_FIELDS = {"bus", "id", "serial", "target"}
NATIVE_FILE_FIELDS = {
    "artifact_id",
    "ctime_ns",
    "device",
    "disk_id",
    "inode",
    "member_backup_id",
    "member_checkpoint",
    "mtime_ns",
    "path",
    "role",
    "size",
}


def refuse():
    raise StorageOwnershipError("Native inventory unavailable; retain local evidence")


def digest(value):
    return hashlib.sha256(
        json.dumps(
            value,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
    ).hexdigest()


def exact(value, fields):
    if type(value) is not dict or set(value) != set(fields):
        refuse()


def native_source_disks(inventory):
    """Project measured capacity out of the original four-field producer identity."""
    if type(inventory) is not list or not 0 < len(inventory) <= 128:
        refuse()
    result, targets = [], set()
    for observed in inventory:
        if type(observed) is not dict:
            refuse()
        disk = dict(observed)
        capacity = disk.pop("capacity_bytes", None)
        if capacity is not None and (
            type(capacity) is not int or not 0 < capacity < 2**63
        ):
            refuse()
        if "capacity_source" in disk and (
            disk.pop("capacity_source") != "libvirt.domain.blockInfo.capacity"
            or capacity is None
        ):
            refuse()
        exact(disk, {"target", "source", "bus", "format"})
        if any(type(v) is not str or not v or len(v) > 1024 for v in disk.values()):
            refuse()
        if disk["target"] in targets or not re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", disk["target"]
        ):
            refuse()
        targets.add(disk["target"])
        result.append(disk)
    return sorted(result, key=lambda d: d["target"])


def validate(value):
    exact(value, NATIVE_FILESET_FIELDS)
    for key in ("domain_uuid", "backup_id", "attempt_id"):
        if type(value[key]) is not str or not re.fullmatch(
            r"[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}",
            value[key],
        ):
            refuse()
    for key in ("job_id", "checkpoint"):
        if type(value[key]) is not str or not re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", value[key]
        ):
            refuse()
    if value["format"] != "libvirt-native-fileset/1":
        refuse()
    disks, files = value["disks"], value["files"]
    if (
        type(disks) is not list
        or not 0 < len(disks) <= 128
        or type(files) is not list
        or not 0 < len(files) <= 4096
    ):
        refuse()
    disk_ids, targets = set(), set()
    for disk in disks:
        exact(disk, NATIVE_DISK_FIELDS)
        for key in ("id", "target", "bus"):
            if type(disk[key]) is not str or not re.fullmatch(
                r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", disk[key]
            ):
                refuse()
        if (
            type(disk["serial"]) is not str
            or len(disk["serial"].encode()) > 256
            or disk["id"] in disk_ids
            or disk["target"] in targets
        ):
            refuse()
        disk_ids.add(disk["id"])
        targets.add(disk["target"])
    paths, directories, inodes, roles, payloads = set(), {}, set(), set(), set()
    total = path_bytes = components = 0
    for f in files:
        exact(f, NATIVE_FILE_FIELDS)
        p = f["path"]
        if (
            type(p) is not str
            or not 0 < len(p) <= 1024
            or len(p.split("/")) > 16
            or any(
                re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,254}", part) is None
                for part in p.split("/")
            )
            or p.lower() in paths
        ):
            refuse()
        paths.add(p.lower())
        path_bytes += len(p)
        components += len(p.split("/"))
        directory = posixpath.dirname(p)
        while directory:
            folded = directory.lower()
            if folded in directories and directories[folded] != directory:
                refuse()
            directories[folded] = directory
            directory = posixpath.dirname(directory)
        if path_bytes > 256 * 1024 or components > 4096 or len(directories) > 1024:
            refuse()
        for key in ("device", "inode", "size", "mtime_ns", "ctime_ns"):
            lower, upper = (
                (0, 2**64) if key in {"device", "inode"} else (-(2**63), 2**63)
            )
            if type(f[key]) is not int or not lower <= f[key] < upper:
                refuse()
        if not 0 <= f["size"] <= 2**50 or f["inode"] <= 0 or f["device"] < 0:
            refuse()
        total += f["size"]
        if total > 128 * 2**50 + 260 * 16 * 1024 * 1024:
            refuse()
        inode = (f["device"], f["inode"])
        if inode in inodes:
            refuse()
        inodes.add(inode)
        if (
            f["member_backup_id"] != value["backup_id"]
            or f["member_checkpoint"] != value["checkpoint"]
        ):
            refuse()
        disk, role = f["disk_id"], f["role"]
        if type(role) is not str or (
            disk is not None and (type(disk) is not str or disk not in disk_ids)
        ):
            refuse()
        if (role, disk) in roles:
            refuse()
        roles.add((role, disk))
        if role in {"disk_payload", "disk_checksum", "disk_metadata"}:
            if disk is None:
                refuse()
            if role == "disk_payload":
                payloads.add(disk)
        elif (
            role not in {"domain_config", "checkpoint", "autostart", "backup_metadata"}
            or disk is not None
        ):
            refuse()
        if role != "disk_payload" and f["size"] > 16 * 1024 * 1024:
            refuse()
        identity = [
            value[k]
            for k in (
                "format",
                "domain_uuid",
                "backup_id",
                "attempt_id",
                "job_id",
                "checkpoint",
            )
        ]
        identity += [
            f[k]
            for k in (
                "member_backup_id",
                "member_checkpoint",
                "path",
                "role",
                "disk_id",
            )
        ]
        if f["artifact_id"] != digest(identity):
            refuse()
    if (
        paths.intersection(directories)
        or payloads != disk_ids
        or not {("domain_config", None), ("checkpoint", None)} <= roles
    ):
        refuse()
    return value
