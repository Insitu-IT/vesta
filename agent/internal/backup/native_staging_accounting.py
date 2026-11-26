"""Retire local budgets for positively published/reclaimed native attempts.

The authenticated local worker owns its success records. This is local resource
accounting, not independent backend attestation, writer-closure inference, backup
publication, or authority to delete any file. Original evidence is retained.
"""

import hashlib
import json
import os
import re
import stat

import native_write_fence as fence
import libvirt_push as push

RELEASE = "accounting-release.json"
RECORDS = {
    "intent.json",
    "target-binding.json",
    "begin-intent.json",
    "begin-returned.json",
    "producer-sealed.json",
    "admission.json",
    "published.json",
}
HASH = re.compile(r"[0-9a-f]{64}\Z")


def sha(body):
    return hashlib.sha256(body).hexdigest()


def unique(pairs):
    result = {}
    for key, value in pairs:
        fence.require(key not in result, "duplicate accounting field")
        result[key] = value
    return result


def read(directory, name, owner):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    try:
        info = os.fstat(fd)
        fence.require(
            stat.S_ISREG(info.st_mode)
            and info.st_nlink == 1
            and info.st_uid == owner
            and info.st_mode & 0o077 == 0,
            "unsafe accounting evidence",
        )
        body = os.read(fd, fence.MAX_JSON + 1)
        fence.require(len(body) <= fence.MAX_JSON, "oversized accounting evidence")
        value = json.loads(body, object_pairs_hook=unique)
        os.fsync(fd)
        return value, body
    finally:
        os.close(fd)


def retire_reclaimed(directory, allocation, allocation_body):
    """Under allocator lock, freeze positive success evidence before credit."""
    names = set(os.listdir(directory))
    if "published.json" not in names:
        fence.require(RELEASE not in names, "retirement lacks original publication")
        return False
    if "data" in names:
        fence.require(RELEASE not in names, "retired output reappeared")
        return False  # Publication alone does not establish completed reclamation.
    fence.require(
        names
        in (RECORDS | {"allocation.json"}, RECORDS | {"allocation.json", RELEASE}),
        "conflicting or incomplete accounting evidence",
    )
    values, bodies = {}, {}
    for name in sorted(RECORDS):
        values[name], bodies[name] = read(directory, name, allocation["uid"])
    request = values["intent.json"]
    push.validate_request(request)
    fence.require(
        sha(push.canonical(request)) == allocation["request_sha256"]
        and bodies["intent.json"] == push.canonical(request),
        "allocation request changed",
    )
    aid, bid = request["attempt_id"], request["backup_id"]
    binding, seal, admission, published = (
        values[n]
        for n in (
            "target-binding.json",
            "producer-sealed.json",
            "admission.json",
            "published.json",
        )
    )
    push.exact(
        published,
        {
            "schema",
            "backup_id",
            "attempt_id",
            "intent_sha256",
            "admission_sha256",
            "receipt_sha256",
            "acceptance_id",
        },
    )
    push.exact(admission, {"intent_sha256", "inventory", "push_result", "closed_job"})
    push.exact(
        seal, {"schema", "request_sha256", "invocation_id", "result", "artifacts"}
    )
    fence.require(
        type(published["schema"]) is int
        and published["schema"] == 1
        and published["backup_id"] == bid
        and published["attempt_id"] == aid
        and published["intent_sha256"] == admission["intent_sha256"]
        and published["admission_sha256"] == sha(bodies["admission.json"])
        and all(
            type(published[k]) is str and HASH.fullmatch(published[k])
            for k in ("intent_sha256", "admission_sha256", "receipt_sha256")
        )
        and type(published["acceptance_id"]) is str
        and 0 < len(published["acceptance_id"]) <= 1024,
        "publication accounting identity differs",
    )
    fence.require(
        seal["schema"] == "libvirt-producer-seal/1"
        and seal["request_sha256"] == allocation["request_sha256"]
        and seal["result"] == admission["push_result"],
        "original success seal differs",
    )
    result, closed, inventory = (
        admission["push_result"],
        admission["closed_job"],
        admission["inventory"],
    )
    push.exact(result, {"manifest", "manifest_sha256"})
    manifest = result["manifest"]
    fence.require(
        result["manifest_sha256"] == sha(push.canonical(manifest))
        and manifest["schema"] == push.FORMAT
        and manifest["backup_id"] == bid
        and manifest["attempt_id"] == aid
        and manifest["domain_uuid"] == request["domain_uuid"]
        and manifest["source"] == request["disks"]
        and manifest["exclusions"] == request["exclusions"]
        and manifest["checkpoint"] == "vnbui-" + aid,
        "original successful manifest differs",
    )
    push.exact(closed, {"job_id", "attempt_id", "invocation_id", "exit_code", "state"})
    fence.require(
        closed["attempt_id"] == aid
        and closed["job_id"] == "vnbui-native-" + aid
        and closed["state"] in ("exited", "sealed")
        and type(closed["exit_code"]) is int
        and closed["exit_code"] == 0
        and type(closed["invocation_id"]) is str
        and re.fullmatch(r"[0-9a-f]{32}", closed["invocation_id"])
        and type(seal["invocation_id"]) is str
        and re.fullmatch(r"[0-9a-f]{32}", seal["invocation_id"])
        and (
            closed["state"] != "sealed"
            or closed["invocation_id"] == seal["invocation_id"]
        ),
        "positive original closure unavailable",
    )
    fence.require(
        inventory["format"] == "libvirt-native-fileset/1"
        and inventory["backup_id"] == bid
        and inventory["attempt_id"] == aid
        and inventory["domain_uuid"] == request["domain_uuid"]
        and inventory["job_id"] == closed["job_id"]
        and inventory["checkpoint"] == manifest["checkpoint"],
        "published inventory differs",
    )
    selected = {
        d["target"]
        for d in request["disks"]
        if d["target"] not in request["exclusions"]
    }
    expected = {"domain.xml", "checkpoint.xml", "manifest.json"} | {
        t + ".qcow2" for t in selected
    }
    artifacts, members = seal["artifacts"], inventory["files"]
    fence.require(
        type(artifacts) is list
        and type(members) is list
        and len(artifacts) == len(members) == len(expected)
        and {a["path"] for a in artifacts} == {m["path"] for m in members} == expected,
        "original artifact membership differs",
    )
    by_path = {m["path"]: m for m in members}
    for artifact in artifacts:
        member = by_path[artifact["path"]]
        fence.require(
            all(
                artifact[k] == member[k]
                for k in ("device", "inode", "size", "mtime_ns", "ctime_ns")
            )
            and member["member_backup_id"] == bid
            and member["member_checkpoint"] == manifest["checkpoint"],
            "sealed inventory identity differs",
        )
    fence.require(
        binding["schema"] == "libvirt-target-binding/1"
        and binding["directory"] == allocation["directory"]
        and binding["request_sha256"] == allocation["request_sha256"]
        and set(binding["targets"]) == selected,
        "original target binding differs",
    )
    for target in selected:
        member = by_path[target + ".qcow2"]
        fence.require(
            binding["targets"][target] == [member["device"], member["inode"]],
            "original disk identity differs",
        )
    fence.require(
        values["begin-intent.json"]
        == {
            "schema": "libvirt-begin-intent/1",
            "request_sha256": allocation["request_sha256"],
        }
        and values["begin-returned.json"]["schema"] == "libvirt-begin-returned/1"
        and values["begin-returned.json"]["request_sha256"]
        == allocation["request_sha256"],
        "original begin identity differs",
    )
    certificate = {
        "schema": "libvirt-staging-reclaimed/1",
        "directory": allocation["directory"],
        "request_sha256": allocation["request_sha256"],
        "allocation_sha256": sha(allocation_body),
        "evidence_sha256": {n: sha(b) for n, b in bodies.items()},
    }
    encoded = fence.canonical(certificate)
    if RELEASE in names:
        value, original = read(directory, RELEASE, 0)
        fence.require(
            value == certificate and original == encoded,
            "root accounting certificate changed",
        )
    else:
        fd = os.open(
            RELEASE,
            os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW,
            0o600,
            dir_fd=directory,
        )
        with os.fdopen(fd, "wb") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
    # Freeze names first, then enroll metadata verity: a lingering writable FD
    # refuses credit. Never unlink/clear flags; partial failure stays charged.
    fence.make_immutable(directory)
    fence.require(
        set(os.listdir(directory)) == RECORDS | {"allocation.json", RELEASE},
        "accounting entries changed",
    )
    for name in sorted(RECORDS | {RELEASE}):
        fd = os.open(
            name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory
        )
        try:
            fence.enable_verity(fd)
            expected_body = encoded if name == RELEASE else bodies[name]
            fence.require(
                os.read(fd, fence.MAX_JSON + 1) == expected_body,
                "accounting evidence changed during freeze",
            )
            fence.make_immutable(fd)
        finally:
            os.close(fd)
    os.fsync(directory)
    return True
