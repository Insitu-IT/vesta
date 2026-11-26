"""Attempt-scoped libvirt push producer and offline qcow2 chain restore.

Executed by the agent with a private JSON request on stdin. Requires current
python3-libvirt/libvirt_qemu and qemu-img; there is no older-provider fallback.
No checkpoint deletion, job abort, QMP mutation, or live-domain restore occurs.
"""

from decimal import Decimal, ROUND_CEILING
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import threading
import time
import uuid
import xml.etree.ElementTree as ET

FORMAT = "libvirt-push-qcow2/1"
MAX_JSON = 4 * 1024 * 1024
MAX_EVENTS = 8192
FAILURE_CLOSURE_WAIT_SECONDS = 60
SAFE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
SHA = re.compile(r"[0-9a-f]{64}\Z")
# This profile uses a private libvirt job-name implementation, not a public
# attempt-ID API. Expanding it requires checking that implementation and the
# live event contract, not guessing a name for an unrecognized runtime.
LIBVIRT_PROFILES = ((11010000, 11011000), (12007000, 12008000))
# CentOS Stream 9's 11.10.x is the primary distribution profile. The separately
# validated 12.7.x profile remains explicit; this is not an open-ended minimum.
QEMU_PROFILE = (10001000, 10002000)  # 10.1.x


class Uncertain(Exception):
    """The attempt is not publishable; retain all custody and output."""


def require(value, message):
    if not value:
        raise Uncertain(message)


def canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()


def sha(value):
    return hashlib.sha256(value).hexdigest()


def valid_uuid(value):
    return isinstance(value, str) and str(uuid.UUID(value)) == value


def exact(value, keys):
    require(
        type(value) is dict and set(value) == set(keys), "unexpected request fields"
    )


def source(xml):
    root = ET.fromstring(xml)
    disks = []
    for disk in root.findall("./devices/disk"):
        if disk.get("device") != "disk":
            continue
        require(
            disk.get("type") in {"file", "block"},
            "only local file/block disks are supported",
        )
        require(
            disk.find("readonly") is None and disk.find("shareable") is None,
            "readonly/shared disks must not enter this producer",
        )
        target, backing, driver = (
            disk.find("target"),
            disk.find("source"),
            disk.find("driver"),
        )
        require(
            target is not None and backing is not None and driver is not None,
            "incomplete disk mapping",
        )
        path = backing.get("file") if disk.get("type") == "file" else backing.get("dev")
        require(
            path and os.path.isabs(path), "disk source is not an absolute local path"
        )
        disks.append(
            dict(
                target=target.get("dev"),
                source=path,
                bus=target.get("bus"),
                format=driver.get("type"),
            )
        )
    return root.findtext("uuid"), sorted(disks, key=lambda d: d["target"])


def validate_disks(disks):
    require(type(disks) is list and 0 < len(disks) <= 128, "invalid disk count")
    targets = set()
    for disk in disks:
        exact(disk, ("target", "source", "bus", "format"))
        require(
            all(type(x) is str and 0 < len(x) <= 4096 for x in disk.values()),
            "invalid disk identity",
        )
        require(
            SAFE.fullmatch(disk["target"]) and disk["target"] not in targets,
            "duplicate/invalid target",
        )
        require(
            os.path.isabs(disk["source"]) and disk["format"] in {"qcow2", "raw"},
            "unsupported disk source",
        )
        targets.add(disk["target"])
    require(disks == sorted(disks, key=lambda d: d["target"]), "disks must be ordered")


def allocation_ancestry(target):
    for parent in target.parents:
        info = parent.lstat()
        require(
            stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and info.st_mode & 0o022 == 0,
            "allocation ancestry is not root-managed",
        )


def claim_staging_allocation(target, request):
    """Accept only a root-issued fresh slot, never an existing producer attempt."""
    import fcntl
    import struct

    require(request is not None, "existing output is not a fresh allocation")
    allocation_ancestry(target)
    directory = os.open(target, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        info = os.fstat(directory)
        require(info.st_uid == os.geteuid() and info.st_mode & 0o066 == 0,
                "allocation owner or permissions differ")
        require(os.listdir(directory) == ["allocation.json"], "allocation is not fresh")
        fd = os.open("allocation.json", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                     dir_fd=directory)
        with os.fdopen(fd, "rb") as stream:
            record = os.fstat(stream.fileno())
            require(stat.S_ISREG(record.st_mode) and record.st_uid == 0
                    and record.st_nlink == 1 and record.st_mode & 0o222 == 0,
                    "allocation is not root-issued")
            flags = bytearray(8)
            fcntl.ioctl(stream.fileno(), 0x80086601, flags, True)
            require(struct.unpack_from("<I", flags)[0] & 0x10, "allocation is not immutable")
            body = stream.read(MAX_JSON + 1)
        require(len(body) <= MAX_JSON, "allocation too large")
        allocation = json.loads(body)
        exact(allocation, ("schema", "request_sha256", "directory", "uid", "gid", "reserved_bytes"))
        require(body == canonical(allocation)
                and allocation["schema"] == "libvirt-staging-allocation/1"
                and allocation["request_sha256"] == sha(canonical(request))
                and allocation["directory"] == [info.st_dev, info.st_ino]
                and allocation["uid"] == info.st_uid and allocation["gid"] == info.st_gid
                and type(allocation["reserved_bytes"]) is int and allocation["reserved_bytes"] > 0,
                "allocation binding differs")
    finally:
        os.close(directory)


def private_directory(path, qemu_search=False, allocation_request=None):
    target = Path(path)
    require(
        target.is_absolute() and str(target) == os.path.normpath(path),
        "output path must be absolute and normalized",
    )
    require(
        str(target.parent.resolve(strict=True)) == str(target.parent),
        "output parent may not contain symlinks",
    )
    # QEMU needs search permission after libvirt labels/chowns target files.
    # It does not need to list the attempt journal or read its metadata.
    mode = 0o711 if qemu_search else 0o700
    try:
        target.mkdir(mode=mode)
    except FileExistsError:
        if not os.path.lexists(target / "allocation.json"):
            raise
        claim_staging_allocation(target, allocation_request)
    os.chmod(target, mode)  # Search access must not depend on the service umask.
    parent = os.open(target.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(parent)  # A crash must not lose the attempt's directory link.
    finally:
        os.close(parent)
    return target


def durable_file(path, body):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(body)
        stream.flush()
        os.fsync(stream.fileno())
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def file_identity(path):
    info = os.lstat(path)
    require(
        stat.S_ISREG(info.st_mode) and info.st_nlink == 1,
        "target is not a private regular file",
    )
    return info.st_dev, info.st_ino


def hash_file(path, seal=False):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        require(
            stat.S_ISREG(before.st_mode) and before.st_nlink == 1,
            "non-private image",
        )
        digest = hashlib.sha256()
        count = 0
        while True:
            block = stream.read(1024 * 1024)
            if not block:
                break
            digest.update(block)
            count += len(block)
        if seal:
            os.fsync(stream.fileno())
        after = os.fstat(stream.fileno())
        require(
            (
                before.st_dev,
                before.st_ino,
                before.st_size,
                before.st_mtime_ns,
                before.st_ctime_ns,
            )
            == (
                after.st_dev,
                after.st_ino,
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
            )
            and count == after.st_size
            and file_identity(path) == (after.st_dev, after.st_ino),
            "image changed during hashing",
        )
        if seal:
            return (
                count,
                digest.hexdigest(),
                dict(
                    path=path.name,
                    device=after.st_dev,
                    inode=after.st_ino,
                    size=after.st_size,
                    mtime_ns=after.st_mtime_ns,
                    ctime_ns=after.st_ctime_ns,
                    sha256=digest.hexdigest(),
                ),
            )
    return count, digest.hexdigest()


def sealed_artifact(path, expected_digest):
    """Durably pin a closed artifact after every image-writing command returned."""
    _, digest, artifact = hash_file(path, seal=True)
    require(digest == expected_digest, "sealed artifact changed")
    return artifact


def verify_sealed_artifact(path, artifact):
    info = os.lstat(path)
    require(
        stat.S_ISREG(info.st_mode)
        and info.st_nlink == 1
        and (
            info.st_dev,
            info.st_ino,
            info.st_size,
            info.st_mtime_ns,
            info.st_ctime_ns,
        )
        == tuple(
            artifact[k] for k in ("device", "inode", "size", "mtime_ns", "ctime_ns")
        ),
        "artifact changed before durable seal",
    )


def image_command(*args):
    # No shell and no -U: qemu-img must obtain its normal image lock. In
    # particular, a surviving producer makes finalization fail, not bypass it.
    result = subprocess.run(
        ["qemu-img", *args], capture_output=True, check=True, timeout=3600
    )
    require(len(result.stdout) <= MAX_JSON, "qemu-img output too large")
    return result.stdout


def verify_image_tool():
    version = image_command("--version").decode("ascii", errors="replace")
    match = re.match(r"qemu-img version (\d+)\.(\d+)\.(\d+)(?:\s|$)", version)
    require(
        match is not None and tuple(map(int, match.groups()))[:2] == (10, 1),
        "native qcow2 profile requires qemu-img 10.1.x; install the supported image tools",
    )


def verify_runtime_versions(libvirt_version, qemu_version):
    require(
        any(low <= libvirt_version < high for low, high in LIBVIRT_PROFILES),
        "native push profile requires validated libvirt 11.10.x or 12.7.x; other versions are refused",
    )
    require(
        QEMU_PROFILE[0] <= qemu_version < QEMU_PROFILE[1],
        "native push profile requires running QEMU 10.1.x; upgrade/restart the domain on the supported runtime",
    )


def image_info(path):
    info = json.loads(image_command("info", "--output=json", "-f", "qcow2", str(path)))
    require(
        info.get("format") == "qcow2"
        and type(info.get("virtual-size")) is int
        and info["virtual-size"] > 0,
        "invalid qcow2 image",
    )
    specific = info.get("format-specific", {}).get("data", {})
    require(
        not specific.get("data-file") and not info.get("snapshots"),
        "external data files/snapshots are not supported",
    )
    return info


class Transcript:
    """Continuous event history; domain-wide success alone is never evidence.

    QEMU job IDs can be reused. Each pinned job must have exactly one observed
    created->running->completed->concluded->null cycle during this invocation.
    QEMU can pause and resume a pinned job internally during normal backup;
    pause alone has no provenance. A reconnect, replacement cycle, error or
    any other domain job is uncertain.
    """

    def __init__(self):
        self.lock = threading.Lock()
        self.events = []
        self.failure = None

    def append(self, event, data):
        with self.lock:
            if len(self.events) >= MAX_EVENTS:
                self.failure = "event observation overflow"
            else:
                self.events.append((event, data))

    def gap(self, why):
        with self.lock:
            self.failure = why

    def closed_events(self, expected):
        """Prove writer termination, never successful data or cleanup authority.

        Foreign activity invalidates successful backup attribution but need not
        prevent an acknowledged attempt's own jobs from finishing. Each pinned
        ID must still have one continuously observed created-to-null lifecycle.
        A gap or replacement is not closure, even if a later job is terminal.
        """
        with self.lock:
            require(self.failure is None, self.failure or "observer gap")
            events = list(self.events)
        require(bool(expected), "no pinned jobs for failure closure")
        transitions = {
            None: {"created"},
            "created": {"running", "aborting"},
            "running": {"paused", "waiting", "pending", "aborting", "concluded"},
            "paused": {"running", "aborting"},
            "waiting": {"pending", "aborting", "concluded"},
            "pending": {"aborting", "concluded"},
            "aborting": {"concluded"},
            "concluded": {"null"},
            "null": set(),
        }
        states, selected = {}, []
        for event, data in events:
            if event != "JOB_STATUS_CHANGE" or data.get("id") not in expected:
                continue
            job, state = data["id"], data.get("status")
            require(
                state in transitions.get(states.get(job), set()),
                "replaced or incomplete job lifecycle during failure closure",
            )
            states[job] = state
            selected.append(dict(id=job, status=state))
        if set(states) == expected and all(s == "null" for s in states.values()):
            return selected
        return None

    def closed(self, expected):
        return self.closed_events(expected) is not None

    def evaluate(self, expected, final=False):
        with self.lock:
            require(self.failure is None, self.failure or "observer gap")
            events = list(self.events)
        states, finished, domain_success = {}, set(), 0
        transitions = {
            None: {"created"},
            "created": {"running"},
            "running": {"paused", "waiting", "pending", "concluded"},
            "paused": {"running"},
            "waiting": {"pending", "concluded"},
            "pending": {"concluded"},
            "concluded": {"null"},
            "null": set(),
        }
        for event, data in events:
            if event == "JOB_STATUS_CHANGE":
                job, state = data.get("id"), data.get("status")
                previous = states.get(job)
                require(
                    job in expected
                    and state in transitions.get(previous, set())
                    and (state not in {"paused", "running"} or job not in finished),
                    "foreign, replaced or incomplete job lifecycle",
                )
                if state in {"concluded", "null"}:
                    require(job in finished, "job concluded without attributed success")
                states[job] = state
            elif event == "BLOCK_JOB_COMPLETED":
                job = data.get("device")
                require(
                    job in expected
                    and job not in finished
                    and states.get(job) in {"running", "waiting", "pending"}
                    and data.get("type") == "backup"
                    and "error" not in data
                    and type(data.get("len")) is int
                    and data["len"] >= 0
                    and data.get("offset") == data["len"],
                    "backup completion was not attributable and successful",
                )
                finished.add(job)
            elif event == "DOMAIN_JOB_COMPLETED":
                require(
                    data.get("operation") == 9 and data.get("success") is True,
                    "domain job failed or was replaced",
                )
                domain_success += 1
                require(
                    domain_success == 1, "multiple domain completions in one attempt"
                )
            elif event in {
                "BLOCK_JOB_CANCELLED",
                "BLOCK_JOB_ERROR",
                "LIFECYCLE",
                "DEVICE_ADDED",
                "DEVICE_DELETED",
                "BLOCK_IMAGE_CORRUPTED",
                "RESET",
                "SHUTDOWN",
                "STOP",
                "RESUME",
            }:
                raise Uncertain(
                    "observed external mutation, cancellation or I/O error: " + event
                )
        done = (
            bool(expected)
            and set(states) == expected
            and all(s == "null" for s in states.values())
            and domain_success == 1
        )
        if final:
            require(done, "terminal event history is incomplete")
        return done


class LibvirtDriver:
    def __init__(self, uri, domain_uuid):
        import libvirt
        import libvirt_qemu

        self.lv, self.qemu = libvirt, libvirt_qemu
        libvirt.virEventRegisterDefaultImpl()
        self.conn = libvirt.open(uri)
        require(self.conn is not None, "libvirt connection failed")
        self.dom = self.conn.lookupByUUIDString(domain_uuid)
        # The domain may still run an older binary after host packages were
        # upgraded. Check its QMP version, not just the driver's default binary.
        version = self.query("query-version").get("qemu", {})
        require(
            all(type(version.get(k)) is int for k in ("major", "minor", "micro")),
            "QEMU version unavailable",
        )
        verify_runtime_versions(
            self.conn.getLibVersion(),
            version["major"] * 1000000 + version["minor"] * 1000 + version["micro"],
        )
        self.transcript = Transcript()
        self.conn.registerCloseCallback(
            lambda *_: self.transcript.gap("libvirt connection closed"), None
        )
        self.ids = [
            self.conn.domainEventRegisterAny(
                self.dom,
                libvirt.VIR_DOMAIN_EVENT_ID_JOB_COMPLETED,
                lambda _c, _d, params, _o: self.transcript.append(
                    "DOMAIN_JOB_COMPLETED", params
                ),
                None,
            ),
            self.conn.domainEventRegisterAny(
                self.dom,
                libvirt.VIR_DOMAIN_EVENT_ID_LIFECYCLE,
                lambda *_: self.transcript.append("LIFECYCLE", {}),
                None,
            ),
        ]
        self.qmp_id = libvirt_qemu.qemuMonitorEventRegister(
            self.conn, self.dom, None, self._qmp_event, None
        )
        self.stopped = False
        self.event_thread = threading.Thread(target=self._events, daemon=True)
        self.event_thread.start()

    def _qmp_event(self, _conn, _dom, event, _seconds, _micros, details, _opaque):
        try:
            self.transcript.append(event, json.loads(details or "{}"))
        except Exception:
            self.transcript.gap("malformed QEMU event")

    def _events(self):
        try:
            while not self.stopped:
                self.lv.virEventRunDefaultImpl()
        except Exception:
            self.transcript.gap("libvirt event loop stopped")

    def query(self, name):
        require(
            name in {"query-block-jobs", "query-jobs", "query-block", "query-version"},
            "non-read-only QMP command refused",
        )
        reply = json.loads(
            self.qemu.qemuMonitorCommand(self.dom, json.dumps({"execute": name}), 0)
        )
        require("return" in reply, "QEMU observation failed")
        return reply["return"]

    def xml(self):
        return self.dom.XMLDesc(0)

    def checkpoints(self):
        values = {}
        for checkpoint in self.dom.listAllCheckpoints(0):
            name = checkpoint.getName()
            require(
                name not in values and len(values) < 4096,
                "invalid checkpoint inventory",
            )
            values[name] = checkpoint.getXMLDesc(0)
        return values

    def sizes(self, disks):
        return {d["target"]: self.dom.blockInfo(d["target"], 0)[0] for d in disks}

    def expected_jobs(self, disks):
        # Reviewed libvirt v11.10.0/v12.7.0 qemuBlockJobDiskNewBackup names jobs
        # using the
        # disk target and effective QEMU source node. Derive that node from a
        # read-only query, never from whatever job happens to be current later.
        # Unrecognized/filter/ambiguous mappings are refused, not guessed.
        blocks = self.query("query-block")
        result, nodes = set(), set()
        for disk in disks:
            matches = [
                b["inserted"]
                for b in blocks
                if isinstance(b.get("inserted"), dict)
                and b["inserted"].get("image", {}).get("filename") == disk["source"]
                and b["inserted"].get("image", {}).get("format") == disk["format"]
            ]
            require(len(matches) == 1, "QEMU source node is ambiguous or unsupported")
            node = matches[0].get("node-name")
            require(
                isinstance(node, str) and SAFE.fullmatch(node) and node not in nodes,
                "QEMU source node is not unique",
            )
            nodes.add(node)
            result.add("backup-" + disk["target"] + "-" + node)
        return result

    def begin(self, backup_xml, checkpoint_xml):
        # All target files were exclusively created by us before begin. Reuse
        # avoids internal image-create QMP jobs and libvirt deleting targets on
        # cancellation; it never means reusing a previous attempt's files.
        self.dom.backupBegin(
            backup_xml, checkpoint_xml, self.lv.VIR_DOMAIN_BACKUP_BEGIN_REUSE_EXTERNAL
        )

    def backup_xml(self):
        try:
            return self.dom.backupGetXMLDesc(0)
        except self.lv.libvirtError as error:
            if error.get_error_code() in {
                self.lv.VIR_ERR_OPERATION_INVALID,
                self.lv.VIR_ERR_NO_DOMAIN_BACKUP,
            }:
                return (
                    None  # No active view is NOT success; events still must prove it.
                )
            raise

    def close(self):
        self.stopped = True
        self.qemu.qemuMonitorEventDeregister(self.conn, self.qmp_id)
        for callback in self.ids:
            self.conn.domainEventDeregisterAny(callback)
        self.conn.unregisterCloseCallback()
        # Deregistration need not wait for an already-dispatching callback.
        # Wake the default loop so it can observe stopped, and join it before
        # the caller evaluates the final transcript. A timeout is uncertainty,
        # never permission to seal while callbacks can still change evidence.
        wake = self.lv.virEventAddTimeout(0, lambda *_: None, None)
        try:
            self.event_thread.join(timeout=5)
            require(not self.event_thread.is_alive(), "observer teardown did not quiesce")
        finally:
            self.lv.virEventRemoveTimeout(wake)
            self.conn.close()


def backup_xml(request, checkpoint, directory):
    backup = ET.Element("domainbackup", mode="push")
    if request["parent"] is not None:
        ET.SubElement(backup, "incremental").text = request["parent"]["manifest"][
            "checkpoint"
        ]
    disks = ET.SubElement(backup, "disks")
    cp = ET.Element("domaincheckpoint")
    ET.SubElement(cp, "name").text = checkpoint
    ET.SubElement(cp, "description").text = "Vesta native backup attempt " + request["attempt_id"]
    cpdisks = ET.SubElement(cp, "disks")
    for disk in request["disks"]:
        target = disk["target"]
        if target in request["exclusions"]:
            ET.SubElement(disks, "disk", name=target, backup="no")
            ET.SubElement(cpdisks, "disk", name=target, checkpoint="no")
        else:
            output = ET.SubElement(
                disks, "disk", name=target, backup="yes", type="file"
            )
            ET.SubElement(output, "driver", type="qcow2")
            ET.SubElement(output, "target", file=str(directory / (target + ".qcow2")))
            ET.SubElement(
                cpdisks, "disk", name=target, checkpoint="bitmap", bitmap=checkpoint
            )
    return ET.tostring(backup, encoding="unicode"), ET.tostring(cp, encoding="unicode")


def verify_active(xml, request, directory):
    root = ET.fromstring(xml)
    require(root.get("mode", "push") == "push", "active backup mode changed")
    wanted = request["parent"]["manifest"]["checkpoint"] if request["parent"] else None
    require(
        root.findtext("incremental") == wanted, "active incremental ancestor changed"
    )
    observed = {}
    for disk in root.findall("./disks/disk"):
        if disk.get("backup") == "no":
            continue
        target = disk.find("target")
        require(
            target is not None and disk.get("name") not in observed,
            "invalid active backup mapping",
        )
        observed[disk.get("name")] = target.get("file")
    expected = {
        d["target"]: str(directory / (d["target"] + ".qcow2"))
        for d in request["disks"]
        if d["target"] not in request["exclusions"]
    }
    require(observed == expected, "active backup targets do not belong to this attempt")


def validate_manifest(manifest):
    exact(
        manifest,
        (
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
        ),
    )
    require(manifest["schema"] == FORMAT, "unsupported native representation")
    require(
        all(
            valid_uuid(manifest[k]) for k in ("backup_id", "attempt_id", "domain_uuid")
        ),
        "invalid manifest identity",
    )
    require(
        manifest["checkpoint"] == "vnbui-" + manifest["attempt_id"],
        "checkpoint/attempt mismatch",
    )
    require(
        all(
            type(manifest[k]) is str and SHA.fullmatch(manifest[k])
            for k in ("checkpoint_sha256", "domain_xml_sha256")
        ),
        "invalid metadata digest",
    )
    parent = manifest["parent_backup_id"]
    require(
        (parent is None and manifest["parent_manifest_sha256"] is None)
        or (
            valid_uuid(parent)
            and type(manifest["parent_manifest_sha256"]) is str
            and SHA.fullmatch(manifest["parent_manifest_sha256"])
        ),
        "invalid parent binding",
    )
    validate_disks(manifest["source"])
    exclusions = manifest["exclusions"]
    require(
        type(exclusions) is list and exclusions == sorted(set(exclusions)),
        "invalid exclusions",
    )
    wanted = [d["target"] for d in manifest["source"] if d["target"] not in exclusions]
    require(
        set(exclusions) < {d["target"] for d in manifest["source"]},
        "exclusions do not select protected disks",
    )
    require(
        type(manifest["disks"]) is list
        and [d.get("target") for d in manifest["disks"]] == wanted,
        "manifest disks differ from source",
    )
    for disk in manifest["disks"]:
        exact(disk, ("target", "file", "size_bytes", "virtual_size", "sha256"))
        require(
            disk["file"] == disk["target"] + ".qcow2"
            and type(disk["sha256"]) is str
            and SHA.fullmatch(disk["sha256"]),
            "invalid image binding",
        )
        require(
            all(
                type(disk[k]) is int and 0 < disk[k] < 2**63
                for k in ("size_bytes", "virtual_size")
            ),
            "invalid image size",
        )


def validate_request(request):
    exact(
        request,
        (
            "schema",
            "uri",
            "backup_id",
            "attempt_id",
            "domain_uuid",
            "disks",
            "exclusions",
            "parent",
            "output_path",
            "timeout_seconds",
        ),
    )
    require(
        request["schema"] == FORMAT and request["uri"] == "qemu:///system",
        "native push requires local qemu:///system",
    )
    require(
        all(valid_uuid(request[k]) for k in ("backup_id", "attempt_id", "domain_uuid")),
        "invalid request identity",
    )
    require(
        type(request["timeout_seconds"]) is int
        and 1 <= request["timeout_seconds"] <= 86400,
        "invalid observation timeout",
    )
    validate_disks(request["disks"])
    exclusions = request["exclusions"]
    require(
        type(exclusions) is list
        and exclusions == sorted(set(exclusions))
        and set(exclusions) < {d["target"] for d in request["disks"]},
        "invalid disk exclusions",
    )
    require(
        all(
            d["format"] == "qcow2"
            for d in request["disks"]
            if d["target"] not in exclusions
        ),
        "native checkpoint backups require qcow2 for every protected source disk",
    )
    if request["parent"] is not None:
        parent = request["parent"]
        exact(parent, ("manifest", "manifest_sha256"))
        validate_manifest(parent["manifest"])
        require(
            parent["manifest_sha256"] == sha(canonical(parent["manifest"])),
            "parent manifest digest mismatch",
        )
        require(
            parent["manifest"]["domain_uuid"] == request["domain_uuid"]
            and parent["manifest"]["source"] == request["disks"]
            and parent["manifest"]["exclusions"] == exclusions
            and parent["manifest"]["backup_id"] != request["backup_id"]
            and parent["manifest"]["attempt_id"] != request["attempt_id"],
            "parent source/identity mismatch",
        )


def observe_failure_closure(
    request, directory, driver, jobs, identities, deadline, ack
):
    """Bounded read-only observation of our failed attempt, with no job abort.

    The original begin RPC must have returned and its binding must be durable.
    Keep private output and checkpoint custody; this record cannot be uploaded
    as a successful producer seal or consumed as a pre-begin refusal.
    """
    require(
        (directory / "begin-returned.json").read_bytes() == ack, "begin ACK changed"
    )
    stop = min(deadline, time.monotonic() + FAILURE_CLOSURE_WAIT_SECONDS)
    while not driver.transcript.closed(jobs):
        require(time.monotonic() < stop, "failed writer closure remains unknown")
        time.sleep(0.1)
    artifacts = []
    for name, identity in sorted(identities.items()):
        path = directory / "data" / (name + ".qcow2")
        require(file_identity(path) == identity, "failed target replaced")
        # Normal qemu-img locking, never force-share or a read of the live VM.
        # Do not inspect an incremental backing chain: its source is still live.
        info = image_info(path)
        require(info.get("format") == "qcow2", "failed target format unavailable")
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            stat_before = os.fstat(fd)
            require(
                (stat_before.st_dev, stat_before.st_ino) == identity,
                "failed target replaced",
            )
            os.fsync(fd)
            stat_after = os.fstat(fd)
            fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
            require(
                tuple(getattr(stat_before, k) for k in fields)
                == tuple(getattr(stat_after, k) for k in fields),
                "failed target changed",
            )
            artifacts.append(
                dict(
                    path=path.name,
                    device=stat_after.st_dev,
                    inode=stat_after.st_ino,
                    size=stat_after.st_size,
                    mtime_ns=stat_after.st_mtime_ns,
                    ctime_ns=stat_after.st_ctime_ns,
                )
            )
        finally:
            os.close(fd)
        require(file_identity(path) == identity, "failed target replaced")
    events = driver.transcript.closed_events(jobs)
    require(events is not None, "failed writer closure changed")
    certificate = dict(
        schema="libvirt-closed-failure/1",
        request_sha256=sha(canonical(request)),
        backup_id=request["backup_id"],
        attempt_id=request["attempt_id"],
        domain_uuid=request["domain_uuid"],
        invocation_id=uuid.uuid4().hex,
        begin_ack_sha256=sha(ack),
        job_ids=sorted(jobs),
        terminal_events=events,
        artifacts=artifacts,
    )
    require(len(canonical(certificate)) <= MAX_JSON, "failed closure evidence too large")
    return certificate



def operation_budget(sizes, directory, ceiling):
    """Pin a fresh producer's estimate after exact libvirt source admission.

    The immutable native request's observation timeout remains a hard ceiling.
    This does not grant abort/replay authority for an uncertain existing job.
    """
    def coefficient(name, fallback, upper):
        value = Decimal(os.environ.get(name, fallback))
        require(value.is_finite() and 1 <= value <= upper, "invalid operation coefficient")
        return value

    def positive(name, fallback, maximum):
        value = int(os.environ.get(name, fallback))
        require(1 <= value <= maximum, "invalid operation estimate")
        return value

    factor = coefficient("OPERATION_TIME_COEFFICIENT", "3", 100)
    scratch = coefficient("OPERATION_SCRATCH_COEFFICIENT", "1.2", 4)
    rate = positive("OPERATION_BOOTSTRAP_BYTES_PER_SECOND", "8388608", 2**40)
    preparation = positive("OPERATION_PREPARATION_ESTIMATE_SECONDS", "180", 86400)
    control = positive("OPERATION_CONTROL_ESTIMATE_SECONDS", "60", 3600)
    require(sizes and all(type(v) is int and 0 < v < 2**63 for v in sizes.values()), "invalid selected disk capacities")
    total = sum(sizes.values())
    require(total < 2**63, "selected disk capacity overflow")
    expected = preparation + (total + rate - 1) // rate + control
    run = int((factor * expected).to_integral_value(rounding=ROUND_CEILING))
    closure = int((factor * control).to_integral_value(rounding=ROUND_CEILING))
    require(run + closure <= ceiling, "estimated operation exceeds native observation ceiling")
    required = int((scratch * total).to_integral_value(rounding=ROUND_CEILING))
    stat = os.statvfs(directory)
    available = stat.f_bavail * stat.f_frsize
    require(available >= required, "native output worst-case filesystem reserve unavailable")
    return dict(schema=1, expected_bytes=total, bytes_per_second=rate,
                expected_seconds=expected, run_seconds=run, closure_seconds=closure,
                required_output_bytes=required, available_output_bytes=available,
                started_at_unix=time.time())

def run_backup(request, driver_factory=LibvirtDriver):
    validate_request(request)
    directory = private_directory(request["output_path"], qemu_search=True, allocation_request=request)
    durable_file(directory / "intent.json", canonical(request))
    tree = directory / "data"
    tree.mkdir(mode=0o711)
    os.chmod(tree, 0o711)
    driver = None
    begin_possible = False
    begin_ack = None
    begin_bound = False
    try:
        # Bind local prerequisite failures to this exclusive attempt too. The
        # version probe cannot mutate libvirt; a terminal refusal may settle
        # only after the request intent is durable, never from missing files.
        verify_image_tool()
        driver = driver_factory(request["uri"], request["domain_uuid"])
        original_xml = driver.xml()
        require(
            source(original_xml) == (request["domain_uuid"], request["disks"]),
            "admitted source mapping changed",
        )
        require(
            not driver.query("query-block-jobs") and not driver.query("query-jobs"),
            "another hypervisor job is active",
        )
        before = driver.checkpoints()
        checkpoint = "vnbui-" + request["attempt_id"]
        require(
            checkpoint not in before,
            "attempt checkpoint already exists; restart cannot adopt it",
        )
        if request["parent"] is not None:
            parent = request["parent"]["manifest"]
            require(
                parent["checkpoint"] in before
                and sha(before[parent["checkpoint"]].encode())
                == parent["checkpoint_sha256"],
                "accepted ancestor checkpoint is missing or changed; request a new full",
            )
        selected = [
            d for d in request["disks"] if d["target"] not in request["exclusions"]
        ]
        sizes = driver.sizes(selected)
        budget = operation_budget(sizes, tree, request["timeout_seconds"])
        budget["request_sha256"] = sha(canonical(request))
        deadline = time.monotonic() + budget["run_seconds"]
        durable_file(directory / "operation-budget.json", canonical(budget))
        if request["parent"] is not None:
            parent_sizes = {
                disk["target"]: disk["virtual_size"]
                for disk in request["parent"]["manifest"]["disks"]
            }
            require(
                sizes == parent_sizes,
                "source disk size changed since accepted parent; request a new full",
            )
        job_ids = driver.expected_jobs(selected)
        identities = {}
        for disk in selected:
            path = tree / (disk["target"] + ".qcow2")
            require(not os.path.lexists(path), "target already exists")
            args = ["create", "-f", "qcow2"]
            if request["parent"] is not None:
                # -u records the backing reference without opening the live
                # source. Libvirt attaches the existing source node at begin.
                args += ["-u", "-F", disk["format"], "-b", disk["source"]]
            image_command(*args, str(path), str(sizes[disk["target"]]))
            os.chmod(path, 0o600)
            identities[disk["target"]] = file_identity(path)
        backup, cp = backup_xml(request, checkpoint, tree)
        # The durable intent is already on disk before the single mutation.
        require(
            driver.sizes(selected) == sizes, "source disk size changed before begin"
        )
        # Recovery must bind the original targets even if the begin reply is
        # lost. An ACK written after the RPC cannot supply that missing fact.
        # Persist this before crossing the uncertainty boundary; this record
        # alone is never writer closure or authority to release custody.
        for disk in selected:
            path = tree / (disk["target"] + ".qcow2")
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                info = os.fstat(fd)
                require(
                    (info.st_dev, info.st_ino) == identities[disk["target"]]
                    and stat.S_ISREG(info.st_mode)
                    and info.st_nlink == 1,
                    "target replaced before begin binding",
                )
                os.fsync(fd)
            finally:
                os.close(fd)
        durable_file(
            directory / "target-binding.json",
            canonical(
                dict(
                    schema="libvirt-target-binding/1",
                    request_sha256=sha(canonical(request)),
                    directory=[
                        directory.stat().st_dev,
                        directory.stat().st_ino,
                    ],
                    data_directory=[tree.stat().st_dev, tree.stat().st_ino],
                    backup_xml_sha256=sha(backup.encode()),
                    checkpoint_xml_sha256=sha(cp.encode()),
                    targets={k: list(v) for k, v in sorted(identities.items())},
                )
            ),
        )
        # Publish the uncertainty boundary BEFORE the sole hypervisor mutation.
        # A failed boundary write is itself held; it must never become no-effect.
        begin_possible = True
        durable_file(
            directory / "begin-intent.json",
            canonical(
                dict(
                    schema="libvirt-begin-intent/1",
                    request_sha256=sha(canonical(request)),
                )
            ),
        )
        require(time.monotonic() < deadline, "preparation exhausted the pinned operation budget")
        driver.begin(backup, cp)
        begin_ack = canonical(
            dict(
                schema="libvirt-begin-returned/1",
                request_sha256=sha(canonical(request)),
                job_ids=sorted(job_ids),
                targets={k: list(v) for k, v in sorted(identities.items())},
            )
        )
        durable_file(directory / "begin-returned.json", begin_ack)
        active = driver.backup_xml()
        if active is not None:
            verify_active(active, request, tree)
        jobs = driver.query("query-block-jobs")
        require(
            all(j.get("type") == "backup" and j.get("device") in job_ids for j in jobs),
            "active foreign job observed",
        )
        require(
            all(
                file_identity(tree / (d["target"] + ".qcow2"))
                == identities[d["target"]]
                for d in selected
            ),
            "target replaced at begin",
        )
        begin_bound = True
        after = driver.checkpoints()
        require(
            set(after) == set(before) | {checkpoint}
            and all(after[name] == xml for name, xml in before.items()),
            "checkpoint tree changed across begin",
        )
        cp_root = ET.fromstring(after[checkpoint])
        cp_source = cp_root.find("domain")
        require(
            cp_root.findtext("name") == checkpoint
            and cp_source is not None
            and source(ET.tostring(cp_source, encoding="unicode"))
            == (request["domain_uuid"], request["disks"]),
            "atomic checkpoint source differs from admitted source",
        )
        cp_disks = {
            d.get("name"): d.get("bitmap")
            for d in cp_root.findall("./disks/disk")
            if d.get("checkpoint") != "no"
        }
        require(
            cp_disks == {d["target"]: checkpoint for d in selected},
            "atomic checkpoint bitmap mapping changed",
        )
        while True:
            require(
                source(driver.xml()) == (request["domain_uuid"], request["disks"]),
                "source changed during backup",
            )
            require(
                driver.checkpoints() == after,
                "checkpoint custody changed during backup",
            )
            if driver.transcript.evaluate(job_ids):
                break
            require(
                time.monotonic() < deadline,
                "backup observation deadline exceeded",
            )
            time.sleep(0.1)
        disk_files = []
        disk_artifacts = {}
        for disk in selected:
            path = tree / (disk["target"] + ".qcow2")
            require(
                file_identity(path) == identities[disk["target"]],
                "target inode was replaced",
            )
            info = image_info(path)
            require(
                info["virtual-size"] == sizes[disk["target"]],
                "target virtual size changed",
            )
            if request["parent"] is None:
                require(
                    not info.get("backing-filename"),
                    "full image has an external backing file",
                )
            else:
                # Libvirt incremental push targets reference the live source.
                # Strip only the header reference, without reading/rebasing data.
                # Explicit zero clusters survive; restore supplies accepted parent.
                require(
                    info.get("backing-filename") == disk["source"],
                    "incremental source backing changed",
                )
                image_command("rebase", "-u", "-f", "qcow2", "-b", "", str(path))
            image_command("check", "-f", "qcow2", str(path))
            require(
                not image_info(path).get("backing-filename")
                and file_identity(path) == identities[disk["target"]],
                "image is not isolated",
            )
            count, digest, artifact = hash_file(path, seal=True)
            disk_artifacts[path.name] = artifact
            disk_files.append(
                dict(
                    target=disk["target"],
                    file=path.name,
                    size_bytes=count,
                    virtual_size=sizes[disk["target"]],
                    sha256=digest,
                )
            )
        require(
            source(driver.xml()) == (request["domain_uuid"], request["disks"])
            and driver.sizes(selected) == sizes
            and driver.checkpoints() == after,
            "source/checkpoint changed before sealing",
        )
        driver.transcript.evaluate(job_ids, final=True)
        manifest = dict(
            schema=FORMAT,
            backup_id=request["backup_id"],
            attempt_id=request["attempt_id"],
            domain_uuid=request["domain_uuid"],
            checkpoint=checkpoint,
            checkpoint_sha256=sha(after[checkpoint].encode()),
            parent_backup_id=(
                request["parent"]["manifest"]["backup_id"]
                if request["parent"]
                else None
            ),
            parent_manifest_sha256=(
                request["parent"]["manifest_sha256"] if request["parent"] else None
            ),
            source=request["disks"],
            exclusions=request["exclusions"],
            domain_xml_sha256=sha(original_xml.encode()),
            disks=disk_files,
        )
        validate_manifest(manifest)
        durable_file(tree / "domain.xml", original_xml.encode())
        durable_file(tree / "checkpoint.xml", after[checkpoint].encode())
        durable_file(tree / "manifest.json", canonical(manifest))
        result = dict(manifest=manifest, manifest_sha256=sha(canonical(manifest)))
        digests = {
            "domain.xml": sha(original_xml.encode()),
            "checkpoint.xml": sha(after[checkpoint].encode()),
            "manifest.json": result["manifest_sha256"],
            **{disk["file"]: disk["sha256"] for disk in disk_files},
        }
        artifacts = [
            (
                disk_artifacts[name]
                if name in disk_artifacts
                else sealed_artifact(tree / name, digest)
            )
            for name, digest in sorted(digests.items())
        ]
        require(
            {entry.name for entry in tree.iterdir()} == set(digests),
            "unexpected sealed artifact",
        )
        for artifact in artifacts:
            verify_sealed_artifact(tree / artifact["path"], artifact)
        require(
            source(driver.xml()) == (request["domain_uuid"], request["disks"])
            and driver.sizes(selected) == sizes
            and driver.checkpoints() == after,
            "source/checkpoint changed during durable sealing",
        )
        driver.transcript.evaluate(job_ids, final=True)
        # The QEMU cycles were terminal and all qemu-img children returned.
        # Close observation before publishing the final positive fact. After
        # this record, the helper may only return its result, never write data.
        transcript = driver.transcript
        driver.close()
        driver = None
        # Unsubscription can deliver a final callback or connection gap. Match
        # failed-closure handling: never discard that evidence at teardown.
        transcript.evaluate(job_ids, final=True)
        durable_file(
            directory / "producer-sealed.json",
            canonical(
                dict(
                    schema="libvirt-producer-seal/1",
                    request_sha256=sha(canonical(request)),
                    invocation_id=uuid.uuid4().hex,
                    result=result,
                    artifacts=artifacts,
                )
            ),
        )
        return result
    except BaseException as exc:
        durable_file(
            directory / "uncertain.json",
            canonical(dict(state="uncertain", reason=str(exc)[:2048])),
        )
        if not begin_possible:
            # This positive terminal record, not a missing job/marker or error
            # string, proves this invocation cannot now enter backupBegin.
            durable_file(
                directory / "prebegin-refusal.json",
                canonical(
                    dict(
                        schema="libvirt-prebegin-refusal/1",
                        request_sha256=sha(canonical(request)),
                        backup_id=request["backup_id"],
                        attempt_id=request["attempt_id"],
                        domain_uuid=request["domain_uuid"],
                        reason=str(exc)[:2048],
                    )
                ),
            )
        elif begin_bound and driver is not None:
            try:
                certificate = observe_failure_closure(
                    request, directory, driver, job_ids, identities, deadline, begin_ack
                )
                transcript = driver.transcript
                driver.close()
                driver = None
                # Recheck the continuous history after unsubscribing. Never
                # turn observer teardown failure/replacement into a certificate.
                events = certificate["terminal_events"]
                require(
                    events == transcript.closed_events(job_ids),
                    "failure closure changed",
                )
                durable_file(
                    directory / "producer-closed-failure.json", canonical(certificate)
                )
            except Exception:
                # Preserve the original failure and all output. Missing positive
                # closure means held; no guessed cancellation or disposal.
                pass
        raise
    finally:
        if driver is not None:
            driver.close()  # Unsubscribe only: NEVER abort a domain job.


def run_restore(request):
    """Offline fresh-disk restore. Members must come from an authorized catalog.

    Input images are never changed, and all backing paths are local staged files.
    Rebase changes metadata on the copies only; qcow2 zero extents override parent.
    """
    exact(request, ("members", "output_path"))
    verify_image_tool()
    members = request["members"]
    require(
        type(members) is list and 0 < len(members) <= 1024,
        "invalid restore chain length",
    )
    previous, seen = None, set()
    for item in members:
        exact(item, ("manifest", "manifest_sha256", "directory"))
        manifest = item["manifest"]
        validate_manifest(manifest)
        require(
            item["manifest_sha256"] == sha(canonical(manifest)),
            "member manifest digest mismatch",
        )
        require(manifest["backup_id"] not in seen, "duplicate chain member")
        seen.add(manifest["backup_id"])
        if previous is None:
            require(
                manifest["parent_backup_id"] is None,
                "restore chain must start with full",
            )
        else:
            require(
                manifest["parent_backup_id"] == previous["manifest"]["backup_id"]
                and manifest["parent_manifest_sha256"] == previous["manifest_sha256"],
                "wrong or reordered incremental parent",
            )
            for field in ("domain_uuid", "source", "exclusions"):
                require(
                    manifest[field] == previous["manifest"][field],
                    "restore source changed",
                )
            require(
                [d["virtual_size"] for d in manifest["disks"]]
                == [d["virtual_size"] for d in previous["manifest"]["disks"]],
                "restore disk size changed",
            )
        previous = item
    output = private_directory(request["output_path"])
    tops = {}
    for number, item in enumerate(members):
        directory = Path(item["directory"])
        require(
            directory.is_absolute()
            and str(directory.resolve(strict=True)) == str(directory),
            "restore input directory is not pinned",
        )
        for disk in item["manifest"]["disks"]:
            original = directory / disk["file"]
            # Copy via no-follow FD; hash the copy to bind bytes actually used,
            # not a pre-read which another process can replace before copying.
            staged = output / (str(number) + "-" + disk["file"])
            fd = os.open(original, os.O_RDONLY | os.O_NOFOLLOW)
            with os.fdopen(fd, "rb") as src, staged.open("xb") as dst:
                info = os.fstat(src.fileno())
                require(
                    stat.S_ISREG(info.st_mode)
                    and info.st_nlink == 1
                    and info.st_size == disk["size_bytes"],
                    "restore image identity changed",
                )
                shutil.copyfileobj(src, dst, 1024 * 1024)
            require(
                hash_file(staged) == (disk["size_bytes"], disk["sha256"]),
                "restore image checksum mismatch",
            )
            info = image_info(staged)
            require(
                not info.get("backing-filename")
                and info["virtual-size"] == disk["virtual_size"],
                "restore input has an untrusted backing/size",
            )
            if disk["target"] in tops:
                image_command(
                    "rebase",
                    "-u",
                    "-f",
                    "qcow2",
                    "-F",
                    "qcow2",
                    "-b",
                    str(tops[disk["target"]]),
                    str(staged),
                )
            tops[disk["target"]] = staged
    results = []
    for disk in members[-1]["manifest"]["disks"]:
        raw = output / (disk["target"] + ".raw")
        require(not raw.exists(), "restore output already exists")
        image_command(
            "convert", "-f", "qcow2", "-O", "raw", str(tops[disk["target"]]), str(raw)
        )
        count, digest = hash_file(raw)
        require(count == disk["virtual_size"], "restored virtual size mismatch")
        results.append(
            dict(target=disk["target"], path=str(raw), size_bytes=count, sha256=digest)
        )
    durable_file(output / "restored.json", canonical(results))
    return results


def main():
    body = sys.stdin.buffer.read(MAX_JSON + 1)
    require(len(body) <= MAX_JSON, "native request too large")

    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "duplicate JSON field")
            result[key] = value
        return result

    envelope = json.loads(body, object_pairs_hook=unique)
    exact(envelope, ("action", "request"))
    if envelope["action"] == "backup":
        result = run_backup(envelope["request"])
    elif envelope["action"] == "restore":
        result = run_restore(envelope["request"])
    else:
        raise Uncertain("unsupported native operation")
    sys.stdout.buffer.write(canonical(result))


if __name__ == "__main__":
    try:
        main()
    except BaseException as error:
        sys.stderr.write(
            "native attempt refused/uncertain: " + str(error)[:2048] + "\n"
        )
        sys.exit(1)
