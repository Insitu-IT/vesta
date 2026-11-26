"""Experimental operator-only failed-output fence; no libvirt or settlement.

Requires the original producer to be fenced first. The caller retains this
result outside the attempt directory, which becomes immutable. Partial failure
intentionally leaves established fences intact and grants no release authority.
Only read-only receipt inspection is dispatched by the agent. Enrollment and
immutable flag changes require the separate root operator; no agent privilege.
"""

import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import struct
import sys
import uuid

ENABLE_VERITY = 0x40806685
MEASURE_VERITY = 0xC0046686
GET_FLAGS = 0x80086601
SET_FLAGS = 0x40086602
IMMUTABLE = 0x10
MAX_JSON = 4 * 1024 * 1024


class FenceRefused(Exception):
    """Keep custody and any partial fence; never interpret this as closure."""


def require(value, message):
    if not value:
        raise FenceRefused(message)


def canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()


def identity(info):
    return [info.st_dev, info.st_ino]


def read_record(directory, name, *, shared_receipt=False):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        require(
            stat.S_ISREG(info.st_mode)
            and info.st_nlink == 1
            and (
                (info.st_uid == 0 and info.st_mode & 0o037 == 0)
                if shared_receipt
                else info.st_mode & 0o077 == 0
            ),
            "non-private recovery record",
        )
        body = stream.read(MAX_JSON + 1)
    require(len(body) <= MAX_JSON, "oversized recovery record")
    value = json.loads(body)
    require(canonical(value) == body, "noncanonical recovery record")
    return value, body


def flags(fd, value=None):
    body = bytearray(8)
    if value is None:
        fcntl.ioctl(fd, GET_FLAGS, body, True)
        return struct.unpack_from("<I", body)[0]
    struct.pack_into("<I", body, 0, value)
    fcntl.ioctl(fd, SET_FLAGS, body)


def make_immutable(fd):
    current = flags(fd)
    if not current & IMMUTABLE:
        flags(fd, current | IMMUTABLE)
    os.fsync(fd)
    require(flags(fd) & IMMUTABLE, "immutable flag not established")


def verity_digest(fd):
    body = bytearray(struct.pack("<HH", 0, 32) + bytes(32))
    fcntl.ioctl(fd, MEASURE_VERITY, body, True)
    algorithm, length = struct.unpack_from("<HH", body)
    require(algorithm == 1 and length == 32, "unexpected fs-verity digest")
    return body[4:].hex()


def enable_verity(fd):
    try:
        existing = verity_digest(fd)
    except OSError as error:
        if error.errno != errno.ENODATA:
            raise
    else:
        return existing
    argument = struct.pack("<IIIIQIIQ11Q", 1, 1, 4096, 0, 0, 0, 0, 0, *([0] * 11))
    fcntl.ioctl(fd, ENABLE_VERITY, argument)
    os.fsync(fd)
    return verity_digest(fd)


def root_managed_ancestry(path):
    for parent in path.parents:
        info = parent.lstat()
        require(
            stat.S_ISDIR(info.st_mode)
            and info.st_uid == 0
            and info.st_mode & 0o022 == 0,
            "staging ancestry is not root-managed",
        )


def allocate_attempt(
    root, request, *, uid, gid, reserved_bytes, capacity_bytes, minimum_free_bytes
):
    """Root operator allocates one request-bound slot; no daemon or agent privilege.

    The root must already exist on the dedicated staging filesystem. Immutable
    root-issued records account for reserved capacity, including failed/partial
    allocations. No reservation is silently reclaimed from age or file absence.
    """
    require(os.geteuid() == 0, "allocation requires the root operator")
    require(
        type(uid) is int and uid > 0 and type(gid) is int and gid >= 0,
        "invalid agent identity",
    )
    require(
        all(
            type(n) is int and n > 0
            for n in (reserved_bytes, capacity_bytes, minimum_free_bytes)
        ),
        "invalid staging capacity",
    )
    root = Path(root)
    require(
        root.is_absolute() and str(root.resolve(strict=True)) == str(root),
        "unsafe staging root",
    )
    root_managed_ancestry(root / "slot")
    require_ext4_staging(root)
    attempt_id = request["attempt_id"]
    require(str(uuid.UUID(attempt_id)) == attempt_id, "invalid attempt identity")
    target = root / attempt_id
    require(
        request["output_path"] == str(target), "allocation path differs from request"
    )
    lock = os.open(
        root / ".allocation-lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600
    )
    try:
        info = os.fstat(lock)
        require(
            stat.S_ISREG(info.st_mode)
            and info.st_uid == 0
            and info.st_nlink == 1
            and info.st_mode & 0o077 == 0,
            "unsafe allocation lock",
        )
        fcntl.flock(lock, fcntl.LOCK_EX)
        total = 0
        for child in root.iterdir():
            if child.name == ".allocation-lock":
                continue
            require(
                child.is_dir() and not child.is_symlink(), "unaccounted staging entry"
            )
            directory = os.open(child, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                fd = os.open(
                    "allocation.json",
                    os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                    dir_fd=directory,
                )
                try:
                    record = os.fstat(fd)
                    require(
                        stat.S_ISREG(record.st_mode)
                        and record.st_uid == 0
                        and record.st_nlink == 1
                        and record.st_mode & 0o222 == 0
                        and flags(fd) & IMMUTABLE,
                        "untrusted staging reservation",
                    )
                    body = os.read(fd, MAX_JSON + 1)
                    value = json.loads(body)
                    require(
                        len(body) <= MAX_JSON
                        and canonical(value) == body
                        and value["schema"] == "libvirt-staging-allocation/1"
                        and value["directory"] == identity(os.fstat(directory))
                        and type(value["reserved_bytes"]) is int
                        and value["reserved_bytes"] > 0,
                        "invalid staging reservation",
                    )
                    from native_staging_accounting import retire_reclaimed

                    if not retire_reclaimed(directory, value, body):
                        total += value["reserved_bytes"]
                finally:
                    os.close(fd)
            finally:
                os.close(directory)
        free = os.statvfs(root)
        require(
            total + reserved_bytes <= capacity_bytes
            and free.f_bavail * free.f_frsize >= reserved_bytes + minimum_free_bytes,
            "staging capacity exhausted",
        )
        target.mkdir(mode=0o711)  # Exclusive; a retry never adopts an existing slot.
        os.chmod(target, 0o711)
        directory = os.open(target, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            allocation = {
                "schema": "libvirt-staging-allocation/1",
                "request_sha256": hashlib.sha256(canonical(request)).hexdigest(),
                "directory": identity(os.fstat(directory)),
                "uid": uid,
                "gid": gid,
                "reserved_bytes": reserved_bytes,
            }
            fd = os.open(
                "allocation.json",
                os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW,
                0o400,
                dir_fd=directory,
            )
            with os.fdopen(fd, "wb") as stream:
                stream.write(canonical(allocation))
                stream.flush()
                os.fsync(stream.fileno())
            fd = os.open(
                "allocation.json", os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory
            )
            try:
                os.fchmod(fd, 0o444)
                make_immutable(fd)
            finally:
                os.close(fd)
            os.fchown(directory, uid, gid)
            os.fsync(directory)
            os.fsync(lock)
            parent = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(parent)
            finally:
                os.close(parent)
            return allocation
        finally:
            os.close(directory)
    finally:
        os.close(lock)


def require_ext4_staging(root):
    mounts = []
    for line in Path("/proc/self/mountinfo").read_text().splitlines():
        before, after = line.split(" - ", 1)
        fields = before.split()
        mount = fields[4]
        for encoded, decoded in (
            ("\\040", " "),
            ("\\011", "\t"),
            ("\\012", "\n"),
            ("\\134", "\\"),
        ):
            mount = mount.replace(encoded, decoded)
        if root.is_relative_to(Path(mount)):
            mounts.append((len(mount), after.split()[0], set(fields[5].split(","))))
    require(bool(mounts), "staging mount is unknown")
    _, filesystem, options = max(mounts)
    require(
        filesystem == "ext4" and {"rw", "nosuid", "nodev", "noexec"} <= options,
        "dedicated ext4 staging mount options missing",
    )


def fence_attempt(request, *, producer_fenced=False, read_only=False):
    """Fence only original output inodes, never infer or certify backup success.

    An existing writable descriptor causes verity enrollment to fail. A reused
    pathname, absent pre-begin binding, seal, upload admission or prior positive
    closure also refuses. No flag is ever cleared and no file is deleted.
    """
    require(
        producer_fenced is True,
        "original producer must be independently fenced",
    )
    require(
        sys.platform == "linux" and os.uname().machine == "x86_64",
        "unsupported fence ABI",
    )
    path = Path(request["output_path"])
    require(
        path.is_absolute() and str(path.resolve(strict=True)) == str(path),
        "unsafe attempt path",
    )
    # Freezing the attempt does not protect a mutable ancestor: renaming a
    # parent could let a delayed RPC reopen the original absolute path on a
    # different inode. Only a root-managed, non-writable staging ancestry is
    # accepted by this experimental operator primitive.
    root_managed_ancestry(path)
    descriptors = []
    try:
        attempt = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        descriptors.append(attempt)
        original, intent = read_record(attempt, "intent.json")
        require(original == request, "original request differs")
        binding, body = read_record(attempt, "target-binding.json")
        require(
            set(binding)
            == {
                "schema",
                "request_sha256",
                "directory",
                "data_directory",
                "backup_xml_sha256",
                "checkpoint_xml_sha256",
                "targets",
            }
            and binding["schema"] == "libvirt-target-binding/1"
            and binding["request_sha256"] == hashlib.sha256(intent).hexdigest()
            and binding["directory"] == identity(os.fstat(attempt)),
            "original target binding differs",
        )
        for name in (
            "producer-sealed.json",
            "producer-closed-failure.json",
            "prebegin-refusal.json",
            "admission.json",
            "published.json",
        ):
            try:
                os.stat(name, dir_fd=attempt, follow_symlinks=False)
            except FileNotFoundError:
                continue
            raise FenceRefused("contradictory producer state")
        begin, _ = read_record(attempt, "begin-intent.json")
        require(
            begin
            == {
                "schema": "libvirt-begin-intent/1",
                "request_sha256": binding["request_sha256"],
            },
            "missing original begin boundary",
        )
        selected = sorted(
            d["target"]
            for d in request["disks"]
            if d["target"] not in request["exclusions"]
        )
        require(
            selected and set(binding["targets"]) == set(selected),
            "target set differs",
        )
        require(
            all(t and "/" not in t and t not in {".", ".."} for t in selected),
            "unsafe target",
        )
        data = os.open(
            "data", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=attempt
        )
        descriptors.append(data)
        require(
            identity(os.fstat(data)) == binding["data_directory"],
            "data directory replaced",
        )
        files = []
        for target in selected:
            fd = os.open(
                target + ".qcow2",
                os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                dir_fd=data,
            )
            descriptors.append(fd)
            info = os.fstat(fd)
            require(
                stat.S_ISREG(info.st_mode)
                and info.st_nlink == 1
                and identity(info) == binding["targets"][target],
                "original target replaced",
            )
            files.append((target, fd))

        # Freeze pathname containers BEFORE enrolling files. Immutable files
        # and directories prevent delayed reopen from finding replacement data.
        def protect(fd):
            if read_only:
                require(flags(fd) & IMMUTABLE, "immutable fence missing")
            else:
                make_immutable(fd)

        protect(attempt)
        protect(data)
        require(
            identity(os.stat(path, follow_symlinks=False)) == binding["directory"],
            "attempt moved",
        )
        require(
            identity(os.stat("data", dir_fd=attempt, follow_symlinks=False))
            == binding["data_directory"],
            "data directory moved",
        )
        artifacts = []
        for target, fd in files:
            digest = verity_digest(fd) if read_only else enable_verity(fd)
            protect(fd)
            info = os.fstat(fd)
            require(
                identity(info) == binding["targets"][target]
                and identity(
                    os.stat(target + ".qcow2", dir_fd=data, follow_symlinks=False)
                )
                == identity(info),
                "target moved during fence",
            )
            artifacts.append(
                {
                    "target": target,
                    "device": info.st_dev,
                    "inode": info.st_ino,
                    "size": info.st_size,
                    "verity_sha256": digest,
                }
            )
        return {
            "schema": "libvirt-failed-output-fence/1",
            "request_sha256": binding["request_sha256"],
            "target_binding_sha256": hashlib.sha256(body).hexdigest(),
            "artifacts": artifacts,
            "directory": binding["directory"],
            "data_directory": binding["data_directory"],
        }
    finally:
        for fd in reversed(descriptors):
            os.close(fd)


def inspect_fence(request):
    """Read current kernel fences without enrollment, flag changes or privileges."""
    return fence_attempt(request, producer_fenced=True, read_only=True)


def save_fence_receipt(
    receipt_root, request, *, producer_fenced=False, reader_gid=None
):
    """Root operator retains failed-only evidence outside the immutable attempt.

    Exact replay rechecks current kernel protection and returns the same receipt.
    Partial/corrupt existing receipts are held, never overwritten or discarded.
    """
    require(os.geteuid() == 0, "receipt persistence requires the root operator")
    require(
        reader_gid is None or (type(reader_gid) is int and 0 < reader_gid < 2**32),
        "invalid receipt reader group",
    )
    receipt_root = Path(receipt_root)
    require(
        receipt_root.is_absolute()
        and str(receipt_root.resolve(strict=True)) == str(receipt_root),
        "unsafe receipt root",
    )
    root_managed_ancestry(receipt_root / "receipt")
    attempt = Path(request["output_path"])
    require(
        not receipt_root.is_relative_to(attempt.parent),
        "receipt must be outside staging allocations",
    )
    aid = request["attempt_id"]
    require(str(uuid.UUID(aid)) == aid, "invalid receipt identity")
    directory = os.open(receipt_root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    name = aid + ".json"
    try:
        try:
            existing, _ = read_record(directory, name, shared_receipt=True)
            info = os.stat(name, dir_fd=directory, follow_symlinks=False)
            require(
                reader_gid is None
                and info.st_mode & 0o077 == 0
                or reader_gid is not None
                and info.st_gid == reader_gid
                and info.st_mode & 0o777 == 0o640,
                "existing receipt reader differs",
            )
        except FileNotFoundError:
            existing = None
        if existing is None:
            proof = fence_attempt(request, producer_fenced=producer_fenced)
        else:
            proof = inspect_fence(request)
        envelope = {
            "schema": "libvirt-fence-receipt/1",
            "proof": proof,
            "proof_sha256": hashlib.sha256(canonical(proof)).hexdigest(),
        }
        if existing is not None:
            require(
                existing == envelope,
                "persisted fence differs from current kernel evidence",
            )
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory)
            try:
                os.fsync(fd)
                os.fsync(directory)
            finally:
                os.close(fd)
            return existing
        fd = os.open(
            name,
            os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW,
            0o600,
            dir_fd=directory,
        )
        with os.fdopen(fd, "wb") as stream:
            stream.write(canonical(envelope))
            stream.flush()
            if reader_gid is not None:
                os.fchown(stream.fileno(), 0, reader_gid)
                os.fchmod(stream.fileno(), 0o640)
            os.fsync(stream.fileno())
        os.fsync(directory)
        saved, _ = read_record(directory, name, shared_receipt=True)
        require(
            saved == envelope and inspect_fence(request) == proof,
            "fence changed while saving receipt",
        )
        return saved
    finally:
        os.close(directory)


def read_fence_receipt(receipt_root, request):
    """Unprivileged read-only consumption, with current kernel reinspection."""
    receipt_root = Path(receipt_root)
    attempt = Path(request["output_path"])
    require(
        receipt_root.is_absolute()
        and str(receipt_root.resolve(strict=True)) == str(receipt_root)
        and not receipt_root.is_relative_to(attempt.parent),
        "unsafe receipt root",
    )
    root_managed_ancestry(receipt_root / "receipt")
    aid = request["attempt_id"]
    require(str(uuid.UUID(aid)) == aid, "invalid receipt identity")
    directory = os.open(receipt_root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        try:
            envelope, body = read_record(directory, aid + ".json", shared_receipt=True)
        except FileNotFoundError:
            return None
        proof = inspect_fence(request)
        require(
            envelope
            == {
                "schema": "libvirt-fence-receipt/1",
                "proof": proof,
                "proof_sha256": hashlib.sha256(canonical(proof)).hexdigest(),
            },
            "receipt differs from current kernel fence",
        )
        fd = os.open(aid + ".json", os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        os.fsync(directory)
        saved, current = read_record(directory, aid + ".json", shared_receipt=True)
        require(
            current == body and saved == envelope, "receipt changed during consumption"
        )
        return proof
    finally:
        os.close(directory)
