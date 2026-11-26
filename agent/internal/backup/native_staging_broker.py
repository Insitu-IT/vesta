"""Allocation-only local broker; never executes source paths or mutates libvirt.

Launch by the root operator with fixed staging/budget/peer configuration. No
remote listener, arbitrary filesystem path, fence/release action or shell API.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import signal
import stat
import struct
import sys

script_root = Path(__file__).resolve().parent
if __name__ == "__main__":
    if os.geteuid() != 0 or not sys.flags.isolated:
        raise SystemExit("Run the operator-installed broker as root with python3 -I")
    for path in (
        Path(__file__).resolve(),
        script_root,
        *script_root.parents,
        script_root / "libvirt_push.py",
        script_root / "native_write_fence.py",
        script_root / "native_staging_accounting.py",
    ):
        info = path.lstat()
        if info.st_uid != 0 or info.st_mode & 0o022 or stat.S_ISLNK(info.st_mode):
            raise SystemExit(
                "Broker code and ancestry must be root-owned and non-writable"
            )
sys.path.insert(0, str(script_root))
import libvirt_push as push
import native_write_fence as fence


def receive(stream, size):
    result = bytearray()
    while len(result) < size:
        chunk = stream.recv(size - len(result))
        if not chunk:
            raise fence.FenceRefused("incomplete staging frame")
        result.extend(chunk)
    return bytes(result)


def unique(pairs):
    result = {}
    for key, value in pairs:
        fence.require(key not in result, "duplicate staging field")
        result[key] = value
    return result


class Broker:
    def __init__(
        self, root, uid, gid, reserved_bytes, capacity_bytes, minimum_free_bytes
    ):
        fence.require(
            type(uid) is int and uid > 0 and type(gid) is int and gid >= 0,
            "invalid staging peer",
        )
        fence.require(
            all(
                type(n) is int and n > 0
                for n in (reserved_bytes, capacity_bytes, minimum_free_bytes)
            )
            and reserved_bytes <= capacity_bytes,
            "invalid staging budget",
        )
        self.root = Path(root)
        self.uid, self.gid = uid, gid
        self.reserved_bytes = reserved_bytes
        self.capacity_bytes = capacity_bytes
        self.minimum_free_bytes = minimum_free_bytes

    def allocate(self, request):
        push.validate_request(request)
        path = self.root / request["attempt_id"]
        fence.require(
            request["output_path"] == str(path), "staging path outside configured root"
        )
        try:
            allocation = fence.allocate_attempt(
                self.root,
                request,
                uid=self.uid,
                gid=self.gid,
                reserved_bytes=self.reserved_bytes,
                capacity_bytes=self.capacity_bytes,
                minimum_free_bytes=self.minimum_free_bytes,
            )
        except FileExistsError:
            # Lost allocation reply may replay only the same untouched slot.
            # An intent/data/partial attempt can never become producer replay.
            directory = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                fence.require(
                    os.listdir(directory) == ["allocation.json"],
                    "staging attempt already consumed",
                )
                fd = os.open(
                    "allocation.json",
                    os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                    dir_fd=directory,
                )
                with os.fdopen(fd, "rb") as stream:
                    info = os.fstat(stream.fileno())
                    fence.require(
                        stat.S_ISREG(info.st_mode)
                        and info.st_uid == 0
                        and info.st_nlink == 1
                        and info.st_mode & 0o222 == 0
                        and fence.flags(stream.fileno()) & fence.IMMUTABLE,
                        "untrusted existing allocation",
                    )
                    body = stream.read(push.MAX_JSON + 1)
                allocation = json.loads(body, object_pairs_hook=unique)
                info = os.fstat(directory)
                expected = {
                    "schema": "libvirt-staging-allocation/1",
                    "request_sha256": hashlib.sha256(
                        push.canonical(request)
                    ).hexdigest(),
                    "directory": fence.identity(info),
                    "uid": self.uid,
                    "gid": self.gid,
                    "reserved_bytes": self.reserved_bytes,
                }
                fence.require(
                    len(body) <= push.MAX_JSON
                    and body == push.canonical(expected)
                    and allocation == expected
                    and info.st_uid == self.uid
                    and info.st_gid == self.gid,
                    "existing allocation differs",
                )
                fd = os.open(
                    "allocation.json", os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory
                )
                try:
                    os.fsync(fd)
                    os.fsync(directory)
                finally:
                    os.close(fd)
                parent = os.open(
                    self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                )
                try:
                    os.fsync(parent)
                finally:
                    os.close(parent)
            finally:
                os.close(directory)
        return {
            "schema": "libvirt-staging-reply/1",
            "status": "allocated",
            "request_sha256": allocation["request_sha256"],
        }

    def handle(self, stream):
        stream.settimeout(5)
        _, uid, _ = struct.unpack(
            "3i", stream.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
        )
        fence.require(uid == self.uid, "unauthorized staging peer")
        size = struct.unpack("!I", receive(stream, 4))[0]
        fence.require(0 < size <= push.MAX_JSON, "oversized staging frame")
        envelope = json.loads(receive(stream, size), object_pairs_hook=unique)
        push.exact(envelope, ("action", "request"))
        fence.require(envelope["action"] == "allocate", "unsupported staging operation")
        result = push.canonical(self.allocate(envelope["request"]))
        stream.sendall(struct.pack("!I", len(result)) + result)


def serve(broker, socket_path):
    fence.require(os.geteuid() == 0, "staging broker requires root")
    path = Path(socket_path)
    fence.require(
        path.is_absolute()
        and str(path.parent.resolve(strict=True)) == str(path.parent),
        "unsafe staging socket path",
    )
    fence.root_managed_ancestry(path)
    fence.require_ext4_staging(broker.root)
    fence.root_managed_ancestry(broker.root / "slot")
    stream = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    bound = None
    try:
        stream.bind(str(path))  # Never unlink/adopt an existing listener.
        bound = path.lstat()
        os.chown(path, 0, broker.gid)
        os.chmod(path, 0o660)
        stream.listen(4)
        while True:
            client, _ = stream.accept()
            with client:
                try:
                    broker.handle(client)
                except (
                    OSError,
                    ValueError,
                    KeyError,
                    TypeError,
                    push.Uncertain,
                    fence.FenceRefused,
                ):
                    # No secret/request/source path in diagnostics or error frames.
                    pass
    finally:
        stream.close()
        if bound is not None:
            current = path.lstat()
            if stat.S_ISSOCK(current.st_mode) and fence.identity(
                current
            ) == fence.identity(bound):
                path.unlink()  # Only this broker's exact new socket inode.


if __name__ == "__main__":

    def stop(signum, frame):
        raise SystemExit(0)

    signal.signal(signal.SIGTERM, stop)
    parser = argparse.ArgumentParser()
    for name in ("root", "socket"):
        parser.add_argument("--" + name, required=True)
    for name in (
        "uid",
        "gid",
        "reserved-bytes",
        "capacity-bytes",
        "minimum-free-bytes",
    ):
        parser.add_argument("--" + name, type=int, required=True)
    args = parser.parse_args()
    serve(
        Broker(
            args.root,
            args.uid,
            args.gid,
            args.reserved_bytes,
            args.capacity_bytes,
            args.minimum_free_bytes,
        ),
        args.socket,
    )
