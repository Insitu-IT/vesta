"""Root-operated exact-attempt fence; never touches a VM or clears flags."""

import argparse
import os
from pathlib import Path
import stat
import sys

script_root = Path(__file__).resolve().parent
if __name__ == "__main__":
    if os.geteuid() != 0 or not sys.flags.isolated:
        raise SystemExit("Run the installed operator tool as root with python3 -I")
    for path in (
        Path(__file__).resolve(),
        script_root,
        *script_root.parents,
        script_root / "libvirt_push.py",
        script_root / "native_write_fence.py",
    ):
        info = path.lstat()
        if info.st_uid != 0 or info.st_mode & 0o022 or stat.S_ISLNK(info.st_mode):
            raise SystemExit(
                "Operator code and ancestry must be root-owned and non-writable"
            )
sys.path.insert(0, str(script_root))
import libvirt_push as push
import native_write_fence as fence


def operate(root, request_path, *, action, producer_fenced=False, reader_gid=None):
    fence.require(os.geteuid() == 0, "root operator required")
    root, request_path = Path(root), Path(request_path)
    fence.require(
        root.is_absolute() and str(root.resolve(strict=True)) == str(root),
        "unsafe staging root",
    )
    fence.root_managed_ancestry(root / "slot")
    fence.require_ext4_staging(root)
    fence.require(
        request_path.is_absolute()
        and str(request_path.resolve(strict=True)) == str(request_path),
        "unsafe original request",
    )
    directory = os.open(
        request_path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    )
    try:
        request, _ = fence.read_record(directory, request_path.name)
    finally:
        os.close(directory)
    push.validate_request(request)
    fence.require(
        request_path == root / request["attempt_id"] / "intent.json"
        and request["output_path"] == str(request_path.parent),
        "request outside configured attempt",
    )
    receipts = root.parent / "fence-receipts"
    if action == "inspect":
        proof = fence.read_fence_receipt(receipts, request)
        fence.require(proof is not None, "no original fence receipt")
        return proof
    fence.require(
        action == "fence" and producer_fenced is True,
        "independent original producer fencing required",
    )
    fence.require(
        type(reader_gid) is int and reader_gid > 0,
        "explicit agent reader group required",
    )
    return fence.save_fence_receipt(
        receipts, request, producer_fenced=True, reader_gid=reader_gid
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("inspect", "fence"))
    parser.add_argument("--root", required=True)
    parser.add_argument("--request", required=True)
    parser.add_argument("--reader-gid", type=int)
    parser.add_argument("--producer-fenced", action="store_true")
    args = parser.parse_args()
    print(
        fence.canonical(
            operate(
                args.root,
                args.request,
                action=args.action,
                producer_fenced=args.producer_fenced,
                reader_gid=args.reader_gid,
            )
        ).decode()
    )
