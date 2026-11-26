#!/usr/bin/env python3
"""Prepare an immutable local public-key ConfigMap; never contacts an issuer."""

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

sys.dont_write_bytecode = True
KEY_ID = r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}"
NAME = r"[a-z0-9](?:[-a-z0-9]*[a-z0-9])?"
MAX_BYTES = 65536


def no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate public-key manifest field")
        result[key] = value
    return result


def read_manifest(path):
    """Bound input and reject symlinks/nonregular files without following them."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_BYTES:
            raise ValueError(
                "Public-key manifest must be a regular file up to 65536 bytes"
            )
        data = stream.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError("Public-key manifest exceeds 65536 bytes")
    return validate_manifest(json.loads(data, object_pairs_hook=no_duplicates))


def validate_manifest(value):
    if (
        type(value) is not dict
        or set(value) != {"schema_version", "keys"}
        or type(value["schema_version"]) is not int
        or value["schema_version"] != 1
    ):
        raise ValueError("Use public-key manifest schema_version 1 with keys only")
    keys = value["keys"]
    if type(keys) is not dict or not 1 <= len(keys) <= 64:
        raise ValueError("Provide 1 to 64 explicitly approved public keys")
    for key_id, encoded in keys.items():
        if (
            not isinstance(key_id, str)
            or not re.fullmatch(KEY_ID, key_id)
            or not isinstance(encoded, str)
        ):
            raise ValueError("Invalid public signing key ID or encoding")
        try:
            raw = base64.b64decode(encoded, validate=True)
        except (ValueError, TypeError):
            raise ValueError("Public keys require canonical base64") from None
        if len(raw) != 32 or base64.b64encode(raw).decode("ascii") != encoded:
            raise ValueError(
                "Public keys require canonical base64 of 32 Ed25519 public bytes"
            )
    return value


def prepare(manifest, namespace, resource_prefix="vesta"):
    if type(resource_prefix) is not str or resource_prefix not in {"vesta", "vnbui"}:
        raise ValueError("resource_prefix must be vesta or vnbui")
    validate_manifest(manifest)
    if (
        not isinstance(namespace, str)
        or len(namespace) > 63
        or not re.fullmatch(NAME, namespace)
    ):
        raise ValueError("Use an explicit valid application namespace")
    content = json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n"
    name = resource_prefix + "-license-keys-" + hashlib.sha256(content.encode()).hexdigest()[:20]
    resource = {
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {"name": name, "namespace": namespace},
        "immutable": True,
        "data": {"license-keys.json": content},
    }
    return resource, {"config_map": name}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--public-keys", required=True, help="approved local public-key manifest"
    )
    parser.add_argument("--namespace", required=True)
    parser.add_argument("--resource-prefix", choices=("vesta", "vnbui"), default="vesta")
    parser.add_argument(
        "--out", required=True, help="new output directory; never overwritten"
    )
    args = parser.parse_args(argv)
    resource, projection = prepare(read_manifest(args.public_keys), args.namespace, args.resource_prefix)
    destination = Path(args.out)
    destination.mkdir(mode=0o700)
    for name, value in (("configmap.json", resource), ("projection.json", projection)):
        with (destination / name).open("x") as stream:
            json.dump(value, stream, sort_keys=True, indent=2)
            stream.write("\n")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError) as error:
        print("Public-key preparation refused: " + str(error), file=sys.stderr)
        raise SystemExit(1)
