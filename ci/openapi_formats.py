"""Deterministic offline JSON-to-YAML conversion; never fetch or refresh a spec."""

import argparse
import hashlib
import json
from pathlib import Path

import yaml


def yaml_bytes(document):
    encoded = yaml.safe_dump(
        document, allow_unicode=True, sort_keys=False, default_flow_style=False
    ).encode("utf-8")
    if yaml.safe_load(encoded) != document:
        raise ValueError("OpenAPI YAML conversion changed the document")
    return encoded


def convert(source, destination):
    source, destination = Path(source), Path(destination)
    original = source.read_bytes()
    document = json.loads(original)
    data = yaml_bytes(document)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("xb") as stream:
        stream.write(data)
    return {
        "kind": "YAML derived from retained OpenAPI JSON; not a live capture",
        "api_version": document.get("info", {}).get("version"),
        "source_commit": document.get("x-source-commit"),
        "source_sha256": hashlib.sha256(original).hexdigest(),
        "source_bytes": len(original),
        "yaml_sha256": hashlib.sha256(data).hexdigest(),
        "yaml_bytes": len(data),
        "semantic_equality": True,
        "yaml_library_version": yaml.__version__,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    print(json.dumps(convert(args.source, args.destination), indent=2, sort_keys=True))
