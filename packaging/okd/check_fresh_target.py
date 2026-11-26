#!/usr/bin/env python3
"""Refuse a portable fresh install that would collide with existing resources.

This is a read-only pre-apply guard, not an upgrade or an atomic namespace lock.
Customer namespaces and plain/customer-managed Secrets may already exist.
"""

import argparse
import json
from pathlib import Path
import subprocess
import sys

# The transferred release is checksum-inventoried. Importing its renderer must
# not add an unmanifested __pycache__ file before a later verify.
sys.dont_write_bytecode = True
from render import STAGES, render


def planned_resources(config, postgres_config=None):
    result = {}
    for stage in STAGES:
        for item in render(config, stage)["items"]:
            ns = item["metadata"]["namespace"]
            ref = item["kind"].lower() + "/" + item["metadata"]["name"]
            result.setdefault(ns, set()).add(ref)
    if postgres_config is not None:
        from postgres import render as render_postgres

        for item in render_postgres(config, postgres_config)["items"]:
            ns = item["metadata"]["namespace"]
            ref = item["kind"].lower() + "/" + item["metadata"]["name"]
            result.setdefault(ns, set()).add(ref)
    return {ns: sorted(refs) for ns, refs in result.items()}


def run(config, oc, postgres_config=None):
    planned = planned_resources(config, postgres_config)
    for namespace, refs in planned.items():
        subprocess.run(
            [oc, "get", "namespace", namespace, "-o", "name"],
            check=True,
            capture_output=True,
            text=True,
        )
        # A single get per namespace checks every product-owned object name.
        # Precreated Secrets are intentionally not on this list.
        found = subprocess.run(
            [oc, "-n", namespace, "get", *refs, "--ignore-not-found", "-o", "name"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.splitlines()
        if found:
            print(f"{namespace}: COLLISION ({len(found)} product resources)")
            for ref in found:
                print(f"  {ref}")
            return 2
        print(f"{namespace}: NO_PRODUCT_COLLISIONS ({len(refs)} names checked)")
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--oc", default="oc")
    parser.add_argument("--postgres-config", type=Path)
    args = parser.parse_args()
    try:
        return run(
            json.loads(args.config.read_text()),
            args.oc,
            (
                json.loads(args.postgres_config.read_text())
                if args.postgres_config
                else None
            ),
        )
    except (subprocess.CalledProcessError, ValueError, KeyError, TypeError, OSError):
        print(
            "FRESH_TARGET_CHECK_FAILED; verify namespace access and config",
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    sys.exit(main())
