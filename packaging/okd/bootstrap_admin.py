#!/usr/bin/env python3
"""Generate a private initial-admin Secret input, or print installation access details."""
import argparse
import json
import os
from pathlib import Path
import secrets
import shlex
import string
import sys
sys.dont_write_bytecode = True
from render import validate


def generate(config, output):
    validate(config)
    # Every generated value contains each class accepted by the backend policy.
    password = "Aa1!" + "".join(secrets.choice(string.ascii_letters + string.digits + "!@#$%") for _ in range(28))
    value = {"apiVersion": "v1", "kind": "Secret", "metadata": {"name": config["secrets"]["admin"], "namespace": config["namespace"]}, "type": "Opaque", "stringData": {"password": password}}
    fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as stream:
        json.dump(value, stream, indent=2)


def report(config):
    validate(config)
    print("URL: https://" + config["ui_host"])
    print("Username: " + config["admin_username"])
    print("Retrieve initial password privately (existing administrators are preserved):")
    print("oc -n " + shlex.quote(config["namespace"]) + " get secret " + shlex.quote(config["secrets"]["admin"]) + " -o jsonpath='{.data.password}' | base64 --decode")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("generate", "report"))
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.action == "generate" and not args.output:
        parser.error("generate requires a new private --output file")
    config = json.loads(args.config.read_text())
    if args.action == "generate":
        generate(config, args.output)
        print("Private initial-admin Secret input created; apply it only for fresh bootstrap.")
    else:
        report(config)

if __name__ == "__main__":
    main()
