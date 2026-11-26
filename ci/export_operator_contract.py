"""Export an explicit HTTP module profile offline, bound to source content.

No ASGI lifespan runs. Engine connections, outbound sockets and scheduler starts
are forbidden during import/schema generation. A dirty export is explicitly DRAFT.
"""

import argparse
from contextlib import ExitStack
from datetime import datetime, timezone
import hashlib
from importlib import import_module
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
from openapi_formats import yaml_bytes

ROOT = Path(__file__).resolve().parents[1]


def git(*args):
    return subprocess.check_output(["git", "-C", str(ROOT), *args], text=True).strip()


def canonical(value):
    return (
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    ).encode()


def no_network(*args, **kwargs):
    raise RuntimeError(
        "Operator schema export cannot open database/network connections or start schedulers"
    )


def validate_auth_descriptions(document):
    """Do not publish a schema whose mounted HTTP topology was skipped."""
    methods = {"get", "put", "post", "patch", "delete", "head", "options", "trace"}
    missing = [
        f"{method.upper()} {path}"
        for path, operations in document.get("paths", {}).items()
        for method, operation in operations.items()
        if method in methods and "x-credential-domain" not in operation
    ]
    if missing:
        raise ValueError("Schema omitted credential domains: " + ", ".join(missing))


def generate_schema(profile_name="community"):
    if "app" in sys.modules:
        raise RuntimeError(
            "Run the offline exporter in a fresh process before importing the application"
        )
    from apscheduler.schedulers.background import BackgroundScheduler
    from sqlalchemy.engine import Engine

    if profile_name not in {"community", "commercial-all"}:
        raise ValueError("Unknown schema export profile")
    commercial = profile_name == "commercial-all"
    modules = ["multi_tenancy", "billing_api", "white_labeling"] if commercial else []
    # Installed-module topology is explicit. Schema inspection must never run
    # the lifespan, migrations, reconciliation or customer startup routines.
    profile = {
        "VNBUI_ARTIFACT_EDITION": "commercial" if commercial else "community",
        "VNBUI_EDITION": "commercial" if commercial else "community",
        "VNBUI_AUTH_MODE": (
            "multi_organization" if commercial else "single_organization"
        ),
        "VNBUI_ENABLED_MODULES": json.dumps(modules),
        "DEMO_MODE": "false",
    }
    # This script can run outside the checkout with only backend/agent on
    # PYTHONPATH. Optional modules live under the repository root.
    sys.path.insert(0, str(ROOT))
    sys.path.insert(0, str(ROOT / "backend"))
    with ExitStack() as stack:
        stack.enter_context(patch.dict(os.environ, profile))
        stack.enter_context(patch.object(socket.socket, "connect", no_network))
        stack.enter_context(patch.object(socket.socket, "connect_ex", no_network))
        stack.enter_context(patch.object(Engine, "connect", no_network))
        stack.enter_context(patch.object(BackgroundScheduler, "start", no_network))
        from app import app, features

        if commercial:
            from core.commercial import load_commercial_modules

            loaded = load_commercial_modules(app, features)
            if set(loaded) != set(modules):
                raise ValueError("Schema export omitted configured commercial modules")
            app.openapi_schema = None

        document = app.openapi()
        document["x-installed-profile"] = features.profile.public()
        validate_auth_descriptions(document)
        return document


def export(output, *, allow_dirty=False, profile="community"):
    commit = git("rev-parse", "HEAD")
    status = git("status", "--porcelain", "--untracked-files=normal")
    dirty = bool(status)
    if dirty and not allow_dirty:
        raise ValueError(
            "Refusing a commit-bound export from dirty source; use --allow-dirty for an explicitly DRAFT local export"
        )
    expected = os.environ.get("CI_COMMIT_SHA")
    if expected and expected != commit:
        raise ValueError("CI commit and checked-out source commit differ")
    source_digest = hashlib.sha256(commit.encode())
    source_digest.update(
        git(
            "diff",
            "HEAD",
            "--binary",
            "--",
            "backend",
            "commercial/backend",
            "ci",
            "tests/fixtures/operator-contract",
        ).encode()
    )
    for name in sorted(
        git("ls-files", "--others", "--exclude-standard", "-z").split("\0")
    ):
        if not name.startswith(
            (
                "backend/",
                "commercial/backend/",
                "ci/",
                "tests/fixtures/operator-contract/",
            )
        ):
            continue
        path = ROOT / name
        if path.is_file():
            source_digest.update(name.encode())
            source_digest.update(hashlib.sha256(path.read_bytes()).digest())
    schema = generate_schema() if profile == "community" else generate_schema(profile)
    schema["x-source-commit"] = commit
    schema["x-source-tree-clean"] = not dirty
    schema["x-contract-export-kind"] = (
        "offline-source-schema; not observed live wire compatibility"
    )
    data = canonical(schema)
    digest = hashlib.sha256(data).hexdigest()
    yaml_data = yaml_bytes(json.loads(data))
    yaml_digest = hashlib.sha256(yaml_data).hexdigest()
    output = Path(output)
    # Existing output must never be silently overwritten under the same name.
    output.mkdir(parents=True, exist_ok=True)
    provenance = {
        "schema_version": 1,
        "framework_versions": {
            name: import_module(name).__version__
            for name in ("fastapi", "starlette", "pydantic")
        },
        "first_public_version": schema.get("x-operator-first-support", {}).get("version"),
        "support_status": "DRAFT",
        "api_version": schema["info"]["version"],
        "source_commit": commit,
        "source_tree_clean": not dirty,
        "source_snapshot_sha256": source_digest.hexdigest(),
        "source_status_sha256": hashlib.sha256(status.encode()).hexdigest(),
        "schema_sha256": digest,
        "schema_bytes": len(data),
        "yaml_sha256": yaml_digest,
        "yaml_bytes": len(yaml_data),
        "yaml_derivation": "Lossless offline conversion of openapi.json; semantic equality checked",
        "profile": (
            "commercial/multi_organization/all-modules"
            if profile == "commercial-all"
            else "community/single_organization"
        ),
        "installed_profile": schema.get("x-installed-profile"),
        "agent_transport_require_mtls": os.getenv("REQUIRE_MTLS", "false").lower()
        == "true",
        "export_kind": schema["x-contract-export-kind"],
        "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "ci_pipeline_id": os.environ.get("CI_PIPELINE_ID"),
        "ci_job_id": os.environ.get("CI_JOB_ID"),
        "untyped_successful_operations": schema["x-response-schema-inventory"][
            "untyped_count"
        ],
    }
    payloads = {
        "openapi.json": data,
        "openapi.yaml": yaml_data,
        "provenance.json": canonical(provenance),
        "response-schema-inventory.json": canonical(
            schema["x-response-schema-inventory"]
        ),
        "openapi.sha256": f"{digest}  openapi.json\n".encode(),
        "openapi.yaml.sha256": f"{yaml_digest}  openapi.yaml\n".encode(),
    }
    for name in payloads:
        if (output / name).exists():
            raise ValueError(
                f"Export destination already contains {name}; choose a new source-specific destination"
            )
    for name, payload in payloads.items():
        with (output / name).open("xb") as stream:
            stream.write(payload)
    return provenance


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--allow-dirty", action="store_true")
    parser.add_argument(
        "--profile", choices=("community", "commercial-all"), default="community"
    )
    args = parser.parse_args()
    result = export(args.output_dir, allow_dirty=args.allow_dirty, profile=args.profile)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
