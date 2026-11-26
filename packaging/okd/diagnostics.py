#!/usr/bin/env python3
"""Bounded, read-only installation observations; never logs, Secrets or repairs."""

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import selectors
import subprocess
import sys
import time

sys.dont_write_bytecode = True
from render import validate, resource_prefix, agent_scope  # noqa: E402

MAX_BYTES = 2 * 1024 * 1024
MAX_ROWS = 50


def query(argv, timeout=25, max_bytes=MAX_BYTES):
    """Bound bytes while reading, not after unbounded communicate()."""
    with subprocess.Popen(
        argv, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL
    ) as proc:
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(proc.stdout, selectors.EVENT_READ)
                deadline, chunks, length = time.monotonic() + timeout, [], 0
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise ValueError("timeout")
                    if not selector.select(remaining):
                        raise ValueError("timeout")
                    chunk = os.read(proc.stdout.fileno(), 65536)
                    if not chunk:
                        break
                    length += len(chunk)
                    if length > max_bytes:
                        raise ValueError("response limit")
                    chunks.append(chunk)
                if proc.wait(timeout=max(0.01, deadline - time.monotonic())) != 0:
                    raise ValueError("query failed")
            return json.loads(b"".join(chunks))
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait()


def project(resource, item):
    """No annotations, labels, env, arguments, URLs, messages or raw errors."""
    metadata, status, spec = (
        item.get(key, {}) for key in ("metadata", "status", "spec")
    )
    row = {key: metadata.get(key) for key in ("name", "uid", "creationTimestamp")}
    if resource in {"deployments", "statefulsets"}:
        row.update(
            {
                key: status.get(key)
                for key in (
                    "observedGeneration",
                    "replicas",
                    "readyReplicas",
                    "availableReplicas",
                )
            }
        )
        row["desiredReplicas"] = spec.get("replicas")
        row["generation"] = metadata.get("generation")
    elif resource == "pods":
        row["phase"] = status.get("phase")
        row["containers"] = [
            {
                "name": state.get("name"),
                "ready": state.get("ready"),
                "restartCount": state.get("restartCount"),
                "state": next(iter(state.get("state", {})), None),
                "exitCode": state.get("state", {})
                .get("terminated", {})
                .get("exitCode"),
            }
            for state in status.get("containerStatuses", [])[:10]
        ]
        row["conditions"] = [
            {"type": c.get("type"), "status": c.get("status")}
            for c in status.get("conditions", [])[:20]
        ]
    elif resource == "jobs":
        row.update({key: status.get(key) for key in ("active", "succeeded", "failed")})
        row["conditions"] = [
            {"type": c.get("type"), "status": c.get("status")}
            for c in status.get("conditions", [])[:20]
        ]
    elif resource == "persistentvolumeclaims":
        row["phase"] = status.get("phase")
        row["storageClassName"] = spec.get("storageClassName")
        row["volumeMode"] = spec.get("volumeMode")
        row["accessModes"] = spec.get("accessModes")
        row["capacity"] = status.get("capacity", {}).get("storage")
    else:
        raise ValueError("unknown projection")
    return row


def collect(config, oc="oc", context=None, budget=120):
    validate(config)
    deadline = time.monotonic() + budget
    command = [oc, "--request-timeout=20s"]
    if context:
        command += ["--context", context]
    sections = []
    agent_namespace, sources, _ = agent_scope(config)
    selector = "app.kubernetes.io/part-of=" + resource_prefix(config)
    for namespace in dict.fromkeys(
        [config["namespace"], agent_namespace, *sources, *config["restore_namespaces"]]
    ):
        for resource in (
            "deployments",
            "statefulsets",
            "pods",
            "jobs",
            "persistentvolumeclaims",
        ):
            section = {"namespace": namespace, "resource": resource}
            try:
                remaining = min(25, deadline - time.monotonic())
                if remaining <= 0:
                    raise ValueError("total collection budget exhausted")
                raw = query(
                    [
                        *command,
                        "-n",
                        namespace,
                        "get",
                        resource,
                        "-l",
                        selector,
                        "--chunk-size=50",
                        "-o",
                        "json",
                    ],
                    timeout=remaining,
                )
                rows = raw["items"]
                if not isinstance(rows, list):
                    raise ValueError("response shape")
                section.update(
                    status="observed",
                    total=len(rows),
                    truncated=len(rows) > MAX_ROWS,
                    rows=[project(resource, item) for item in rows[:MAX_ROWS]],
                )
            except (
                OSError,
                ValueError,
                TypeError,
                KeyError,
                AttributeError,
                subprocess.SubprocessError,
            ):
                section.update(
                    status="unavailable",
                    reason="Denied, missing API, timeout, response limit or invalid response; no raw error retained",
                )
            sections.append(section)
    return {
        "schema": "vnbui-install-diagnostics/1",
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "partial": any(s["status"] != "observed" or s["truncated"] for s in sections),
        "warning": "Recorded installation state only, not health or backup acceptance. Review identifiers before sharing. No logs or Secret values collected.",
        "sections": sections,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--oc", default="oc")
    parser.add_argument("--context")
    args = parser.parse_args()
    os.umask(0o077)
    try:
        # Refuse existing targets (including symlinks) before querying.
        with args.output.open("x") as stream:
            report = collect(json.loads(args.config.read_text()), args.oc, args.context)
            json.dump(report, stream, indent=2)
            stream.write("\n")
        print(
            "Private report saved; inspect locally. Observed is not a health verdict."
        )
        return 2 if report["partial"] else 0
    except (ValueError, KeyError, TypeError, OSError):
        print(
            "DIAGNOSTICS_FAILED: check configuration, tools and new output path",
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    sys.exit(main())
