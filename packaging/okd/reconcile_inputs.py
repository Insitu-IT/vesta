#!/usr/bin/env python3
"""Check or reconcile Deployment Secret/ConfigMap revisions without exposing values.

This is an operator-run day-2 tool, not an in-cluster controller. It uses only
object UID/resourceVersion metadata, never Secret data, and does not assume a
particular Secret manager, reloader, or executable inside the workload image.
"""

import argparse
import json
import os
import subprocess
import sys

ANNOTATION = "backup.insitu.co.il/input-revisions"


def oc_arguments(oc):
    return [oc] if isinstance(oc, (str, os.PathLike)) else list(oc)


def oc_json(oc, namespace, *args):
    result = subprocess.run(
        [*oc_arguments(oc), "-n", namespace, *args, "-o", "json"],
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(result.stdout)


def source_refs(deployment):
    """Return every direct Secret/ConfigMap input to the pod template."""
    pod = deployment["spec"]["template"]["spec"]
    refs = set()
    for container in pod.get("initContainers", []) + pod.get("containers", []):
        for variable in container.get("env", []):
            source = variable.get("valueFrom") or {}
            for field, kind in (
                ("secretKeyRef", "secret"),
                ("configMapKeyRef", "configmap"),
            ):
                if source.get(field):
                    refs.add((kind, source[field]["name"]))
        for env_from in container.get("envFrom", []):
            for field, kind in (("secretRef", "secret"), ("configMapRef", "configmap")):
                if env_from.get(field):
                    refs.add((kind, env_from[field]["name"]))
    for volume in pod.get("volumes", []):
        for field, kind in (("secret", "secret"), ("configMap", "configmap")):
            if volume.get(field):
                value = volume[field]
                refs.add((kind, value.get("secretName") or value.get("name")))
        for source in (volume.get("projected") or {}).get("sources", []):
            for field, kind in (("secret", "secret"), ("configMap", "configmap")):
                if source.get(field):
                    refs.add((kind, source[field]["name"]))
    for image_pull in pod.get("imagePullSecrets", []):
        refs.add(("secret", image_pull["name"]))
    if any(not name for _, name in refs):
        raise ValueError("Deployment has an incomplete Secret/ConfigMap reference")
    return sorted(refs)


def source_versions(oc, namespace, refs):
    versions = {}
    for kind, name in refs:
        # JSONPath emits metadata only; Secret values never enter this process.
        result = subprocess.run(
            [
                *oc_arguments(oc),
                "-n",
                namespace,
                "get",
                kind,
                name,
                "-o",
                "jsonpath={.metadata.uid}|{.metadata.resourceVersion}",
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        uid, separator, version = result.stdout.partition("|")
        if not separator or not uid or not version:
            raise ValueError(f"Missing object metadata: {kind}/{name}")
        versions[f"{kind}/{name}"] = [uid, version]
    return versions


def marker(versions):
    return json.dumps(versions, sort_keys=True, separators=(",", ":"))


def check_deployment(deployment, expected):
    annotation = (
        deployment["spec"]["template"].get("metadata", {}).get("annotations") or {}
    ).get(ANNOTATION)
    if annotation is None:
        return "INPUT_REVISION_UNTRACKED"
    if annotation != expected:
        return "INPUT_REVISION_DRIFT"
    desired = deployment["spec"].get("replicas", 1)
    status = deployment.get("status", {})
    if (
        status.get("observedGeneration", 0) < deployment["metadata"]["generation"]
        or status.get("replicas", 0) != desired
        or status.get("updatedReplicas", 0) != desired
        or status.get("readyReplicas", 0) != desired
        or status.get("availableReplicas", 0) != desired
    ):
        return "ROLLOUT_NOT_CURRENT"
    return "CURRENT"


def patch_marker(oc, namespace, deployment, expected):
    template = deployment["spec"]["template"]
    metadata = template.get("metadata")
    if metadata is None:
        path = "/spec/template/metadata"
        value = {"annotations": {ANNOTATION: expected}}
    elif metadata.get("annotations") is None:
        path = "/spec/template/metadata/annotations"
        value = {ANNOTATION: expected}
    else:
        path = "/spec/template/metadata/annotations/" + ANNOTATION.replace(
            "~", "~0"
        ).replace("/", "~1")
        value = expected
    patch = [
        {
            "op": "test",
            "path": "/metadata/resourceVersion",
            "value": deployment["metadata"]["resourceVersion"],
        },
        {"op": "add", "path": path, "value": value},
    ]
    subprocess.run(
        [
            *oc_arguments(oc),
            "-n",
            namespace,
            "patch",
            "deployment",
            deployment["metadata"]["name"],
            "--type=json",
            "-p",
            json.dumps(patch, separators=(",", ":")),
        ],
        check=True,
        capture_output=True,
        text=True,
    )


def run(oc, namespace, name, reconcile, timeout):
    deployment = oc_json(oc, namespace, "get", "deployment", name)
    refs = source_refs(deployment)
    if not refs:
        print(f"{namespace}/{name}: NO_REFERENCED_INPUTS; inputs=0")
        return 2
    expected = marker(source_versions(oc, namespace, refs))
    state = check_deployment(deployment, expected)
    if reconcile and state != "CURRENT":
        patch_marker(oc, namespace, deployment, expected)
        subprocess.run(
            [
                *oc_arguments(oc),
                "-n",
                namespace,
                "rollout",
                "status",
                f"deployment/{name}",
                f"--timeout={timeout}",
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        deployment = oc_json(oc, namespace, "get", "deployment", name)
        if source_refs(deployment) != refs:
            raise ValueError(
                "Deployment input references changed during reconciliation"
            )
        expected = marker(source_versions(oc, namespace, refs))
        state = check_deployment(deployment, expected)
    print(f"{namespace}/{name}: {state}; inputs={len(refs)}")
    return 0 if state == "CURRENT" else 2


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("check", "reconcile"))
    parser.add_argument("--namespace", required=True)
    parser.add_argument("--deployment", required=True)
    parser.add_argument("--oc", default="oc")
    parser.add_argument("--timeout", default="10m")
    parser.add_argument(
        "--quiesced",
        action="store_true",
        help="acknowledge dispatch is fenced and active/uncertain attempts reviewed",
    )
    args = parser.parse_args()
    if args.action == "reconcile" and not args.quiesced:
        parser.error("reconcile requires --quiesced after fencing dispatch")
    try:
        return run(
            args.oc,
            args.namespace,
            args.deployment,
            args.action == "reconcile",
            args.timeout,
        )
    except (
        subprocess.CalledProcessError,
        ValueError,
        KeyError,
        json.JSONDecodeError,
    ) as exc:
        # Do not echo command arguments or raw API responses in failure logs.
        print(
            f"{args.namespace}/{args.deployment}: RECONCILIATION_FAILED ({type(exc).__name__})",
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    sys.exit(main())
