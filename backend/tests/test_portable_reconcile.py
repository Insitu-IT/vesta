"""Portable operator-side Secret/ConfigMap revision reconciliation."""

import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location(
    "portable_reconcile", ROOT / "packaging/okd/reconcile_inputs.py"
)
reconcile = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reconcile)


def deployment(annotation=None, ready=True):
    template_meta = (
        {"annotations": {reconcile.ANNOTATION: annotation}} if annotation else {}
    )
    return {
        "metadata": {"name": "vnbui-backend", "resourceVersion": "8", "generation": 3},
        "spec": {
            "replicas": 1,
            "template": {
                "metadata": template_meta,
                "spec": {
                    "containers": [
                        {
                            "env": [
                                {
                                    "name": "DATABASE_URL",
                                    "valueFrom": {
                                        "secretKeyRef": {
                                            "name": "db",
                                            "key": "DATABASE_URL",
                                        }
                                    },
                                },
                                {
                                    "name": "UI",
                                    "valueFrom": {
                                        "configMapKeyRef": {
                                            "name": "settings",
                                            "key": "ui",
                                        }
                                    },
                                },
                            ],
                            "envFrom": [{"secretRef": {"name": "app"}}],
                        }
                    ],
                    "initContainers": [
                        {"envFrom": [{"configMapRef": {"name": "init"}}]}
                    ],
                    "volumes": [
                        {"secret": {"secretName": "tls"}},
                        {"projected": {"sources": [{"configMap": {"name": "trust"}}]}},
                    ],
                    "imagePullSecrets": [{"name": "pull"}],
                },
            },
        },
        "status": {
            "observedGeneration": 3 if ready else 2,
            "replicas": 1,
            "updatedReplicas": 1,
            "readyReplicas": 1,
            "availableReplicas": 1,
        },
    }


def test_collects_all_workload_inputs():
    assert reconcile.source_refs(deployment()) == [
        ("configmap", "init"),
        ("configmap", "settings"),
        ("configmap", "trust"),
        ("secret", "app"),
        ("secret", "db"),
        ("secret", "pull"),
        ("secret", "tls"),
    ]


def test_revision_and_rollout_must_both_match():
    assert reconcile.check_deployment(deployment(), "[]") == "INPUT_REVISION_UNTRACKED"
    assert reconcile.check_deployment(deployment("old"), "[]") == "INPUT_REVISION_DRIFT"
    assert (
        reconcile.check_deployment(deployment("[]", ready=False), "[]")
        == "ROLLOUT_NOT_CURRENT"
    )
    assert reconcile.check_deployment(deployment("[]"), "[]") == "CURRENT"


def test_source_version_query_requests_only_metadata(monkeypatch):
    seen = []

    def fake_run(argv, **kwargs):
        seen.append(argv)
        return SimpleNamespace(stdout="uid-1|27")

    monkeypatch.setattr(reconcile.subprocess, "run", fake_run)
    assert reconcile.source_versions("oc", "ns", [("secret", "db")]) == {
        "secret/db": ["uid-1", "27"]
    }
    assert seen == [
        [
            "oc",
            "-n",
            "ns",
            "get",
            "secret",
            "db",
            "-o",
            "jsonpath={.metadata.uid}|{.metadata.resourceVersion}",
        ]
    ]


@pytest.mark.parametrize("existing", ["none", "metadata", "annotations"])
def test_patch_is_cas_and_preserves_other_annotations(monkeypatch, existing):
    seen = []

    def fake_run(argv, **kwargs):
        seen.append(argv)
        return SimpleNamespace(stdout="")

    monkeypatch.setattr(reconcile.subprocess, "run", fake_run)
    obj = deployment()
    if existing == "none":
        del obj["spec"]["template"]["metadata"]
    elif existing == "annotations":
        obj["spec"]["template"]["metadata"]["annotations"] = {"other": "keep"}
    reconcile.patch_marker("oc", "ns", obj, "revision")
    patch = json.loads(seen[0][seen[0].index("-p") + 1])
    assert patch[0] == {"op": "test", "path": "/metadata/resourceVersion", "value": "8"}
    assert (
        patch[1]["path"]
        == {
            "none": "/spec/template/metadata",
            "metadata": "/spec/template/metadata/annotations",
            "annotations": "/spec/template/metadata/annotations/backup.insitu.co.il~1input-revisions",
        }[existing]
    )
    assert "password" not in json.dumps(seen)


def test_reconcile_fails_if_secret_changes_during_rollout(monkeypatch):
    obj = deployment()
    monkeypatch.setattr(reconcile, "oc_json", lambda *args: obj)
    versions = iter([{"secret/db": ["uid", "1"]}, {"secret/db": ["uid", "2"]}])
    monkeypatch.setattr(reconcile, "source_versions", lambda *args: next(versions))
    monkeypatch.setattr(
        reconcile,
        "patch_marker",
        lambda *args: obj["spec"]["template"]["metadata"].update(
            annotations={
                reconcile.ANNOTATION: reconcile.marker({"secret/db": ["uid", "1"]})
            }
        ),
    )
    monkeypatch.setattr(
        reconcile.subprocess, "run", lambda *args, **kwargs: SimpleNamespace(stdout="")
    )
    assert reconcile.run("oc", "ns", "vnbui-backend", True, "1m") == 2


def test_read_only_check_never_patches_or_rolls_out(monkeypatch, capsys):
    obj = deployment()
    monkeypatch.setattr(reconcile, "oc_json", lambda *args: obj)
    monkeypatch.setattr(
        reconcile, "source_versions", lambda *args: {"secret/db": ["uid", "1"]}
    )

    def forbidden(*args, **kwargs):
        raise AssertionError("read-only check attempted a mutation")

    monkeypatch.setattr(reconcile, "patch_marker", forbidden)
    monkeypatch.setattr(reconcile.subprocess, "run", forbidden)
    assert reconcile.run("oc", "ns", "vnbui-backend", False, "1m") == 2
    assert (
        capsys.readouterr().out
        == "ns/vnbui-backend: INPUT_REVISION_UNTRACKED; inputs=7\n"
    )


def test_no_referenced_inputs_is_explicit_and_not_a_pass(monkeypatch, capsys):
    obj = deployment()
    obj["spec"]["template"]["spec"] = {"containers": [{}]}
    monkeypatch.setattr(reconcile, "oc_json", lambda *args: obj)
    assert reconcile.run("oc", "ns", "vnbui-frontend", False, "1m") == 2
    assert (
        capsys.readouterr().out == "ns/vnbui-frontend: NO_REFERENCED_INPUTS; inputs=0\n"
    )
