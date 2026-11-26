"""Customer tools remain offline/read-only and never export private inputs."""

import importlib.util
import json
import subprocess
import sys
from unittest.mock import patch

import pytest

from backend.tests.test_portable_okd import ROOT, renderer, sample_config


def load(name):
    spec = importlib.util.spec_from_file_location(
        name, ROOT / "packaging/okd" / (name + ".py")
    )
    module = importlib.util.module_from_spec(spec)
    with patch.dict(sys.modules, {"render": renderer}):
        spec.loader.exec_module(module)
    return module


postgres = load("postgres")
diagnostics = load("diagnostics")


def test_candidate_lifetime_is_projected_by_supported_site_configuration():
    site = sample_config()
    site["agent_key_rotation_ttl_hours"] = 48
    items = renderer.render(site, "api")["items"]
    workload = next(item for item in items if item["kind"] == "Deployment")
    env = workload["spec"]["template"]["spec"]["containers"][0]["env"]
    assert (
        next(
            item["value"]
            for item in env
            if item["name"] == "AGENT_KEY_ROTATION_TTL_HOURS"
        )
        == "48"
    )
    for invalid in (0, 169, True, "24"):
        site["agent_key_rotation_ttl_hours"] = invalid
        with pytest.raises(ValueError, match="agent_key_rotation_ttl_hours"):
            renderer.render(site, "api")


def pg_config():
    config = json.loads((ROOT / "packaging/okd/postgres.example.json").read_text())
    config["image"] = "registry.test/postgres@sha256:" + "b" * 64
    config["storage_class"] = "rbd"
    return config


def test_postgres_is_namespaced_restricted_tls_and_retains_storage():
    site, config = sample_config(), pg_config()
    items = postgres.render(site, config)["items"]
    assert {item["kind"] for item in items} == {
        "ConfigMap",
        "PersistentVolumeClaim",
        "Service",
        "StatefulSet",
        "NetworkPolicy",
    }
    assert all(item["metadata"]["namespace"] == site["namespace"] for item in items)
    stateful = next(item for item in items if item["kind"] == "StatefulSet")
    assert stateful["spec"]["updateStrategy"] == {"type": "OnDelete"}
    pod = stateful["spec"]["template"]["spec"]
    assert pod["automountServiceAccountToken"] is False
    assert "runAsUser" not in pod["securityContext"]
    for container in [*pod["initContainers"], *pod["containers"]]:
        assert container["image"] == config["image"]
        assert container["securityContext"]["capabilities"] == {"drop": ["ALL"]}
        assert container["securityContext"]["readOnlyRootFilesystem"] is True
    assert "ssl=on" in pod["containers"][0]["args"]
    assert "livenessProbe" not in pod["containers"][0]
    pvc = next(item for item in items if item["kind"] == "PersistentVolumeClaim")
    assert "ownerReferences" not in pvc["metadata"]
    assert pvc["spec"]["accessModes"] == ["ReadWriteOnce"]
    assert pvc["spec"]["volumeMode"] == "Filesystem"
    hba = items[0]["data"]["pg_hba.conf"]
    assert "hostnossl all all all reject" in hba
    assert "hostssl all all all scram-sha-256" in hba
    assert "host all all all trust" not in hba
    script = items[0]["data"]["10-vesta.sh"]
    assert (
        script.count(
            "NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS"
        )
        == 2
    )
    assert "GRANT USAGE, CREATE ON SCHEMA public" in script
    assert "DROP " not in script and "ALTER ROLE" not in script


@pytest.mark.parametrize(
    "field,value",
    [
        ("image", "postgres:17"),
        ("storage_class", "REPLACE"),
        ("owner_role", "vnbui_bootstrap"),
        ("size", "0Gi"),
        ("resources", {"limits": {"cpu": "1", "memory": "1Gi"}}),
    ],
)
def test_postgres_refuses_invalid_config(field, value):
    config = pg_config()
    config[field] = value
    with pytest.raises(ValueError):
        postgres.render(sample_config(), config)


def test_postgres_refuses_runtime_owner_alias():
    site = sample_config()
    site["runtime_role"] = pg_config()["owner_role"]
    with pytest.raises(ValueError):
        postgres.render(site, pg_config())


@pytest.mark.parametrize("overlap", ["protected", "restore"])
def test_installer_isolates_application_credentials_from_agent_permissions(overlap):
    site = sample_config()
    if overlap == "protected":
        site["vm_namespace"] = site["namespace"]
    else:
        site["restore_namespaces"] = [site["namespace"]]
    for stage in renderer.STAGES:
        with pytest.raises(ValueError, match="Application namespace must be separate"):
            renderer.render(site, stage)


def test_postgres_kustomize_and_fresh_collision_inventory(tmp_path):
    site_file, pg_file = tmp_path / "site.json", tmp_path / "pg.json"
    site_file.write_text(json.dumps(sample_config()))
    pg_file.write_text(json.dumps(pg_config()))
    target = tmp_path / "postgres"
    script = ROOT / "packaging/okd/postgres.py"
    command = [
        sys.executable,
        str(script),
        "--config",
        str(site_file),
        "--postgres-config",
        str(pg_file),
        "--output-dir",
        str(target),
    ]
    subprocess.run(command, check=True, capture_output=True)
    from backend.tests.test_portable_okd import oc_binary

    subprocess.run(
        [oc_binary.__wrapped__(), "kustomize", str(target)],
        check=True,
        capture_output=True,
    )
    assert subprocess.run(command, capture_output=True).returncode == 2
    guard = load("check_fresh_target")
    with patch.dict(sys.modules, {"postgres": postgres}):
        planned = guard.planned_resources(sample_config(), pg_config())
    assert "statefulset/vnbui-postgres" in planned["vnbui"]
    assert "persistentvolumeclaim/vnbui-postgres-data" in planned["vnbui"]


def test_hco_projection_reads_supported_storage_field():
    line = next(
        line
        for line in (ROOT / "packaging/okd/preflight/customer-preflight.sh")
        .read_text()
        .splitlines()
        if line.lstrip().startswith("collect hco ")
    )
    projection = line.split("'", 2)[1]
    raw = {
        "items": [
            {
                "spec": {
                    "storage": {"vmStateStorageClass": "correct-rbd"},
                    "virtualization": {"vmStateStorageClass": "WRONG"},
                }
            }
        ]
    }
    result = subprocess.run(
        ["jq", projection],
        input=json.dumps(raw),
        capture_output=True,
        text=True,
        check=True,
    )
    assert json.loads(result.stdout)[0]["vm_state_storage_class"] == "correct-rbd"


@pytest.mark.parametrize(
    "resource",
    ["pods", "deployments", "statefulsets", "jobs", "persistentvolumeclaims"],
)
def test_offline_diagnostics_allowlist(resource):
    planted = "PRIVATE-PASSWORD-URL-KEY"
    item = {
        "metadata": {
            "name": "product",
            "uid": "id",
            "annotations": {"secret": planted},
        },
        "spec": {"containers": [{"env": [{"value": planted}]}]},
        "status": {
            "message": planted,
            "conditions": [{"type": "Ready", "status": "True", "message": planted}],
            "containerStatuses": [
                {
                    "name": "api",
                    "state": {"waiting": {"message": planted}},
                    "ready": False,
                }
            ],
        },
    }
    result = diagnostics.project(resource, item)
    assert planted not in json.dumps(result)
    assert result["name"] == "product"


def test_offline_diagnostics_partial_and_scoped(monkeypatch):
    calls = []

    def query(command, **kwargs):
        calls.append(command)
        assert "get" in command and "-l" in command
        assert not set(command) & {"secrets", "logs", "exec", "apply", "events"}
        if "jobs" in command:
            raise ValueError("PRIVATE FAILURE")
        return {"items": [{"metadata": {"name": "product"}}] * 51}

    monkeypatch.setattr(diagnostics, "query", query)
    report = diagnostics.collect(sample_config(), context="customer")
    assert report["partial"] is True
    assert len(calls) == 10
    assert "PRIVATE FAILURE" not in json.dumps(report)
    assert all(len(s.get("rows", [])) <= 50 for s in report["sections"])


def test_diagnostics_total_budget_exhaustion_does_not_query(monkeypatch):
    def refuse(*args, **kwargs):
        raise AssertionError("No subprocess after the total budget expires")

    monkeypatch.setattr(diagnostics, "query", refuse)
    report = diagnostics.collect(sample_config(), budget=0)
    assert report["partial"] is True
    assert all(section["status"] == "unavailable" for section in report["sections"])


def test_diagnostic_subprocess_bounds_and_errors():
    with pytest.raises(ValueError, match="response limit"):
        diagnostics.query([sys.executable, "-c", "print('x' * 1000)"], max_bytes=50)
    with pytest.raises(ValueError, match="timeout"):
        diagnostics.query(
            [sys.executable, "-c", "import time; time.sleep(5)"], timeout=0.05
        )
    with pytest.raises(ValueError, match="query failed"):
        diagnostics.query([sys.executable, "-c", "raise SystemExit(2)"])
    assert diagnostics.query([sys.executable, "-c", "print('{\"items\": []}')"]) == {
        "items": []
    }


def test_diagnostic_cli_does_not_overwrite_existing_output(tmp_path):
    output = tmp_path / "report.json"
    output.write_text("preserve")
    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "packaging/okd/diagnostics.py"),
            "--config",
            "/nonexistent",
            "--output",
            str(output),
        ],
        capture_output=True,
    )
    assert result.returncode == 2
    assert output.read_text() == "preserve"
