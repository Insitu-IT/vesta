"""Fresh install target guard: read-only and fail closed on collisions."""

import importlib.util
import subprocess
import sys
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from backend.tests.test_portable_okd import renderer, ROOT, sample_config


@pytest.fixture
def config():
    return sample_config()


spec = importlib.util.spec_from_file_location(
    "fresh_target", ROOT / "packaging/okd/check_fresh_target.py"
)
guard = importlib.util.module_from_spec(spec)
with patch.dict(sys.modules, {"render": renderer}):
    spec.loader.exec_module(guard)


def test_planned_resources_cover_every_stage_without_secrets(config):
    result = guard.planned_resources(config)
    assert set(result) == {config["namespace"], config["vm_namespace"]}
    assert "job/vnbui-fresh-schema" in result[config["namespace"]]
    assert "job/vnbui-restore-grants" in result[config["namespace"]]
    assert "deployment/vnbui-backend" in result[config["namespace"]]
    assert "rolebinding/vnbui-agent" in result[config["vm_namespace"]]
    assert "persistentvolumeclaim/vnbui-scratch" in result[config["vm_namespace"]]
    assert all(
        not ref.startswith("secret/") for refs in result.values() for ref in refs
    )


def test_empty_namespaces_pass_without_mutating_commands(config, monkeypatch, capsys):
    calls = []

    def fake_run(argv, **kwargs):
        calls.append(argv)
        assert kwargs["capture_output"] and kwargs["check"]
        return SimpleNamespace(stdout="")

    monkeypatch.setattr(guard.subprocess, "run", fake_run)
    assert guard.run(config, "oc") == 0
    assert len(calls) == 4
    assert all(
        "get" in argv and "apply" not in argv and "patch" not in argv for argv in calls
    )
    assert capsys.readouterr().out.count("NO_PRODUCT_COLLISIONS") == 2


def test_existing_product_object_fails_before_any_apply(config, monkeypatch, capsys):

    def fake_run(argv, **kwargs):
        if "--ignore-not-found" in argv:
            return SimpleNamespace(stdout="deployment.apps/vnbui-backend\n")
        return SimpleNamespace(stdout="namespace/vnbui\n")

    monkeypatch.setattr(guard.subprocess, "run", fake_run)
    assert guard.run(config, "oc") == 2
    output = capsys.readouterr().out
    assert "COLLISION" in output and "deployment.apps/vnbui-backend" in output


def test_missing_permission_or_namespace_does_not_pass(config, monkeypatch):

    def fail(argv, **kwargs):
        raise subprocess.CalledProcessError(1, argv)

    monkeypatch.setattr(guard.subprocess, "run", fail)
    with pytest.raises(subprocess.CalledProcessError):
        guard.run(config, "oc")
