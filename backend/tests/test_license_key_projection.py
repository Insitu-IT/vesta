"""Local trust provisioning, immutable rendering and portable kit boundaries."""

import base64
import copy
import importlib.util
import json
import socket

import pytest

from backend.tests.test_portable_okd import ROOT, renderer, sample_config

spec = importlib.util.spec_from_file_location(
    "license_keys", ROOT / "packaging/okd/license_keys.py"
)
license_keys = importlib.util.module_from_spec(spec)
spec.loader.exec_module(license_keys)


def trust():
    return {
        "schema_version": 1,
        "keys": {"fixture-operator": base64.b64encode(bytes(range(32))).decode()},
    }


@pytest.mark.parametrize(
    "value",
    [
        {"schema_version": True, "keys": {}},
        {"schema_version": 1, "keys": {}},
        {"schema_version": 1, "keys": {"fixture": "not-a-key"}},
        {"schema_version": 1, "keys": {"fixture": base64.b64encode(b"short").decode()}},
        {**trust(), "private_key": "forbidden"},
        {**trust(), "url": "https://issuer.invalid/keys"},
    ],
)
def test_manifest_rejects_invalid_or_remote_trust(value):
    with pytest.raises(ValueError):
        license_keys.validate_manifest(value)


def test_local_manifest_bounds_duplicates_and_symlinks(tmp_path):
    path = tmp_path / "keys.json"
    path.write_text('{"schema_version":1,"schema_version":1,"keys":{}}')
    with pytest.raises(ValueError, match="Duplicate"):
        license_keys.read_manifest(path)
    path.write_bytes(b"x" * 65537)
    with pytest.raises(ValueError, match="65536"):
        license_keys.read_manifest(path)
    link = tmp_path / "link.json"
    link.symlink_to(path)
    with pytest.raises(OSError):
        license_keys.read_manifest(link)


def test_public_manifest_helper_output_matches_runtime_trust_without_crypto_installer_dependency(
    tmp_path, monkeypatch
):
    from core.license_registration import load_trusted_keys

    def forbidden(*args, **kwargs):
        raise AssertionError("Public-key packaging attempted network access")

    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    source, output = tmp_path / "public.json", tmp_path / "prepared"
    source.write_text(json.dumps(trust()))
    assert (
        license_keys.main(
            ["--public-keys", str(source), "--namespace", "vnbui", "--out", str(output)]
        )
        == 0
    )
    resource = json.loads((output / "configmap.json").read_text())
    projection = json.loads((output / "projection.json").read_text())
    assert resource["metadata"]["name"] == projection["config_map"]
    parsed, state = load_trusted_keys(source)
    assert parsed == {"fixture-operator": bytes(range(32))}
    assert state["state"] == "configured"
    with pytest.raises(FileExistsError):
        license_keys.main(
            ["--public-keys", str(source), "--namespace", "vnbui", "--out", str(output)]
        )
    assert "cryptography" not in (ROOT / "packaging/okd/license_keys.py").read_text()


def test_renderer_mounts_local_public_trust_only_in_backend_without_egress(
    tmp_path, monkeypatch
):
    def forbidden(*args, **kwargs):
        raise AssertionError("Offline renderer attempted network access")

    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    resource, projection = license_keys.prepare(trust(), "vnbui")
    assert resource["immutable"]
    assert json.loads(resource["data"]["license-keys.json"]) == trust()
    config = sample_config()
    config["licensing"] = projection
    api = renderer.render(config, "api")["items"]
    deployment = next(
        x
        for x in api
        if x["kind"] == "Deployment" and x["metadata"]["name"] == "vnbui-backend"
    )
    pod = deployment["spec"]["template"]["spec"]
    volume = next(x for x in pod["volumes"] if x["name"] == "license-keys")
    assert volume["configMap"]["name"] == projection["config_map"]
    mount = next(
        x for x in pod["containers"][0]["volumeMounts"] if x["name"] == "license-keys"
    )
    assert mount == {
        "name": "license-keys",
        "mountPath": "/etc/vnbui/license-keys.json",
        "readOnly": True,
        "subPath": "license-keys.json",
    }
    for item in api:
        if item is not deployment:
            assert "license-keys" not in json.dumps(item)
    for stage in ("migrate", "restore-grants", "agent"):
        assert "license-keys" not in json.dumps(renderer.render(config, stage))
    for invalid in (
        {"url": "https://issuer.invalid/keys"},
        {"config_map": "../other"},
        {"config_map": projection["config_map"], "path": "/issuer.pem"},
    ):
        config["licensing"] = invalid
        with pytest.raises(ValueError, match="public-key"):
            renderer.validate(config)


def test_trust_rotation_is_explicit_mutable_configuration_with_input_tracking():
    from backend.tests.test_reconfigure import reconfigure, load

    old = sample_config()
    new = copy.deepcopy(old)
    _, new["licensing"] = license_keys.prepare(trust(), old["namespace"])
    reconfigure.changed(old, new)
    deployment = next(
        x
        for x in renderer.render(new, "api")["items"]
        if x["kind"] == "Deployment" and x["metadata"]["name"] == "vnbui-backend"
    )
    inputs = load("reconcile_inputs").source_refs(deployment)
    assert any(new["licensing"]["config_map"] in str(reference) for reference in inputs)
