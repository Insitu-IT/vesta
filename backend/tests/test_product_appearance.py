"""The standalone installer and backend share supported pack validation/fallback."""

import base64
import copy
import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, ROOT / file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


appearance = load("install_appearance", "packaging/okd/appearance.py")
identity = load("product_identity", "backend/core/product_identity.py")
SVG = b'<svg xmlns="http://www.w3.org/2000/svg"><path d="M0 0"/></svg>'


def manifest(name="active", brand="Active Brand"):
    value = {
        "schema_version": 1,
        "id": name,
        "version": "1.0.0",
        "name": "Example Pack",
        "type": "brand",
        "assets": {"brand-logo": {"file": "logo.svg", "content_type": "image/svg+xml"}},
    }
    if brand:
        value["meta"] = {"vnbui": {"schema_version": 1, "product_name": brand}}
    return value


def write_pack(root, value, content=SVG):
    path = root / "packs" / value["id"] / value["version"]
    path.mkdir(parents=True)
    (path / "manifest.json").write_text(json.dumps(value))
    (path / "logo.svg").write_bytes(content)
    return path


def configured(tmp_path, monkeypatch, value, content=SVG):
    monkeypatch.setenv("APPEARANCE_ROOT", str(tmp_path))
    write_pack(tmp_path, value, content)
    write_pack(tmp_path, manifest("previous", "Previous Brand"))
    (tmp_path / "config.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "active_pack": "/appearance/packs/active/1.0.0",
                "previous_pack": "/appearance/packs/previous/1.0.0",
            }
        )
    )


def test_vesta_appearance_metadata_takes_precedence(tmp_path, monkeypatch):
    value = manifest(brand="Inherited Brand")
    value["meta"]["vesta"] = {"schema_version": 1, "product_name": "Current Brand"}
    appearance.validate_manifest(value)
    configured(tmp_path, monkeypatch, value)
    assert identity.product_name() == "Current Brand"


def invalid_case(case):
    value = manifest()
    if case == "bool-version":
        value["schema_version"] = True
    elif case == "bad-type":
        value["type"] = "invalid type"
    elif case == "bad-category":
        value["categories"] = {"brand": {"unexpected": True}}
    elif case == "bad-label":
        value["assets"]["brand-logo"]["label"] = []
    elif case == "file-default":
        value["assets"]["brand-logo"]["default"] = "logo.svg"
    elif case == "empty-variants":
        value["assets"]["brand-logo"] = {
            "variants": {},
            "default": "logo.svg",
            "content_type": "image/svg+xml",
        }
    elif case == "bad-axis-label":
        value["variant_schema"] = {
            "theme": {"label": [], "values": ["light"], "default": "light"}
        }
    elif case == "bad-color":
        value["meta"]["vnbui"]["colors"] = {"primary": "red"}
    elif case == "bad-density":
        value["meta"]["vnbui"]["density"] = "broken"
    elif case == "empty-meta":
        value["meta"]["vnbui"] = {}
    elif case == "control-name":
        value["meta"]["vnbui"]["product_name"] = "Brand\x7f"
    elif case == "bad-font":
        value["meta"]["vnbui"]["font_asset"] = "brand-logo"
    return value


@pytest.mark.parametrize(
    "case",
    [
        "bool-version",
        "bad-type",
        "bad-category",
        "bad-label",
        "file-default",
        "empty-variants",
        "bad-axis-label",
        "bad-color",
        "bad-density",
        "empty-meta",
        "control-name",
        "bad-font",
    ],
)
def test_shared_invalid_manifest_fixtures_fall_back(case, tmp_path, monkeypatch):
    value = invalid_case(case)
    for validator in (appearance.validate_manifest, identity.validate_manifest):
        with pytest.raises(ValueError):
            validator(copy.deepcopy(value))
    configured(tmp_path, monkeypatch, value)
    assert identity.product_name() == "Previous Brand"


@pytest.mark.parametrize("meta", [None, {}, {"other": {"any": "value"}}])
def test_valid_partial_active_pack_uses_default_product_name(
    meta, tmp_path, monkeypatch
):
    value = manifest(brand=None)
    if meta is not None:
        value["meta"] = meta
    for validator in (appearance.validate_manifest, identity.validate_manifest):
        validator(copy.deepcopy(value))
    configured(tmp_path, monkeypatch, value)
    assert identity.product_name() == identity.DEFAULT_PRODUCT_NAME


@pytest.mark.parametrize(
    "content",
    [
        b"<svg><script>alert(1)</script></svg>",
        b'<svg onload="alert(1)"/>',
        b'<svg><use href="https://outside.example/logo.svg"/></svg>',
        b"<html>not svg</html>",
        b"x" * (256 * 1024 + 1),
    ],
)
def test_invalid_or_oversized_asset_uses_previous_name(content, tmp_path, monkeypatch):
    configured(tmp_path, monkeypatch, manifest(), content)
    assert identity.product_name() == "Previous Brand"


def test_configmap_projection_symlinks_inside_mount_are_supported(
    tmp_path, monkeypatch
):
    projected = tmp_path / "..timestamp"
    projected.mkdir()
    configured(projected, monkeypatch, manifest())
    monkeypatch.setenv("APPEARANCE_ROOT", str(tmp_path))
    (tmp_path / "config.json").symlink_to("..timestamp/config.json")
    (tmp_path / "packs").symlink_to("..timestamp/packs", target_is_directory=True)
    assert identity.product_name() == "Active Brand"


def test_asset_symlink_outside_appearance_mount_fails_closed(tmp_path, monkeypatch):
    root = tmp_path / "mount"
    root.mkdir()
    configured(root, monkeypatch, manifest())
    logo = root / "packs/active/1.0.0/logo.svg"
    logo.unlink()
    outside = tmp_path / "outside.svg"
    outside.write_bytes(SVG)
    logo.symlink_to(outside)
    assert identity.product_name() == "Previous Brand"


def test_installer_prepares_bounded_immutable_pack_and_projection(tmp_path):
    path = write_pack(tmp_path, manifest())
    resource, projection = appearance.prepare(path, None, "vnbui")
    assert resource["immutable"] is True
    assert resource["metadata"]["name"] == projection["config_map"]
    assert {i["path"] for i in projection["items"]} == {
        "config.json",
        "packs/active/1.0.0/manifest.json",
        "packs/active/1.0.0/logo.svg",
    }


def test_generator_projection_with_current_and_previous_versions_renders_both_mounts(
    tmp_path,
):
    from backend.tests.test_portable_okd import renderer, sample_config, oc_binary
    import subprocess
    import yaml

    active = manifest("lab-backup", "Lab Backup")
    active["version"] = "1.0.1"
    previous = manifest("lab-backup", "Previous Lab Backup")
    resource, projection = appearance.prepare(
        write_pack(tmp_path, active), write_pack(tmp_path, previous), "vnbui"
    )
    config = sample_config()
    config["appearance"] = projection
    renderer.validate(config)
    items = renderer.render(config, "api")["items"]
    expected_paths = {
        "config.json",
        "packs/lab-backup/1.0.0/manifest.json",
        "packs/lab-backup/1.0.0/logo.svg",
        "packs/lab-backup/1.0.1/manifest.json",
        "packs/lab-backup/1.0.1/logo.svg",
    }
    assert resource["immutable"] is True
    assert {i["path"] for i in projection["items"]} == expected_paths
    assert {i["key"] for i in projection["items"]} == set(resource["binaryData"])
    deployments = [i for i in items if i["kind"] == "Deployment"]
    assert {i["metadata"]["name"] for i in deployments} == {
        "vnbui-backend",
        "vnbui-frontend",
    }
    for deployment in deployments:
        pod = deployment["spec"]["template"]["spec"]
        volume = next(v for v in pod["volumes"] if v["name"] == "appearance")
        assert volume["configMap"] == {
            "name": resource["metadata"]["name"],
            "items": projection["items"],
        }
        mount = next(
            m for m in pod["containers"][0]["volumeMounts"] if m["name"] == "appearance"
        )
        assert (
            mount["mountPath"] == "/etc/vesta/appearance" and mount["readOnly"] is True
        )
        container = pod["containers"][0]
        if container["name"] == "backend":
            assert {
                "name": "APPEARANCE_ROOT",
                "value": mount["mountPath"],
            } in container["env"]
    target = tmp_path / "api-overlay"
    renderer.write_kustomize(config, "api", target)
    rendered = list(
        yaml.safe_load_all(
            subprocess.check_output(
                [oc_binary.__wrapped__(), "kustomize", str(target)], text=True
            )
        )
    )

    def identity(item):
        return item["kind"], item["metadata"]["namespace"], item["metadata"]["name"]

    assert {identity(i): i for i in rendered} == {identity(i): i for i in items}


@pytest.mark.parametrize(
    "path",
    [
        "../config.json",
        "/packs/lab-backup/1.0.1/logo.svg",
        "elsewhere/lab-backup/1.0.1/logo.svg",
        "packs/lab-backup/1.0.1/../outside.svg",
        "packs/lab-backup/1.0.1/./logo.svg",
        "packs/lab-backup/1.0.1/..",
        "packs/lab-backup/not-a-version/logo.svg",
        "packs/lab-backup/1.0.1",
        "packs/lab.backup/1.0.1/logo.svg",
        "packs/lab-backup/1.0.1/dir.with.dots/logo.svg",
        "packs/lab-backup/1.0.1//logo.svg",
    ],
)
def test_renderer_rejects_unsafe_or_nonversioned_projection_paths(path):
    from backend.tests.test_portable_okd import renderer, sample_config

    config = sample_config()
    config["appearance"] = {
        "config_map": "site-appearance",
        "items": [
            {"key": "config", "path": "config.json"},
            {"key": "asset", "path": path},
        ],
    }
    with pytest.raises(ValueError, match="appearance projection path"):
        renderer.validate(config)


@pytest.mark.parametrize(
    "problem", ["key", "duplicate-path", "count", "missing-config"]
)
def test_projection_fix_keeps_existing_key_count_and_duplicate_guards(problem):
    from backend.tests.test_portable_okd import renderer, sample_config

    config = sample_config()
    entries = [
        {"key": "config", "path": "config.json"},
        {"key": "asset", "path": "packs/lab-backup/1.0.1/logo.svg"},
    ]
    if problem == "key":
        entries[1]["key"] = "../asset"
    elif problem == "duplicate-path":
        entries[1]["path"] = "config.json"
    elif problem == "count":
        entries = entries * 257
    else:
        entries = entries[1:]
    config["appearance"] = {"config_map": "site-appearance", "items": entries}
    with pytest.raises(ValueError):
        renderer.validate(config)


def test_identical_revision_artwork_shares_storage_and_preserves_projected_bytes(
    tmp_path,
):
    from backend.tests.test_portable_okd import renderer, sample_config

    old = manifest("lab-backup")
    new = copy.deepcopy(old)
    new["version"] = "1.0.1"
    active, previous = write_pack(tmp_path, new), write_pack(tmp_path, old)
    resource, projection = appearance.prepare(active, previous, "vnbui")
    expected = {
        "config.json": json.dumps(
            {
                "schema_version": 1,
                "active_pack": "/appearance/packs/lab-backup/1.0.1",
                "previous_pack": "/appearance/packs/lab-backup/1.0.0",
            },
            separators=(",", ":"),
        ).encode()
    }
    for root in (active, previous):
        expected.update(appearance.load_pack(root)[1])
    actual = {
        item["path"]: base64.b64decode(resource["binaryData"][item["key"]])
        for item in projection["items"]
    }
    assert actual == expected
    assert len(resource["binaryData"]) == 4
    assert len(projection["items"]) == 5
    config = sample_config()
    config["appearance"] = projection
    renderer.validate(config)
    assert appearance.prepare(active, previous, "vnbui") == (resource, projection)


def test_unique_revision_assets_still_obey_configmap_limit(tmp_path, monkeypatch):
    old = manifest("lab-backup")
    new = copy.deepcopy(old)
    new["version"] = "1.0.1"
    active = write_pack(tmp_path, new, SVG.replace(b"M0 0", b"M0 1"))
    previous = write_pack(tmp_path, old)
    resource, projection = appearance.prepare(active, previous, "vnbui")
    assert len(resource["binaryData"]) == len(projection["items"]) == 5
    monkeypatch.setattr(
        appearance, "MAX_RESOURCE", len(json.dumps(resource).encode()) - 1
    )
    with pytest.raises(ValueError, match="resource limit"):
        appearance.prepare(active, previous, "vnbui")


def test_generator_still_refuses_symlinked_asset_before_projection(tmp_path):
    active = manifest("lab-backup")
    active["version"] = "1.0.1"
    root = write_pack(tmp_path, active)
    outside = tmp_path / "outside.svg"
    outside.write_bytes(SVG)
    (root / "logo.svg").unlink()
    (root / "logo.svg").symlink_to(outside)
    with pytest.raises(ValueError, match="symlink"):
        appearance.prepare(root, None, "vnbui")


@pytest.mark.parametrize(
    "case",
    json.loads((ROOT / "tests/fixtures/visual-assets-theme-v2.json").read_text()),
    ids=lambda case: case["name"],
)
def test_shared_theme_metadata_contract(case):
    value = manifest()
    value["meta"]["vnbui"] = case["metadata"]
    for validator in (appearance.validate_manifest, identity.validate_manifest):
        if case["valid"]:
            assert validator(copy.deepcopy(value)) == value
        else:
            with pytest.raises(ValueError):
                validator(copy.deepcopy(value))
