"""One passive SVG contract across installer, backend, and native browser fixtures."""

import base64
import importlib.util
import json
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SVG_CASES = json.loads((ROOT / "tests/fixtures/visual-assets-svg-v1.json").read_text())[
    "cases"
]
PACK = json.loads(
    (ROOT / "tests/fixtures/visual-assets-prefixed-pack-v1.json").read_text()
)


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, ROOT / file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


appearance = load("svg_install_appearance", "packaging/okd/appearance.py")
identity = load("svg_product_identity", "backend/core/product_identity.py")


@pytest.mark.parametrize("fixture", SVG_CASES, ids=lambda value: value["name"])
def test_passive_svg_namespaces_have_one_shared_contract(fixture):
    def expanded(name):
        return name[1:].split("}", 1) if name.startswith("{") else ("", name)

    def serialized(node):
        namespace, local = expanded(node.tag)
        return {
            "localName": local,
            "namespaceURI": namespace,
            "attributes": [
                {
                    "localName": expanded(key)[1],
                    "namespaceURI": expanded(key)[0],
                    "value": value,
                }
                for key, value in node.attrib.items()
            ],
            "children": [serialized(child) for child in node],
        }

    try:
        parsed = serialized(ET.fromstring(fixture["xml"]))
    except ET.ParseError:
        parsed = None
    # Finite Node DOM doubles must remain actual standard-parser results; native
    # Chromium separately parses every raw XML string from this same fixture.
    assert parsed == fixture["parsed_document"]
    for validator in (appearance.validate_content, identity.validate_content):
        if fixture["accepted"]:
            validator(fixture["xml"].encode(), "image/svg+xml")
        else:
            with pytest.raises(ValueError):
                validator(fixture["xml"].encode(), "image/svg+xml")


def test_helper_produced_prefixed_pack_is_the_runtime_browser_fixture(
    tmp_path, monkeypatch
):
    fixtures = {fixture["name"]: fixture for fixture in SVG_CASES}
    folders = []
    for kind in ("active", "previous"):
        folder = tmp_path / kind
        folder.mkdir()
        (folder / "manifest.json").write_text(json.dumps(PACK[kind + "_manifest"]))
        (folder / "logo.svg").write_text(fixtures[PACK[kind + "_svg_case"]]["xml"])
        folders.append(folder)
    # This shared browser fixture represents an installed legacy-named pack.
    resource, projection = appearance.prepare(
        *folders, PACK["namespace"], resource_prefix="vnbui"
    )
    # Browser tests decode this exact immutable helper output, not a reconstructed
    # asset/manifest mock or a second implementation of the preparation algorithm.
    assert resource == PACK["resource"]
    assert projection == PACK["projection"]
    mounted = tmp_path / "mounted"
    for item in projection["items"]:
        target = mounted / item["path"]
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(base64.b64decode(resource["binaryData"][item["key"]]))
    monkeypatch.setenv("APPEARANCE_ROOT", str(mounted))
    assert identity.product_name() == "Prefixed SVG Backup"
    active_svg = mounted / "packs/prefixed-active/1.0.0/logo.svg"
    for fixture in SVG_CASES:
        if not fixture["accepted"]:
            active_svg.write_text(fixture["xml"])
            assert identity.product_name() == "Previous SVG Backup", fixture["name"]


def write_many_files_pack(root, identifier, count):
    root.mkdir()
    values = [f"v{i}" for i in range(16)]
    keys = [f"{a}/{b}" for a in values for b in values][:128]
    assets = {}
    for chunk, start in enumerate(range(0, count, 128)):
        filenames = [f"asset-{i:03}.svg" for i in range(start, min(start + 128, count))]
        for filename in filenames:
            (root / filename).write_text('<svg xmlns="http://www.w3.org/2000/svg"/>')
        assets[f"shape-{chunk}"] = {
            "content_type": "image/svg+xml",
            "variants": dict(zip(keys, filenames)),
            "default": filenames[0],
        }
    manifest = {
        "schema_version": 1,
        "id": identifier,
        "version": "1.0.0",
        "name": "Projection boundary",
        "type": "theme",
        "variant_schema": {
            name: {"values": values, "default": "v0"} for name in ("first", "second")
        },
        "assets": assets,
    }
    (root / "manifest.json").write_text(json.dumps(manifest))
    return root


def test_projection_allows_512_items_including_manifests_and_config(tmp_path):
    active = write_many_files_pack(tmp_path / "active", "active-bound", 255)
    previous = write_many_files_pack(tmp_path / "previous", "previous-bound", 254)
    _, projection = appearance.prepare(active, previous, "appearance-test")
    assert len(projection["items"]) == 512


def test_projection_513_items_fails_before_either_output_exists(tmp_path, monkeypatch):
    active = write_many_files_pack(tmp_path / "active", "active-bound", 255)
    previous = write_many_files_pack(tmp_path / "previous", "previous-bound", 255)
    output = tmp_path / "resource.json"
    projection = tmp_path / "projection.json"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "appearance.py",
            "--active",
            str(active),
            "--previous",
            str(previous),
            "--namespace",
            "appearance-test",
            "--output",
            str(output),
            "--projection-output",
            str(projection),
        ],
    )
    with pytest.raises(ValueError, match="512 projection"):
        appearance.main()
    assert not output.exists()
    assert not projection.exists()
