import hashlib
import importlib.util
import io
import json
import subprocess
from pathlib import Path
import sys
from unittest.mock import patch

import pytest

from backend.tests.test_portable_okd import renderer, ROOT, sample_config


@pytest.fixture
def config():
    return sample_config()


# Match the standalone installer import environment for its shared supply policy.
sys.path.insert(0, str(ROOT / "packaging/okd"))
spec = importlib.util.spec_from_file_location(
    "portable_kit", ROOT / "packaging/okd/kit.py"
)
kit = importlib.util.module_from_spec(spec)
with patch.dict(sys.modules, {"render": renderer}):
    spec.loader.exec_module(kit)


def oci_fixture(folder, content=b"app only fixture"):
    folder.mkdir()
    blobs = folder / "blobs/sha256"
    blobs.mkdir(parents=True)

    def blob(content, media):
        data = content if isinstance(content, bytes) else json.dumps(content).encode()
        digest = hashlib.sha256(data).hexdigest()
        (blobs / digest).write_bytes(data)
        return {"digest": "sha256:" + digest, "size": len(data), "mediaType": media}

    config = blob({}, "application/vnd.oci.image.config.v1+json")
    layer = blob(content, "application/vnd.oci.image.layer.v1.tar")
    image = blob(
        {"schemaVersion": 2, "config": config, "layers": [layer]},
        "application/vnd.oci.image.manifest.v1+json",
    )
    (folder / "index.json").write_text(
        json.dumps({"schemaVersion": 2, "manifests": [image]})
    )
    (folder / "oci-layout").write_text('{"imageLayoutVersion":"1.0.0"}')
    return image["digest"]


def test_images_preserve_pinned_digests_through_offline_transport(
    config, tmp_path, monkeypatch
):
    calls = []
    pinned_digest = oci_fixture(tmp_path / "prototype")
    config["images"] = {
        key: value.rsplit("@", 1)[0] + "@" + pinned_digest
        for key, value in config["images"].items()
    }

    def run(argv, **kwargs):
        calls.append(argv)
        assert argv[:4] == ["skopeo", "copy", "--all", "--preserve-digests"]
        assert not any("creds" in arg or "tls-verify=false" in arg for arg in argv)
        digest = pinned_digest
        Path(argv[argv.index("--digestfile") + 1]).write_text(digest)
        if argv[-1].startswith("oci:"):
            folder = Path(argv[-1][4:].rsplit(":", 1)[0])
            assert oci_fixture(folder) == pinned_digest

    monkeypatch.setattr(kit.subprocess, "run", run)
    destination = tmp_path / "release"
    kit.export_images(config, destination)
    manifest = kit.verify(destination)
    assert manifest["kind"] == "images"
    assert manifest["metadata"]["images"] == {
        component: pinned_digest for component in ("backend", "frontend", "agent")
    }
    assert b"registry.test" not in (destination / "manifest.json").read_bytes()
    result = kit.import_images(destination, "onsite.test/backup")
    assert result["backend"] == "onsite.test/backup/backend@" + pinned_digest
    assert len(calls) == 6
    with pytest.raises(FileExistsError):
        kit.export_images(config, destination)


def test_image_kit_refuses_source_registry_references(config, tmp_path):
    images = tmp_path / "images"
    images.mkdir()
    kit.finish(images, "images", {"images": config["images"]})
    with pytest.raises(ValueError, match="image digests"):
        kit.verify(images)


def test_customer_inventory_refuses_symlinked_parent_directories(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "guide.md").write_text("private fixture")
    root = tmp_path / "source"
    root.mkdir()
    (root / "nested").symlink_to(outside, target_is_directory=True)
    assert not kit.regular_asset(root, "nested/guide.md")
    assert not kit.regular_asset(root, "../outside/guide.md")
    assert not kit.regular_asset(root, str(outside / "guide.md"))
    (root / "guide.md").write_text("public fixture")
    assert kit.regular_asset(root, "guide.md")


@pytest.mark.parametrize("problem", ["missing", "symlink", "operational-link"])
def test_runbooks_refuse_missing_unsafe_or_unbundled_operator_inputs(
    tmp_path, monkeypatch, problem
):
    source = tmp_path / "source"
    (source / "docs").mkdir(parents=True)
    original = source / "docs" / "guide.md"
    monkeypatch.setattr(kit, "RUNBOOK_ASSETS", {"docs/guide.md": "runbooks/guide.md"})
    if problem == "symlink":
        outside = tmp_path / "outside.md"
        outside.write_text("fixture")
        original.symlink_to(outside)
    elif problem == "operational-link":
        original.write_text("See [required procedure](missing.md).")
    with pytest.raises(ValueError, match="regular runbook|operational reference"):
        kit.copy_runbooks(source, tmp_path / "release")


@pytest.mark.parametrize("mutation", ["changed", "extra", "missing", "symlink"])
def test_modified_or_unsafe_kit_is_refused(tmp_path, mutation):
    root = tmp_path / "kit"
    root.mkdir()
    file = root / "archive.age"
    file.write_bytes(b"fixture-ciphertext")
    kit.finish(root, "control-plane", {})
    if mutation == "changed":
        file.write_bytes(b"wrong")
    elif mutation == "extra":
        (root / "unrecorded").write_bytes(b"wrong")
    elif mutation == "missing":
        file.unlink()
    else:
        (root / "link").symlink_to(file)
    with pytest.raises(ValueError):
        kit.verify(root)


def test_control_plane_streams_only_through_encryption_and_manifest_last(
    tmp_path, monkeypatch
):
    custody = tmp_path / "private-custody"
    custody.mkdir()
    (custody / "key-fixture").write_bytes(b"private-fixture")
    captured = {}

    def encrypt(producer, destination, recipients):
        stream = io.BytesIO()
        producer(stream)
        captured[destination.name] = stream.getvalue()
        # This tests orchestration, not age cryptography. Plain fixture bytes
        # stay in this test's memory; the archive file contains a fake marker.
        destination.write_bytes(b"encrypted-fixture")

    def dump(argv, **kwargs):
        assert argv == [
            "pg_dump",
            "--format=custom",
            "--no-owner",
            "--no-acl",
            "--dbname=service=fixture",
        ]
        kwargs["stdout"].write(b"custom-database-fixture")

    monkeypatch.setattr(kit, "encrypt_pipe", encrypt)
    monkeypatch.setattr(kit.subprocess, "run", dump)
    output = tmp_path / "sealed"
    kit.seal_control_plane(output, custody, tmp_path / "recipients", "fixture", True)
    assert set(captured) == {"database.dump.age", "custody.tar.age"}
    assert b"private-fixture" in captured["custody.tar.age"]
    assert kit.verify(output)["metadata"]["quiesced"] is True
    assert b"private-fixture" not in (output / "custody.tar.age").read_bytes()


def test_dump_failure_never_produces_accepted_kit(tmp_path, monkeypatch):
    custody = tmp_path / "custody"
    custody.mkdir()
    (custody / "key").write_bytes(b"fixture")

    def failure(producer, destination, recipients):
        raise subprocess.CalledProcessError(1, ["pg_dump"])

    monkeypatch.setattr(kit, "encrypt_pipe", failure)
    destination = tmp_path / "incomplete"
    with pytest.raises(subprocess.CalledProcessError):
        kit.seal_control_plane(
            destination, custody, tmp_path / "recipients", "fixture", True
        )
    assert not (destination / "manifest.json").exists()
    with pytest.raises(ValueError, match="Stop dispatch"):
        kit.seal_control_plane(
            tmp_path / "not-started", custody, tmp_path / "recipients", "fixture", False
        )


def test_age_process_is_streamed_and_success_is_fsynced(tmp_path, monkeypatch):
    class Process:
        def __init__(self, argv, **kwargs):
            assert argv == [
                "age",
                "--encrypt",
                "--recipients-file",
                str(tmp_path / "recipients"),
            ]
            self.stdin = io.BytesIO()
            kwargs["stdout"].write(b"ciphertext-fixture")

        def wait(self):
            return 0

    monkeypatch.setattr(kit.subprocess, "Popen", Process)
    destination = tmp_path / "encrypted.age"
    kit.encrypt_pipe(
        lambda stream: stream.write(b"private-fixture"),
        destination,
        tmp_path / "recipients",
    )
    assert destination.read_bytes() == b"ciphertext-fixture"
    assert destination.stat().st_mode & 0o777 == 0o600
