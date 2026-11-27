#!/usr/bin/env python3
"""Portable image transport and encrypted, quiesced control-plane archives.

Commands never deploy, stop workloads, restore a database or delete a bucket.
Registry credentials use skopeo's auth file; PostgreSQL uses a libpq service.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import posixpath
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
from urllib.parse import urlsplit

# A transferred kit must remain byte-for-byte verifiable after invoking its own
# CLI; importing the local renderer must not create an unmanifested pycache.
sys.dont_write_bytecode = True
from render import STAGES, base_config, render, resource_name, validate, selected_delivery_profile  # noqa: E402

DELIVERY_PROFILES = ("full", "customer-postgresql")

INSTALL_ASSETS = (
    "LICENSE",
    "check_fresh_target.py",
    "config.example.json",
    "kit.py",
    "supply_contract.py",
    "supply-contract.json",
    "render.py",
    "reconcile_inputs.py",
    "reconfigure.py",
    "bootstrap_admin.py",
    "appearance.py",
    "license_keys.py",
    "secrets.example.yaml",
    "README.release.md",
    "postgres.py",
    "postgres-init.sh",
    "postgres.example.json",
    "diagnostics.py",
)

SITE_LAUNCHER_ASSETS = ("vesta", "install/vesta_site.py", "runbooks/site-manifest.md")
VM_PREFLIGHT_ASSET = "vm_readiness.py"

PREFLIGHT_ASSETS = (
    "README.md",
    "customer-preflight.sh",
    "customer-preflight-gates.sh",
    "customer-preflight-scope.sh",
)

# Shared repository helpers keep one source while shipping in the offline kit.
EXTERNAL_INSTALL_ASSETS = {"scripts/activate-agent-key.py": "activate-agent-key.py"}

# Earlier kits have no registration_documents receipt. New Community kits
# bind this closed set of offline files to their release manifest.
REGISTRATION_FILES = (
    "install/legal/terms.html",
    "install/legal/privacy.html",
    "install/legal/policy.json",
    "install/legal/verification-keys.json",
    "install/legal/NOTICE",
)


def install_asset_names():
    """Closed customer inventory: no recursive copy of tests or scratch files."""
    result = list(INSTALL_ASSETS)
    result.extend("preflight/" + name for name in PREFLIGHT_ASSETS)
    result.append(VM_PREFLIGHT_ASSET)
    for stage in STAGES:
        prefix = "kustomize/base/" + stage + "/"
        result.append(prefix + "kustomization.yaml")
        result.extend(
            prefix + resource_name(index, item)
            for index, item in enumerate(render(base_config(), stage, structural=True)["items"])
        )
    return tuple(result)


def regular_asset(root, name):
    relative = Path(name)
    if relative.is_absolute() or ".." in relative.parts:
        return False
    candidate = root
    for part in relative.parts:
        candidate = candidate / part
        if candidate.is_symlink():
            return False
    return candidate.is_file()


RUNBOOK_ASSETS = {
    "docs/operations/agent-key-rotation.md": "runbooks/agent-key-rotation.md",
    "packaging/okd/runbooks/installation.md": "portable-install-dr.md",
    "packaging/okd/runbooks/site-manifest.md": "runbooks/site-manifest.md",
    "packaging/okd/runbooks/reconfiguration.md": "runbooks/reconfiguration.md",
    "packaging/okd/runbooks/appearance.md": "runbooks/appearance.md",
    "packaging/okd/runbooks/licensing.md": "runbooks/licensing.md",
    "packaging/okd/runbooks/installed-profile.md": "runbooks/installed-profile.md",
    "packaging/okd/runbooks/first-configuration.md": "runbooks/first-configuration.md",
    "packaging/okd/runbooks/operations.md": "runbooks/operations.md",
    "packaging/okd/runbooks/native-backup-lifetime.md": "runbooks/native-backup-lifetime.md",
    "packaging/okd/runbooks/backup-safety.md": "runbooks/backup-safety.md",
    "packaging/okd/runbooks/held-backup-review.md": "runbooks/held-backup-review.md",
    "packaging/okd/runbooks/kubevirt-transfer-performance.md": "runbooks/kubevirt-transfer-performance.md",
    "packaging/okd/runbooks/restore.md": "runbooks/fresh-vm-restore.md",
    "packaging/okd/runbooks/file-backups.md": "runbooks/file-backups.md",
    "packaging/okd/runbooks/encryption-custody.md": "runbooks/encryption-custody.md",
    "packaging/okd/runbooks/bucket-recovery.md": "runbooks/bucket-recovery.md",
    "packaging/okd/runbooks/installation-key-rotation.md": "runbooks/installation-key-rotation.md",
    "packaging/rpm/README.files.md": "runbooks/file-agent.md",
    "agent/cmd/vnbui-restore/README.md": "runbooks/standalone-recovery.md",
    "packaging/okd/runbooks/upgrade-recovery.md": "runbooks/upgrade-recovery.md",
    "packaging/okd/runbooks/installation-checklist.md": "runbooks/installation-checklist.md",
    "packaging/okd/runbooks/postgresql.md": "runbooks/postgresql.md",
    "packaging/okd/runbooks/customer-postgresql.md": "runbooks/customer-postgresql.md",
    "packaging/okd/runbooks/supply-support.md": "runbooks/supply-support.md",
}


def copy_runbooks(source_root, destination):
    """Export only the dedicated customer guide inventory, never developer docs."""
    for source, target in RUNBOOK_ASSETS.items():
        original = source_root / source
        if not regular_asset(source_root, source):
            raise ValueError(f"Missing regular runbook: {source}")
        content = original.read_text()

        def link(match):
            label, address = match.groups()
            parsed = urlsplit(address)
            if parsed.scheme or parsed.netloc or not parsed.path:
                return match.group(0)
            reference = posixpath.normpath(
                posixpath.join(posixpath.dirname(source), parsed.path)
            )
            resolved = RUNBOOK_ASSETS.get(reference)
            if reference in EXTERNAL_INSTALL_ASSETS:
                resolved = "install/" + EXTERNAL_INSTALL_ASSETS[reference]
            if resolved is None and (
                reference == "packaging/okd" or reference.startswith("packaging/okd/")
            ):
                resolved = "install" + reference[len("packaging/okd") :]
            if resolved is None:
                raise ValueError(f"Unbundled operational reference: {reference}")
            relative = posixpath.relpath(resolved, posixpath.dirname(target) or ".")
            if parsed.fragment:
                relative += "#" + parsed.fragment
            return f"[{label}]({relative})"

        content = re.sub(r"\[([^\]]+)\]\(([^)]+)\)", link, content)
        output = destination / target
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(content)


def image_digests(metadata):
    """A transferred kit names immutable images, never its source registry."""
    images = metadata.get("images") if isinstance(metadata, dict) else None
    if (
        not isinstance(images, dict)
        or set(images)
        not in (
            {"backend", "frontend", "agent"},
            {"backend", "frontend", "agent", "postgres"},
        )
        or any(
            not isinstance(digest, str)
            or not re.fullmatch(r"sha256:[0-9a-f]{64}", digest)
            for digest in images.values()
        )
    ):
        raise ValueError(
            "Three application image digests and optional dedicated PostgreSQL required"
        )
    return images


def delivery_profile(metadata):
    profile = metadata.get("delivery_profile")
    if profile not in DELIVERY_PROFILES:
        raise ValueError("Explicit full or customer-postgresql delivery profile required")
    expected = {"backend", "frontend", "agent"}
    if profile == "full":
        expected.add("postgres")
    if set(image_digests(metadata)) != expected:
        raise ValueError("Delivery profile contradicts supplied image inventory")
    return profile


def verify_oci_inventory(root, images):
    """Verify closed OCI descriptor graphs, rejecting retained/unreferenced blobs.

    This proves transport closure and byte identity, not package-level legal or
    vulnerability qualification of the three application images.
    """
    expected_files = set()
    for component, digest in images.items():
        layout = root / component
        expected_files.update({component + ".digest", component + "/index.json", component + "/oci-layout"})
        if (root / (component + ".digest")).read_text().strip() != digest:
            raise ValueError("Image digest receipt differs from manifest")
        if json.loads((layout / "oci-layout").read_text()) != {"imageLayoutVersion": "1.0.0"}:
            raise ValueError("Unsupported OCI layout")
        index = json.loads((layout / "index.json").read_text())
        descriptors = index.get("manifests", [])
        if len(descriptors) != 1 or descriptors[0].get("digest") != digest:
            raise ValueError("OCI index must contain exactly the pinned image")
        visited = set()
        def visit(descriptor):
            value = descriptor.get("digest", "")
            if not re.fullmatch(r"sha256:[0-9a-f]{64}", value):
                raise ValueError("Only sha256 OCI descriptors supported")
            name = component + "/blobs/sha256/" + value[7:]
            path = root / name
            if not path.is_file() or sha(path) != value[7:] or path.stat().st_size != descriptor.get("size"):
                raise ValueError("OCI descriptor content/size mismatch")
            expected_files.add(name)
            if value in visited:
                return
            visited.add(value)
            media = descriptor.get("mediaType", "")
            if media.endswith("index.v1+json") or media.endswith("manifest.list.v2+json"):
                for child in json.loads(path.read_text())["manifests"]:
                    visit(child)
            elif media.endswith("manifest.v1+json") or media.endswith("manifest.v2+json"):
                manifest = json.loads(path.read_text())
                visit(manifest["config"])
                for child in manifest["layers"]:
                    visit(child)
            elif media not in {"application/vnd.oci.image.config.v1+json", "application/vnd.docker.container.image.v1+json"} and "layer" not in media and "rootfs.diff" not in media:
                raise ValueError("Unsupported OCI descriptor media type")
        visit(descriptors[0])
    actual = set(files(root)) - {"manifest.json"}
    if actual != expected_files:
        raise ValueError("Unexpected OCI files or retained/unreferenced image blobs")


def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def files(root):
    result = {}
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise ValueError(
                "Symlinks are not accepted in portable kits or custody archives"
            )
        if path.is_file():
            result[path.relative_to(root).as_posix()] = path
        elif not path.is_dir():
            raise ValueError("Only ordinary files/directories are accepted")
    return result


def finish(root, kind, metadata):
    if kind in {"images", "release"} and "delivery_profile" in metadata:
        from supply_contract import build_contract
        metadata = dict(metadata)
        metadata["supply_contract"] = build_contract(delivery_profile(metadata), metadata)
    entries = {name: sha(path) for name, path in files(root).items()}
    manifest = {
        "schema": "vnbui-portable-kit/1",
        "kind": kind,
        "metadata": metadata,
        "files": entries,
    }
    with (root / "manifest.json").open("x") as stream:
        json.dump(manifest, stream, indent=2)


def verify_registration_documents(manifest, actual):
    metadata = manifest["metadata"]
    receipt = metadata["registration_documents"]
    error = "Community registration document inventory or digest differs"
    policy_name = "install/legal/policy.json"
    if metadata.get("edition") != "community" or policy_name not in actual or not isinstance(receipt, dict):
        raise ValueError(error)
    policy = json.loads(actual[policy_name].read_bytes())
    if not isinstance(policy, dict):
        raise ValueError(error)
    names = set(REGISTRATION_FILES)
    if policy.get("release") != metadata.get("runtime_version"):
        binding_name = "install/legal/release-binding.json"
        if binding_name not in actual:
            raise ValueError(error)
        binding = json.loads(actual[binding_name].read_bytes())
        if binding != {"release": metadata["runtime_version"], "policy_release": policy.get("release"),
                       "policy_sha256": sha(actual[policy_name])}:
            raise ValueError(error)
        names.add(binding_name)
    documents = ["terms", "privacy"]
    if "eligibility" in policy:
        names.add("install/legal/eligibility.html")
        documents.append("eligibility")
        if not isinstance(policy["eligibility"], dict) or policy["eligibility"].get("version") != policy.get("schedule"):
            raise ValueError(error)
    if set(receipt) != names or any(name not in actual or manifest["files"].get(name) != receipt[name] for name in names):
        raise ValueError(error)
    for name in documents:
        document = policy.get(name)
        if not isinstance(document, dict) or document.get("sha256") != receipt[f"install/legal/{name}.html"]:
            raise ValueError(error)
    return names


def verify(root, *, local_site_manifest=False):
    root = Path(root)
    if root.is_symlink():
        raise ValueError("Kit root must not be a symlink")
    manifest = json.loads((root / "manifest.json").read_text())
    if (
        set(manifest) != {"schema", "kind", "metadata", "files"}
        or manifest["schema"] != "vnbui-portable-kit/1"
    ):
        raise ValueError("Unknown kit schema")
    actual = files(root)
    actual.pop("manifest.json")
    if local_site_manifest and manifest["kind"] == "release" and "vesta.json" not in manifest["files"]:
        actual.pop("vesta.json", None)
    if set(actual) != set(manifest["files"]):
        raise ValueError("Kit file inventory differs from manifest")
    if any(sha(path) != manifest["files"][name] for name, path in actual.items()):
        raise ValueError("Kit checksum mismatch")
    if manifest["kind"] in {"images", "release"}:
        image_digests(manifest["metadata"])
        if "delivery_profile" in manifest["metadata"]:
            delivery_profile(manifest["metadata"])
            from supply_contract import validate_contract
            if not isinstance(manifest["metadata"].get("supply_contract"), dict):
                raise ValueError("Missing supply contract receipt")
            validate_contract(manifest["metadata"].get("supply_contract"), manifest["metadata"]["images"], manifest["metadata"])
            if manifest["kind"] == "images":
                verify_oci_inventory(root, manifest["metadata"]["images"])
    if manifest["kind"] == "release":
        nested = verify(root / "images")
        if "delivery_profile" in manifest["metadata"]:
            allowed = {"install/" + name for name in install_asset_names()}
            allowed.update("install/" + name for name in EXTERNAL_INSTALL_ASSETS.values())
            allowed.update(RUNBOOK_ASSETS.values())
            allowed.difference_update(SITE_LAUNCHER_ASSETS)
            if manifest["metadata"].get("site_launcher") == 1:
                allowed.update(SITE_LAUNCHER_ASSETS)
                if not (root / "vesta").stat().st_mode & 0o111:
                    raise ValueError("Kit launcher is not executable")
            if "vm_preflight" not in manifest["metadata"]:
                allowed.remove("install/" + VM_PREFLIGHT_ASSET)
            elif type(manifest["metadata"]["vm_preflight"]) is not int or manifest["metadata"]["vm_preflight"] != 1:
                raise ValueError("Unknown VM preflight revision")
            allowed.update("images/" + name for name in files(root / "images"))
            if "registration_documents" in manifest["metadata"]:
                allowed.update(verify_registration_documents(manifest, actual))
            if set(actual) != allowed:
                raise ValueError("Unexpected supplied release files outside the closed customer inventory")
        if nested["metadata"].get("delivery_profile") != manifest["metadata"].get("delivery_profile"):
            raise ValueError("Bundled image delivery profile differs from release")
        if nested["kind"] != "images" or nested["metadata"].get("images") != manifest[
            "metadata"
        ].get("images"):
            raise ValueError("Bundled image kit differs from release manifest")
    return manifest


def assemble_release(image_source, destination, source_revision):
    """Assemble a self-contained, checksum-inventoried offline install tree."""
    if not re.fullmatch(r"[0-9a-f]{40}", source_revision):
        raise ValueError("Explicit 40-hex reviewed source revision required")
    image_source = Path(image_source)
    image_manifest = verify(image_source)
    if image_manifest["kind"] != "images":
        raise ValueError("An exported three-image kit is required")
    root = Path(destination)
    if root.exists():
        raise ValueError("Destination already exists")
    if root.resolve().is_relative_to(image_source.resolve()):
        raise ValueError("Destination must not be inside the image kit")
    assets = Path(__file__).resolve().parent
    inventory = install_asset_names()
    for name in (*inventory, "vesta", "vesta_site.py"):
        if not regular_asset(assets, name):
            raise ValueError(f"Missing regular install asset: {name}")
    root.mkdir(mode=0o700, parents=False)
    shutil.copytree(image_source, root / "images", symlinks=False)
    install = root / "install"
    install.mkdir()
    for name in inventory:
        target = install / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(assets / name, target)
    if "delivery_profile" in image_manifest["metadata"]:
        profile = delivery_profile(image_manifest["metadata"])
        example_path = install / "config.example.json"
        example = json.loads(example_path.read_text())
        example["delivery_profile"] = profile
        example_path.write_text(json.dumps(example, indent=2) + "\n")
        if profile == "customer-postgresql":
            base = base_config()
            base["delivery_profile"] = profile
            for stage in STAGES:
                for index, item in enumerate(render(base, stage, structural=True)["items"]):
                    target = install / "kustomize/base" / stage / resource_name(index, item)
                    target.write_text(json.dumps(item, indent=2) + "\n")
    for source, target in EXTERNAL_INSTALL_ASSETS.items():
        source_root = assets.parent.parent
        if not regular_asset(source_root, source):
            raise ValueError(f"Missing regular install helper: {source}")
        shutil.copy2(source_root / source, install / target)
    shutil.copy2(assets / "vesta", root / "vesta")
    shutil.copy2(assets / "vesta_site.py", install / "vesta_site.py")
    copy_runbooks(assets.parent.parent, root)
    finish(
        root,
        "release",
        {
            "source_revision": source_revision,
            "site_launcher": 1,
            "vm_preflight": 1,
            "source_revision_provenance": "operator-declared; verify OCI build provenance separately",
            **({"delivery_profile": image_manifest["metadata"]["delivery_profile"]} if "delivery_profile" in image_manifest["metadata"] else {}),
            "images": image_manifest["metadata"]["images"],
            "scope": "offline images, install renderer/base, preflight and runbook; no site credentials",
        },
    )
    verify(root)


def export_images(config, destination, postgres_config=None, profile=None):
    validate(config)
    profile = profile or ("full" if postgres_config is not None else "customer-postgresql")
    if profile not in DELIVERY_PROFILES or (profile == "full") != (postgres_config is not None):
        raise ValueError("full requires PostgreSQL config; customer-postgresql forbids it")
    sources = dict(config["images"])
    if postgres_config is not None:
        from postgres import validate as validate_postgres

        validate_postgres(postgres_config)
        sources["postgres"] = postgres_config["image"]
    root = Path(destination)
    root.mkdir(mode=0o700, parents=False, exist_ok=False)
    for component, source in sources.items():
        digest_file = root / (component + ".digest")
        subprocess.run(
            [
                "skopeo",
                "copy",
                "--all",
                "--preserve-digests",
                "--digestfile",
                str(digest_file),
                "docker://" + source,
                "oci:" + str(root.resolve() / component) + ":release",
            ],
            check=True,
        )
        if digest_file.read_text().strip() != source.split("@")[1]:
            raise ValueError("Exported image digest differs from pinned release")
    finish(
        root,
        "images",
        {
            "delivery_profile": profile,
            "images": {
                component: source.rsplit("@", 1)[1]
                for component, source in sources.items()
            }
        },
    )

    verify(root)


def import_images(source, registry):
    root = Path(source)
    manifest = verify(root)
    root = root.resolve()
    if (
        manifest["kind"] != "images"
        or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/-]*[A-Za-z0-9]", registry)
        or "://" in registry
    ):
        raise ValueError(
            "Image kit and explicit destination registry/repository required"
        )
    images = image_digests(manifest["metadata"])
    result = {}
    with tempfile.TemporaryDirectory(prefix="vnbui-image-import-") as temporary:
        for component, digest in images.items():
            target = registry.rstrip("/") + "/" + component
            receipt = Path(temporary) / component
            subprocess.run(
                [
                    "skopeo",
                    "copy",
                    "--all",
                    "--preserve-digests",
                    "--digestfile",
                    str(receipt),
                    "oci:" + str(root / component) + ":release",
                    "docker://" + target + ":kit-" + digest[7:19],
                ],
                check=True,
            )
            if receipt.read_text().strip() != digest:
                raise ValueError("Imported image digest differs from pinned release")
            result[component] = target + "@" + digest
    return result


def encrypt_pipe(producer, destination, recipients):
    """Write encrypted bytes exclusively; failed output never gets a kit manifest."""
    fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as output:
        process = subprocess.Popen(
            ["age", "--encrypt", "--recipients-file", str(recipients)],
            stdin=subprocess.PIPE,
            stdout=output,
        )
        try:
            producer(process.stdin)
            process.stdin.close()
            if process.wait() != 0:
                raise RuntimeError(
                    "age encryption failed; partial archive retained, not accepted"
                )
            output.flush()
            os.fsync(output.fileno())
        except BaseException:
            try:
                process.stdin.close()
            except BrokenPipeError:
                pass
            process.wait()
            raise


def seal_control_plane(destination, custody, recipients, service, quiesced, *,
                       profile=None, pg_host=None, pg_ca_file=None, config=None):
    if not quiesced:
        raise ValueError(
            "Stop dispatch/producers and snapshot persistent journals before sealing"
        )
    if not re.fullmatch(r"[A-Za-z0-9_-]+", service):
        raise ValueError(
            "Use an explicit libpq service name, never a URL/password in argv"
        )
    if config is not None and type(config) is not dict:
        raise ValueError("Site configuration must be a JSON object")
    site = dict(config or {})
    if profile is not None:
        if site.get("delivery_profile", profile) != profile:
            raise ValueError("Explicit delivery profile contradicts the site configuration")
        site["delivery_profile"] = profile
    selected = selected_delivery_profile(site)
    connection = "service=" + service
    if selected == "customer-postgresql":
        if (not isinstance(pg_host, str) or not pg_host
                or any(not item or "/" in item or "\\" in item or "@" in item
                       or any(character.isspace() for character in item)
                       for item in pg_host.split(","))):
            raise ValueError("Customer sealing requires explicit TCP --pg-host")
        if pg_ca_file is None or not Path(pg_ca_file).is_file():
            raise ValueError("Customer sealing requires an existing --pg-ca-file")
        def quote_parameter(value):
            return "'" + str(value).replace("\\", "\\\\").replace("'", "\\'") + "'"
        parameters = {"service": service, "host": pg_host,
                      "sslmode": "verify-full", "sslrootcert": str(Path(pg_ca_file).resolve()),
                      "gssencmode": "disable"}
        connection = " ".join(name + "=" + quote_parameter(value) for name, value in parameters.items())
    elif pg_host is not None or pg_ca_file is not None:
        raise ValueError("Explicit --pg-host/--pg-ca-file require customer-postgresql profile")
    custody = Path(custody)
    if custody.is_symlink() or not custody.is_dir():
        raise ValueError("Custody must be an explicit private directory snapshot")
    snapshot = files(custody)
    if not snapshot:
        raise ValueError(
            "Custody snapshot is empty; keys/configuration/journals are required"
        )
    root = Path(destination)
    root.mkdir(mode=0o700, parents=False, exist_ok=False)

    def database(stream):
        # pg_dump owns its consistent DB snapshot. Quiescence aligns that with
        # separately captured filesystem journals and encryption key custody.
        subprocess.run(
            [
                "pg_dump",
                "--format=custom",
                "--no-owner",
                "--no-acl",
                "--dbname=" + connection,
            ],
            stdout=stream,
            check=True,
        )

    def archive(stream):
        with tarfile.open(fileobj=stream, mode="w|") as target:
            for name, path in snapshot.items():
                before = path.stat()
                target.add(path, arcname=name, recursive=False)
                after = path.stat()
                if (before.st_ino, before.st_size, before.st_mtime_ns) != (
                    after.st_ino,
                    after.st_size,
                    after.st_mtime_ns,
                ):
                    raise ValueError("Custody snapshot changed while sealing")

    encrypt_pipe(database, root / "database.dump.age", recipients)
    encrypt_pipe(archive, root / "custody.tar.age", recipients)
    finish(
        root,
        "control-plane",
        {
            "delivery_profile": selected,
            "quiesced": True,
            "scope": "database, keys, configuration and journals; S3 payloads retained separately",
        },
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    export = commands.add_parser("export-images")
    export.add_argument("--config", required=True, type=Path)
    export.add_argument("--destination", required=True, type=Path)
    export.add_argument("--postgres-config", type=Path)
    export.add_argument("--profile", required=True, choices=DELIVERY_PROFILES)
    release = commands.add_parser("assemble-release")
    release.add_argument("--images", required=True, type=Path)
    release.add_argument("--destination", required=True, type=Path)
    release.add_argument("--source-revision", required=True)
    load = commands.add_parser("import-images")
    load.add_argument("--source", required=True, type=Path)
    load.add_argument("--registry", required=True)
    check = commands.add_parser("verify")
    check.add_argument("--source", required=True, type=Path)
    seal = commands.add_parser("seal-control-plane")
    seal.add_argument("--destination", required=True, type=Path)
    seal.add_argument("--custody", required=True, type=Path)
    seal.add_argument("--recipients", required=True, type=Path)
    seal.add_argument("--pg-service", required=True)
    seal.add_argument("--config", type=Path)
    seal.add_argument("--profile", choices=DELIVERY_PROFILES)
    seal.add_argument("--pg-host")
    seal.add_argument("--pg-ca-file", type=Path)
    seal.add_argument("--quiesced", action="store_true", required=True)
    args = parser.parse_args()
    if args.command == "export-images":
        export_images(
            json.loads(args.config.read_text()),
            args.destination,
            (
                json.loads(args.postgres_config.read_text())
                if args.postgres_config
                else None
            ),
            profile=args.profile,
        )
    elif args.command == "assemble-release":
        assemble_release(args.images, args.destination, args.source_revision)
    elif args.command == "import-images":
        print(json.dumps(import_images(args.source, args.registry), indent=2))
    elif args.command == "verify":
        manifest = verify(args.source)
        print("Kit checksums verified: " + manifest["kind"])
    else:
        seal_control_plane(
            args.destination,
            args.custody,
            args.recipients,
            args.pg_service,
            args.quiesced,
            profile=args.profile, pg_host=args.pg_host, pg_ca_file=args.pg_ca_file,
            config=json.loads(args.config.read_text()) if args.config else None,
        )


if __name__ == "__main__":
    main()
