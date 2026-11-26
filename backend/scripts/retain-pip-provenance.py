"""Retain compact public archive provenance; raw pip metadata never ships."""

import argparse
import hashlib
from importlib.metadata import distributions, version
import json
import os
from pathlib import Path
import platform
import re
import sys
from urllib.parse import unquote_to_bytes, urlsplit


class ProvenanceError(RuntimeError):
    """Fixed errors must not echo credentials or unreviewed report fields."""


def current_environment():
    implementation = sys.implementation.version
    implementation_version = (
        f"{implementation.major}.{implementation.minor}.{implementation.micro}"
    )
    if implementation.releaselevel != "final":
        implementation_version += {"alpha": "a", "beta": "b", "candidate": "rc"}[
            implementation.releaselevel
        ]
        implementation_version += str(implementation.serial)
    return {
        "implementation_name": sys.implementation.name,
        "implementation_version": implementation_version,
        "os_name": os.name,
        "platform_machine": platform.machine(),
        "platform_release": platform.release(),
        "platform_system": platform.system(),
        "platform_version": platform.version(),
        "python_full_version": platform.python_version(),
        "platform_python_implementation": platform.python_implementation(),
        "python_version": f"{sys.version_info.major}.{sys.version_info.minor}",
        "sys_platform": sys.platform,
    }


def package_identity(name, selected_version):
    if not isinstance(name, str) or not re.fullmatch(
        r"[A-Za-z0-9](?:[A-Za-z0-9._-]{0,198}[A-Za-z0-9])?", name
    ):
        raise ProvenanceError("Invalid package identity in installation metadata")
    if not isinstance(selected_version, str) or not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9!+_.-]{0,99}", selected_version
    ):
        raise ProvenanceError("Invalid package version in installation metadata")
    return {"name": name, "version": selected_version}


def public_archive_url(value):
    # Current requirements resolve from public PyPI. Unknown mirrors/direct/VCS
    # origins need an explicit review; stripping tokens would lose exact identity.
    if not isinstance(value, str):
        raise ProvenanceError("Unreviewed archive origin in installation report")
    try:
        url = urlsplit(value)
    except ValueError:
        raise ProvenanceError(
            "Unreviewed archive origin in installation report"
        ) from None
    if (
        value != url.geturl()
        or url.scheme != "https"
        or url.netloc != "files.pythonhosted.org"
        or url.query
        or url.fragment
        or not re.fullmatch(
            r"/packages/[a-f0-9]{2}/[a-f0-9]{2}/[a-f0-9]{60}/"
            r"[A-Za-z0-9][A-Za-z0-9._+-]*\.(?:whl|tar\.gz|zip|tar\.bz2|tar\.xz)",
            url.path,
        )
    ):
        raise ProvenanceError("Unreviewed archive origin in installation report")
    return value


def archive_origin(value, sha256):
    if not isinstance(value, str):
        raise ProvenanceError("Unreviewed archive origin in installation report")
    try:
        url = urlsplit(value)
    except ValueError:
        raise ProvenanceError(
            "Unreviewed archive origin in installation report"
        ) from None
    if url.scheme != "file":
        return {"origin": "public-pypi", "url": public_archive_url(value)}
    # Offline wheelhouses are supported without retaining private mount paths.
    if (
        value != url.geturl()
        or url.netloc
        or url.query
        or url.fragment
        or not url.path.startswith("/")
    ):
        raise ProvenanceError("Unreviewed local archive origin in installation report")
    try:
        archive = Path(unquote_to_bytes(url.path).decode("utf-8"))
        if not re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9._+-]*\.(?:whl|tar\.gz|zip|tar\.bz2|tar\.xz)",
            archive.name,
        ):
            raise ProvenanceError("Unreviewed local archive basename")
        if not archive.is_file():
            raise ProvenanceError("Cannot verify local installation archive")
        digest = hashlib.sha256()
        with archive.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
    except (OSError, UnicodeError, ValueError):
        raise ProvenanceError("Cannot verify local installation archive") from None
    if digest.hexdigest() != sha256:
        raise ProvenanceError(
            "Local installation archive SHA256 differs from pip report"
        )
    return {
        "origin": "local-archive",
        "archive_basename": archive.name,
        "sha256_verified_from_archive": True,
    }


def compact_report(report, installed=None):
    if not isinstance(report, dict) or report.get("version") != "1":
        raise ProvenanceError("Unsupported pip installation report schema")
    if report.get("pip_version") != version("pip"):
        raise ProvenanceError(
            "Installation report pip version differs from build runtime"
        )
    environment = current_environment()
    reported_environment = report.get("environment", {})
    if not isinstance(reported_environment, dict) or any(
        reported_environment.get(key) != value for key, value in environment.items()
    ):
        raise ProvenanceError(
            "Installation report environment differs from build runtime"
        )
    entries = report.get("install")
    if not isinstance(entries, list) or not entries:
        raise ProvenanceError(
            "Installation report contains no downloaded distributions"
        )
    archives = []
    observed = set()
    for entry in entries:
        if not isinstance(entry, dict):
            raise ProvenanceError("Invalid distribution entry in installation report")
        metadata, download = entry.get("metadata", {}), entry.get("download_info", {})
        if not isinstance(metadata, dict) or not isinstance(download, dict):
            raise ProvenanceError("Invalid distribution entry in installation report")
        identity = package_identity(metadata.get("name"), metadata.get("version"))
        normalized = re.sub(r"[-_.]+", "-", identity["name"]).lower()
        if normalized in observed:
            raise ProvenanceError("Duplicate package identity in installation report")
        observed.add(normalized)
        archive_info = download.get("archive_info", {})
        hashes = (
            archive_info.get("hashes", {}) if isinstance(archive_info, dict) else {}
        )
        sha256 = hashes.get("sha256") if isinstance(hashes, dict) else None
        if not isinstance(sha256, str) or not re.fullmatch(r"[a-f0-9]{64}", sha256):
            raise ProvenanceError("Installation archive requires an exact SHA256")
        requested = entry.get("requested", False)
        if not isinstance(requested, bool):
            raise ProvenanceError(
                "Invalid requested-package flag in installation report"
            )
        archives.append(
            {
                **identity,
                **archive_origin(download.get("url"), sha256),
                "sha256": sha256,
                "requested": requested,
            }
        )
    if installed is None:
        installed = (
            (item.metadata.get("Name"), item.version) for item in distributions()
        )
    inventory = []
    installed_versions = {}
    for name, selected_version in installed:
        identity = package_identity(name, selected_version)
        normalized = re.sub(r"[-_.]+", "-", identity["name"]).lower()
        if normalized in installed_versions:
            # Some platforms expose the same site-packages through lib/lib64 aliases.
            if installed_versions[normalized] != identity["version"]:
                raise ProvenanceError("Ambiguous installed distribution inventory")
            continue
        installed_versions[normalized] = identity["version"]
        inventory.append(identity)
    for archive in archives:
        normalized = re.sub(r"[-_.]+", "-", archive["name"]).lower()
        if installed_versions.get(normalized) != archive["version"]:
            raise ProvenanceError(
                "Installation report differs from installed package versions"
            )
    inventory.sort(key=lambda item: item["name"].lower())
    return {
        "schema_version": 1,
        "pip_report_schema_version": "1",
        "pip_version": report["pip_version"],
        "environment": environment,
        "archive_hash_source": (
            "pip installation report archive_info.hashes.sha256; "
            "local archives additionally rehashed"
        ),
        "archives": sorted(archives, key=lambda item: item["name"].lower()),
        "installed_distributions": inventory,
        "coverage": "Archive records cover this pip invocation; pre-existing distributions may have no archive record.",
        "pruning_receipt": "python-pruning.json",
        "corresponding_source_fulfillment": False,
    }


def retain(raw_path, destination):
    try:
        try:
            report = json.loads(raw_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            raise ProvenanceError("Cannot read pip installation report") from None
        compact = compact_report(report)
    finally:
        # Also erase an unreviewed raw report on refusal; no later OCI layer keeps it.
        raw_path.unlink(missing_ok=True)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(compact, indent=2) + "\n", encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("raw_report", type=Path)
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    try:
        retain(args.raw_report, args.destination)
    except ProvenanceError as exc:
        raise SystemExit(str(exc)) from None


if __name__ == "__main__":
    main()
