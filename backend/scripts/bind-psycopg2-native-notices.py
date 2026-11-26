"""Bind original upstream-base notices to one reviewed installed wheel, not sources."""

import argparse
import hashlib
from importlib.metadata import distribution
import json
from pathlib import Path
import platform
import re
import sys

WHEEL_SHA256 = "977646e05232579d2e7b9c59e21dbe5261f403a88417f6a6512e70d3f8a046be"
REVIEW_SHA256 = "f772ec0e5084018c52995fba1e77242216b795a10ba693bcb1dcc7435afb7918"


class NativeNoticeError(RuntimeError):
    """Fixed errors never disclose installation metadata or private paths."""


def sha(path):
    if path.is_symlink() or not path.is_file():
        raise NativeNoticeError("Reviewed member must be a regular file")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def current_environment():
    return {
        "implementation_name": sys.implementation.name,
        "python_version": f"{sys.version_info.major}.{sys.version_info.minor}",
        "sys_platform": sys.platform,
        "platform_machine": platform.machine(),
    }


def load_review(notices):
    path = notices / "review.json"
    if sha(path) != REVIEW_SHA256:
        raise NativeNoticeError(
            "Native notice review changed; explicit review required"
        )
    review = json.loads(path.read_text())
    if (
        review.get("schema") != "vesta-psycopg2-native-review/1"
        or review.get("wheel_sha256") != WHEEL_SHA256
    ):
        raise NativeNoticeError("Unsupported native notice review")
    expected = {"review.json"} | {entry["file"] for entry in review["notice_sources"]}
    actual = {
        path.relative_to(notices).as_posix()
        for path in notices.rglob("*")
        if path.is_file() or path.is_symlink()
    }
    if actual != expected:
        raise NativeNoticeError("Native notice file inventory differs from review")
    for entry in review["notice_sources"]:
        if sha(notices / entry["file"]) != entry["sha256"]:
            raise NativeNoticeError("Original notice bytes differ from review")
    return review


def validate_installation(receipt, review, environment):
    if not isinstance(receipt, dict) or receipt.get("schema_version") != 1:
        raise NativeNoticeError("Unsupported Python installation receipt")
    expected = review["supported_environment"]
    if environment != expected or any(
        receipt.get("environment", {}).get(key) != value
        for key, value in expected.items()
    ):
        raise NativeNoticeError(
            "Native notices support only reviewed CPython3.11 Linux x86_64 wheel"
        )

    def normalize(value):
        return re.sub(r"[-_.]+", "-", value).lower()

    archives = [
        entry
        for entry in receipt.get("archives", [])
        if normalize(entry.get("name", "")) == "psycopg2-binary"
    ]
    installed = [
        entry
        for entry in receipt.get("installed_distributions", [])
        if normalize(entry.get("name", "")) == "psycopg2-binary"
    ]
    if (
        len(archives) != 1
        or len(installed) != 1
        or installed[0].get("version") != "2.9.9"
    ):
        raise NativeNoticeError(
            "Exact fresh psycopg2-binary installation record required"
        )
    archive = archives[0]
    if archive.get("version") != "2.9.9" or archive.get("sha256") != WHEEL_SHA256:
        raise NativeNoticeError("Unreviewed psycopg2-binary archive")
    if archive.get("origin") == "public-pypi":
        valid = archive.get("url") == review["wheel_url"]
    elif archive.get("origin") == "local-archive":
        valid = (
            archive.get("archive_basename") == review["wheel_filename"]
            and archive.get("sha256_verified_from_archive") is True
        )
    else:
        valid = False
    if not valid:
        raise NativeNoticeError("Unreviewed psycopg2-binary archive origin")
    return {key: archive[key] for key in ("name", "version", "sha256", "origin")}


def verify_installed_files(root, review):
    expected = {
        **review["native_members_sha256"],
        **review["wheel_control_members_sha256"],
    }
    for name, digest in expected.items():
        parts = Path(name).parts
        if (
            Path(name).is_absolute()
            or ".." in parts
            or any(
                (root / Path(*parts[:index])).is_symlink()
                for index in range(1, len(parts) + 1)
            )
            or sha(root / name) != digest
        ):
            raise NativeNoticeError(
                "Installed native/control bytes differ from reviewed wheel"
            )
    expected_private = {
        name
        for name in review["native_members_sha256"]
        if name.startswith("psycopg2_binary.libs/")
    }
    private = root / "psycopg2_binary.libs"
    if private.is_symlink():
        raise NativeNoticeError("Private library directory must not be a symlink")
    actual_private = {
        path.relative_to(root).as_posix()
        for path in private.rglob("*")
        if path.is_file() or path.is_symlink()
    }
    expected_extensions = set(review["native_members_sha256"]) - expected_private
    actual_extensions = {
        path.relative_to(root).as_posix()
        for path in (root / "psycopg2").rglob("*")
        if ".so" in path.name and (path.is_file() or path.is_symlink())
    }
    if actual_private != expected_private or actual_extensions != expected_extensions:
        raise NativeNoticeError(
            "Unknown installed native member; explicit wheel review required"
        )
    return expected


def bind(pip_receipt, notices, root, environment=None):
    review = load_review(notices)
    receipt = json.loads(pip_receipt.read_text())
    archive = validate_installation(
        receipt, review, current_environment() if environment is None else environment
    )
    members = verify_installed_files(root, review)
    return {
        "schema": "vesta-psycopg2-native-installation/1",
        "review_sha256": REVIEW_SHA256,
        "wheel_sha256": WHEEL_SHA256,
        "archive": archive,
        "pip_installation_receipt_sha256": sha(pip_receipt),
        "installed_members_sha256": members,
        "notice_files_sha256": {
            entry["file"]: entry["sha256"] for entry in review["notice_sources"]
        },
        "source_fulfilment_accepted": False,
        "scope": "Exact reviewed pip archive and installed native/control hashes only. "
        "Original upstream-base/family notices are supplements; downstream sources, "
        "patches, build provenance and complete compliance remain unresolved.",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pip_receipt", type=Path)
    parser.add_argument("notices", type=Path)
    args = parser.parse_args()
    package = distribution("psycopg2-binary")
    if package.version != "2.9.9":
        raise NativeNoticeError("Unreviewed installed psycopg2-binary version")
    result = bind(args.pip_receipt, args.notices, Path(package.locate_file("")))
    with (args.notices / "installation.json").open("x") as stream:
        json.dump(result, stream, indent=2)
        stream.write("\n")


if __name__ == "__main__":
    try:
        main()
    except (NativeNoticeError, OSError, ValueError, KeyError, TypeError):
        raise SystemExit(
            "Native notice binding refused; inspect reviewed wheel/profile/member identity, not raw credentials"
        ) from None
