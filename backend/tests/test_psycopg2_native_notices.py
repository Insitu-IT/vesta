"""Exact native-notice binding, without loading ELF code or installing packages."""

import copy
import hashlib
import importlib.util
from pathlib import Path
import shutil

import pytest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location(
    "native_notice_binding", ROOT / "backend/scripts/bind-psycopg2-native-notices.py"
)
binder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(binder)
NOTICES = ROOT / "backend/notices/psycopg2-native"


def reviewed():
    return binder.load_review(NOTICES)


def receipt():
    review = reviewed()
    return {
        "schema_version": 1,
        "environment": review["supported_environment"],
        "archives": [
            {
                "name": "psycopg2-binary",
                "version": "2.9.9",
                "sha256": binder.WHEEL_SHA256,
                "origin": "public-pypi",
                "url": review["wheel_url"],
            }
        ],
        "installed_distributions": [{"name": "psycopg2-binary", "version": "2.9.9"}],
    }


def test_original_documents_are_exact_and_unresolved_sources_remain_explicit():
    review = reviewed()
    assert len(review["native_members_sha256"]) == 15
    assert len(review["wheel_control_members_sha256"]) == 3
    assert review["source_fulfilment_accepted"] is False
    assert len((NOTICES / "krb5_krb5-krb5-1.15.1-final-NOTICE").read_bytes()) == 61301
    header = (NOTICES / "keyutils-v1.5.8-keyutils.c.license-header.txt").read_text()
    assert "2 of the License, or (at your option) any later version" in header
    assert "Version 2.1" in (NOTICES / "keyutils-v1.5.8-LICENCE.LGPL").read_text()
    assert "PCRE LICENCE" in (NOTICES / "pcre-8.32-LICENCE").read_text()
    bound = [
        row
        for row in review["components"]
        if "libselinux" in row["member"] or "libcom_err" in row["member"]
    ]
    assert len(bound) == 2
    for row in bound:
        mapping = row["runtime_rpm_binding"]
        assert mapping["gnu_build_id"] in row["build_ids"]
        assert set(mapping["equal_sections"]) == {".text", ".rodata"}
        assert mapping["different_sections"] == [".dynamic", ".dynstr", ".dynsym"]
        assert mapping["source_rpm"].endswith(".src.rpm")
        assert mapping["rpm_signature_verified"] is False
        assert row["notice_files"]


def test_review_tamper_or_notice_change_refuses_before_binding(tmp_path):
    target = tmp_path / "notices"
    shutil.copytree(NOTICES, target)
    (target / "pcre-8.32-LICENCE").write_text("shortened grant")
    with pytest.raises(binder.NativeNoticeError):
        binder.load_review(target)


def test_exact_public_and_rehashed_offline_archive_records_are_supported():
    review = reviewed()
    value = receipt()
    binder.validate_installation(value, review, review["supported_environment"])
    value["archives"][0] = {
        "name": "psycopg2-binary",
        "version": "2.9.9",
        "sha256": binder.WHEEL_SHA256,
        "origin": "local-archive",
        "archive_basename": review["wheel_filename"],
        "sha256_verified_from_archive": True,
    }
    binder.validate_installation(value, review, review["supported_environment"])


@pytest.mark.parametrize(
    "field,value",
    [
        ("sha256", "a" * 64),
        ("version", "2.9.10"),
        ("url", "https://unreviewed.invalid/wheel.whl"),
        ("origin", "mirror"),
    ],
)
def test_unknown_archive_or_version_is_not_relabelled(field, value):
    review, actual = reviewed(), receipt()
    actual["archives"][0][field] = value
    with pytest.raises(binder.NativeNoticeError):
        binder.validate_installation(actual, review, review["supported_environment"])


@pytest.mark.parametrize(
    "change",
    [
        "wrong-python",
        "wrong-arch",
        "missing-archive",
        "duplicate-archive",
        "wrong-installed",
    ],
)
def test_unsupported_or_ambiguous_profile_refuses(change):
    review, actual = reviewed(), receipt()
    environment = copy.deepcopy(review["supported_environment"])
    if change == "wrong-python":
        environment["python_version"] = "3.12"
    elif change == "wrong-arch":
        environment["platform_machine"] = "aarch64"
    elif change == "missing-archive":
        actual["archives"] = []
    elif change == "duplicate-archive":
        actual["archives"] *= 2
    else:
        actual["installed_distributions"][0]["version"] = "other"
    with pytest.raises(binder.NativeNoticeError):
        binder.validate_installation(actual, review, environment)


def fixture_files(root):
    names = {
        "psycopg2_binary.libs/library.so": b"native fixture",
        "psycopg2/_psycopg.fixture.so": b"extension fixture",
        "psycopg2_binary-2.9.9.dist-info/WHEEL": b"wheel control",
    }
    for name, body in names.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(body)
    return {
        "native_members_sha256": {
            name: hashlib.sha256(body).hexdigest()
            for name, body in names.items()
            if name.endswith(".so")
        },
        "wheel_control_members_sha256": {
            name: hashlib.sha256(body).hexdigest()
            for name, body in names.items()
            if not name.endswith(".so")
        },
    }


@pytest.mark.parametrize(
    "change", [None, "modified", "extra-private", "extra-extension", "symlink"]
)
def test_installed_native_inventory_is_closed_and_bytes_match(tmp_path, change):
    review = fixture_files(tmp_path)
    file = tmp_path / "psycopg2_binary.libs/library.so"
    if change == "modified":
        file.write_bytes(b"different")
    elif change == "extra-private":
        (tmp_path / "psycopg2_binary.libs/unknown.so").write_bytes(b"extra")
    elif change == "extra-extension":
        (tmp_path / "psycopg2/unknown.so").write_bytes(b"extra")
    elif change == "symlink":
        file.unlink()
        file.symlink_to(tmp_path / "psycopg2/_psycopg.fixture.so")
    if change:
        with pytest.raises(binder.NativeNoticeError):
            binder.verify_installed_files(tmp_path, review)
    else:
        assert len(binder.verify_installed_files(tmp_path, review)) == 3


def check_backend_install_layer(filename, prefix):
    text = (ROOT / filename).read_text()
    assert (
        f"COPY {prefix}notices/psycopg2-native/ /usr/share/licenses/vnbui/psycopg2-native/"
        in text
    )
    assert (
        "&& python /tmp/bind-psycopg2-native-notices.py /usr/share/licenses/vnbui/python-installation.json"
        in text
    )
    assert text.index(
        "retain-pip-provenance.py /tmp/vesta-pip-install.json"
    ) < text.index("&& python /tmp/bind-psycopg2-native-notices.py")


def test_community_backend_install_layer_requires_binding_and_notice_payload():
    check_backend_install_layer("backend/Dockerfile", "")


def test_matched_runtime_original_notices_keep_full_special_terms():
    selinux = (NOTICES / "libselinux-2.5-LICENSE").read_text()
    assert "Warranty Exclusion" in selinux and "Limitation of Liability" in selinux
    copying = (NOTICES / "libcom_err-1.42.9-19.el7-COPYING").read_text()
    assert "MIT-style license" in copying and "source file headers" in copying
    header = (NOTICES / "e2fsprogs-v1.42.9-com_err.c.license-header.txt").read_text()
    assert "Copyright 1987, 1988 by MIT Student Information Processing Board." in header
    assert "advertising or publicity" in header
    assert "specific, written prior permission" in header
    assert "without" in header and "express or implied warranty" in header
