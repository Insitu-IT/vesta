"""Installation receipts retain exact public archives without raw report secrets."""

import copy
import importlib.util
import hashlib
from importlib.metadata import version
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/retain-pip-provenance.py"
spec = importlib.util.spec_from_file_location("pip_provenance", SCRIPT)
provenance = importlib.util.module_from_spec(spec)
spec.loader.exec_module(provenance)
URL = (
    "https://files.pythonhosted.org/packages/1c/13/"
    "bc43591a54dd38ac5c19e7e849f0311d879737a0d07e032e5be79849a5fb/"
    "reportlab-4.5.0-py3-none-any.whl"
)
SHA256 = "b8cc8996947d84e805368b47b2376070966f091d029351a0d8a1f238984c2c7f"
SECRET = "PRIVATE_SITE_TOKEN_MUST_NOT_SHIP"


def report():
    return {
        "version": "1",
        "pip_version": version("pip"),
        "environment": provenance.current_environment(),
        "install": [
            {
                "metadata": {
                    "name": "reportlab",
                    "version": "4.5.0",
                    "description": SECRET,
                },
                "download_info": {
                    "url": URL,
                    "archive_info": {"hashes": {"sha256": SHA256}},
                },
                "requested": True,
            }
        ],
    }


def test_receipt_preserves_exact_archive_and_actual_environment_without_extra_values(
    monkeypatch,
):
    monkeypatch.setenv("VESTA_PRIVATE_SITE_TOKEN", SECRET)
    source = report()
    source["environment"]["DATABASE_URL"] = SECRET
    source["index_url"] = "https://private:" + SECRET + "@mirror.invalid/simple"
    source["install"][0]["metadata"]["requires_dist"] = [SECRET]
    result = provenance.compact_report(
        source, [("reportlab", "4.5.0"), ("pip", version("pip"))]
    )
    assert result["archives"] == [
        {
            "name": "reportlab",
            "version": "4.5.0",
            "origin": "public-pypi",
            "url": URL,
            "sha256": SHA256,
            "requested": True,
        }
    ]
    assert result["environment"] == provenance.current_environment()
    assert result["pip_version"] == version("pip")
    assert SECRET not in json.dumps(result)
    assert result["corresponding_source_fulfillment"] is False
    assert result["pruning_receipt"] == "python-pruning.json"
    assert {item["name"] for item in result["installed_distributions"]} == {
        "pip",
        "reportlab",
    }


@pytest.mark.parametrize(
    "url",
    [
        URL.replace("https://", "https://private:" + SECRET + "@"),
        URL + "?token=" + SECRET,
        URL + "#token=" + SECRET,
        URL.replace("https://", "http://"),
        URL.replace("files.pythonhosted.org", "mirror.invalid"),
        URL.replace("files.pythonhosted.org", "files.pythonhosted.org:443"),
        URL.replace("/packages/", "/" + SECRET + "/packages/"),
        "file:///private/" + SECRET + "/package.whl",
        "\n" + URL,
        URL.replace("reportlab-", "%72eportlab-"),
    ],
)
def test_unreviewed_or_credential_bearing_origins_fail_without_echo(url):
    source = report()
    source["install"][0]["download_info"]["url"] = url
    with pytest.raises(provenance.ProvenanceError) as refused:
        provenance.compact_report(source, [("reportlab", "4.5.0")])
    assert SECRET not in str(refused.value)
    assert url not in str(refused.value)


@pytest.mark.parametrize(
    "mutation",
    ["missing_hash", "bad_hash", "wrong_python", "wrong_pip", "vcs", "duplicate"],
)
def test_incomplete_or_mismatched_report_cannot_become_a_receipt(mutation):
    source = report()
    entry = source["install"][0]
    if mutation == "missing_hash":
        entry["download_info"]["archive_info"]["hashes"] = {}
    elif mutation == "bad_hash":
        entry["download_info"]["archive_info"]["hashes"]["sha256"] = SECRET
    elif mutation == "wrong_python":
        source["environment"]["python_full_version"] = "0.0.0"
    elif mutation == "wrong_pip":
        source["pip_version"] = "0.0.0"
    elif mutation == "vcs":
        entry["download_info"] = {
            "url": "https://private.invalid/" + SECRET,
            "vcs_info": {"vcs": "git"},
        }
    else:
        source["install"].append(copy.deepcopy(entry))
    with pytest.raises(provenance.ProvenanceError) as refused:
        provenance.compact_report(source, [("reportlab", "4.5.0")])
    assert SECRET not in str(refused.value)


@pytest.mark.parametrize(
    "installed",
    [[], [("reportlab", "4.2.5")], [("reportlab", "4.5.0"), ("ReportLab", "4.2.5")]],
)
def test_receipt_must_match_unambiguous_installed_versions(installed):
    with pytest.raises(provenance.ProvenanceError):
        provenance.compact_report(report(), installed)


@pytest.mark.parametrize("unsafe", [False, True])
def test_raw_report_erased_on_success_and_refusal(monkeypatch, tmp_path, unsafe):
    source = report()
    if unsafe:
        source["install"][0]["download_info"]["url"] += "?token=" + SECRET
    raw = tmp_path / "raw.json"
    raw.write_text(json.dumps(source))
    destination = tmp_path / "notices/python-installation.json"
    monkeypatch.setattr(
        provenance,
        "distributions",
        lambda: [
            SimpleNamespace(
                metadata={"Name": "reportlab"},
                version="4.5.0",
            )
        ],
    )
    if unsafe:
        with pytest.raises(provenance.ProvenanceError):
            provenance.retain(raw, destination)
        assert not destination.exists()
    else:
        provenance.retain(raw, destination)
        result = json.loads(destination.read_text())
        assert result["archives"][0]["sha256"] == SHA256
        assert SECRET not in destination.read_text()
    assert not raw.exists()


def test_same_version_metadata_aliases_do_not_duplicate_inventory():
    result = provenance.compact_report(
        report(), [("reportlab", "4.5.0"), ("ReportLab", "4.5.0")]
    )
    assert result["installed_distributions"] == [
        {"name": "reportlab", "version": "4.5.0"}
    ]


def local_report(tmp_path):
    private = tmp_path / ("private wheelhouse " + SECRET)
    private.mkdir()
    archive = private / "reviewed-1.0-py3-none-any.whl"
    archive.write_bytes(b"reviewed archive byte fixture")
    source = report()
    source["install"][0]["download_info"]["url"] = archive.as_uri()
    source["install"][0]["download_info"]["archive_info"]["hashes"]["sha256"] = (
        hashlib.sha256(archive.read_bytes()).hexdigest()
    )
    return source, archive


def test_local_wheelhouse_receipt_rehashes_bytes_without_private_mount_path(tmp_path):
    source, archive = local_report(tmp_path)
    result = provenance.compact_report(source, [("reportlab", "4.5.0")])
    entry = result["archives"][0]
    assert entry["origin"] == "local-archive"
    assert entry["archive_basename"] == archive.name
    assert entry["sha256"] == hashlib.sha256(archive.read_bytes()).hexdigest()
    assert entry["sha256_verified_from_archive"] is True
    assert "url" not in entry
    assert SECRET not in json.dumps(result)
    assert str(tmp_path) not in json.dumps(result)


@pytest.mark.parametrize(
    "change", ["query", "userinfo", "fragment", "changed_bytes", "missing"]
)
def test_local_archive_secrets_or_unverified_bytes_cannot_ship(tmp_path, change):
    source, archive = local_report(tmp_path)
    download = source["install"][0]["download_info"]
    if change == "query":
        download["url"] += "?token=" + SECRET
    elif change == "userinfo":
        download["url"] = download["url"].replace(
            "file://", "file://private:" + SECRET + "@localhost"
        )
    elif change == "fragment":
        download["url"] += "#" + SECRET
    elif change == "changed_bytes":
        archive.write_bytes(b"different bytes after installation")
    else:
        archive.unlink()
    with pytest.raises(provenance.ProvenanceError) as refused:
        provenance.compact_report(source, [("reportlab", "4.5.0")])
    assert SECRET not in str(refused.value)
    assert str(tmp_path) not in str(refused.value)
