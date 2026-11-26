"""Build-time notice collection must not manufacture terms or copy source."""

from pathlib import Path
import os
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[2]
COLLECT = ROOT / "agent/scripts/collect-third-party-notices.sh"


def run_collector(tmp_path, *, source=False, refuse=False, profile="kubevirt"):
    standard = tmp_path / "go-license"
    standard.write_text("Matching Go standard-library license\n")
    tool = tmp_path / "collector"
    tool.write_text(
        "#!/bin/sh\nset -eu\n"
        + ("exit 19\n" if refuse else "")
        + 'case "$1" in\ncheck) exit 0 ;;\nsave)\n'
        + 'for arg; do case "$arg" in --save_path=*) dest=${arg#--save_path=} ;; esac; done\n'
        + 'mkdir -p "$dest/public/module"\n'
        + 'printf "Full upstream license\\n" > "$dest/public/module/license.md"\n'
        + ('printf "source" > "$dest/public/module/LICENSE.go"\n' if source else "")
        + ";;\nesac\n"
    )
    tool.chmod(0o700)
    commands = tmp_path / "commands"
    commands.mkdir()
    go = commands / "go"
    go.write_text('#!/bin/sh\ntest "$1 $2" = "env GOVERSION"\nprintf "go1.26.9\\n"\n')
    go.chmod(0o700)
    destination = tmp_path / "output"
    result = subprocess.run(
        ["sh", str(COLLECT), str(destination), profile, str(standard)],
        env={
            **os.environ,
            "GO_LICENSES_BIN": str(tool),
            "PATH": str(commands) + os.pathsep + os.environ["PATH"],
        },
        capture_output=True,
        text=True,
    )
    return result, destination


@pytest.mark.parametrize("profile", ["default", "kubevirt", "libvirt"])
def test_preserves_case_insensitive_upstream_notices_and_matching_go_license(
    tmp_path, profile
):
    result, destination = run_collector(tmp_path, profile=profile)
    assert result.returncode == 0, result.stderr
    assert (
        destination / "agent/public/module/license.md"
    ).read_text() == "Full upstream license\n"
    assert (
        destination / "go/LICENSE"
    ).read_text() == "Matching Go standard-library license\n"
    if profile != "default":
        assert (
            destination / "restore/public/module/license.md"
        ).read_text() == "Full upstream license\n"
    assert profile + " binaries" in (destination / "NOTICE.txt").read_text()


def test_required_terms_review_stops_before_copying_any_documents(tmp_path):
    result, destination = run_collector(tmp_path, refuse=True)
    assert result.returncode == 19
    assert not destination.exists()


def test_source_in_legal_bundle_refuses(tmp_path):
    result, _ = run_collector(tmp_path, source=True)
    assert result.returncode != 0
    assert "Source or tooling" in result.stderr


@pytest.mark.parametrize("profile", ["older", "mock", "", "other"])
def test_unknown_build_profile_refuses(tmp_path, profile):
    result, destination = run_collector(tmp_path, profile=profile)
    assert result.returncode != 0
    assert not destination.exists()
