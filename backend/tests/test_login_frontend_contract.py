"""Run the frontend login contract in the blocking backend unit job."""

from pathlib import Path
import subprocess


def test_local_login_frontend_boundary():
    root = Path(__file__).resolve().parents[2]
    result = subprocess.run(
        [
            "node",
            "--experimental-vm-modules",
            "frontend/scripts/test-login-boundary.mjs",
        ],
        cwd=root,
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "PASS: OSS/commercial encoding" in result.stdout


def test_session_frontend_boundary():
    root = Path(__file__).resolve().parents[2]
    result = subprocess.run(
        [
            "node",
            "--experimental-vm-modules",
            "frontend/scripts/test-session-boundary.mjs",
        ],
        cwd=root,
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "PASS: session cleanup" in result.stdout


def test_profile_frontend_boundary():
    root = Path(__file__).resolve().parents[2]
    result = subprocess.run(
        [
            "node",
            "--experimental-vm-modules",
            "frontend/scripts/test-profile-boundary.mjs",
        ],
        cwd=root,
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "PASS: persisted profile" in result.stdout
