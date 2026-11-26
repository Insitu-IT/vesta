"""Exercise real automatic-policy UI handlers in the blocking unit job."""

from pathlib import Path
import subprocess

import pytest


@pytest.mark.parametrize(
    "script, marker",
    [
        ("test-schedule-policy.mjs", "PASS: automatic schedule form"),
        ("test-backup-policy-decision.mjs", "PASS: saved automatic backup decision"),
        ("test-verification.mjs", "PASS: receipt-bound verification controls"),
        ("test-health-diagnostics.mjs", "PASS: read-only health diagnostic download"),
        (
            "test-artifact-edition.mjs",
            "PASS: community artifact excludes commercial pages",
        ),
        ("test-admission-settings.mjs", "PASS: explicit safe admission settings"),
    ],
)
def test_schedule_policy_frontend_contract(script, marker):
    root = Path(__file__).resolve().parents[2]
    result = subprocess.run(
        [
            "node",
            "--experimental-vm-modules",
            "frontend/scripts/" + script,
        ],
        cwd=root,
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert marker in result.stdout
