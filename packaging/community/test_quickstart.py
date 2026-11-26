"""Quickstart input, runtime separation and schema selection checks."""

import base64
import importlib.util
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

DIRECTORY = Path(__file__).resolve().parent


def load_script(filename):
    spec = importlib.util.spec_from_file_location(filename, DIRECTORY / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


initialize = load_script("init-local.py")
startup = load_script("start-local.py")


class QuickstartInputsTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name) / ".local"

    def test_credentials_and_project_name_are_private_stable_and_distinct(self):
        self.assertTrue(initialize.initialize(self.directory))
        self.assertEqual(stat.S_IMODE(self.directory.stat().st_mode), 0o700)

        contents = {path.name: path.read_bytes() for path in self.directory.iterdir()}
        passwords = {contents[name] for name in initialize.SECRET_FORMATS}
        self.assertEqual(len(passwords), len(initialize.SECRET_FORMATS))
        self.assertEqual(len(base64.urlsafe_b64decode(contents["fernet-key"])), 32)
        self.assertTrue(contents["admin-password"].endswith(b"Aa1!\n"))
        self.assertRegex(
            contents["compose.env"],
            rb"^COMPOSE_PROJECT_NAME=vesta-community-[0-9a-f]{12}\n$",
        )
        for name in initialize.SECRET_FORMATS:
            self.assertEqual(
                stat.S_IMODE((self.directory / name).stat().st_mode), 0o644
            )
            self.assertNotIn(contents[name].strip(), contents["compose.env"])
        self.assertEqual(
            stat.S_IMODE((self.directory / "compose.env").stat().st_mode), 0o600
        )

        self.assertFalse(initialize.initialize(self.directory))
        self.assertEqual(
            contents,
            {path.name: path.read_bytes() for path in self.directory.iterdir()},
        )

    def test_partial_directory_is_refused_without_populating_other_files(self):
        self.directory.mkdir(mode=0o700)
        path = self.directory / "owner-password"
        path.write_text("incomplete", encoding="ascii")
        path.chmod(0o644)
        with self.assertRaisesRegex(ValueError, "incomplete"):
            initialize.initialize(self.directory)
        self.assertEqual(list(self.directory.iterdir()), [path])
        self.assertEqual(path.read_text(encoding="ascii"), "incomplete")

    def test_truncated_file_in_otherwise_complete_directory_is_refused(self):
        initialize.initialize(self.directory)
        path = self.directory / "owner-password"
        path.write_text("incomplete", encoding="ascii")
        with self.assertRaisesRegex(ValueError, "incomplete"):
            initialize.initialize(self.directory)
        self.assertEqual(path.read_text(encoding="ascii"), "incomplete")

    def test_symlinked_secret_is_refused(self):
        initialize.initialize(self.directory)
        owner = self.directory / "owner-password"
        original = owner.read_bytes()
        runtime = self.directory / "runtime-password"
        runtime.unlink()
        runtime.symlink_to(owner)
        with self.assertRaisesRegex(ValueError, "incomplete"):
            initialize.initialize(self.directory)
        self.assertEqual(owner.read_bytes(), original)

    def test_initializer_reports_state_without_printing_secrets(self):
        copied = self.directory.with_name("init-local.py")
        copied.write_bytes((DIRECTORY / copied.name).read_bytes())
        completed = subprocess.run(
            [sys.executable, str(copied)], check=True, capture_output=True
        )
        self.assertIn(b"inputs created", completed.stdout)
        self.assertEqual(completed.stderr, b"")
        for name in initialize.SECRET_FORMATS:
            self.assertNotIn(
                (self.directory / name).read_bytes().strip(), completed.stdout
            )


class QuickstartStartupTest(unittest.TestCase):
    def test_migration_reads_only_owner_file(self):
        with patch.object(
            startup, "secret", return_value="test-owner"
        ) as read, patch.object(startup, "prepare_schema") as prepare, patch(
            "builtins.print"
        ):
            startup.main(["migrate"])
        read.assert_called_once_with("owner-password")
        prepare.assert_called_once_with(
            "postgresql://vesta_owner:test-owner@postgres:5432/vesta"
        )

    def test_runtime_reads_only_runtime_and_application_secrets(self):
        values = {
            "runtime-password": "test-runtime@password",
            "jwt-secret": "test-jwt",
            "fernet-key": "test-fernet",
        }
        with patch.object(
            startup, "secret", side_effect=values.__getitem__
        ) as read, patch.object(os, "execvpe") as execute, patch.dict(
            os.environ, clear=True
        ):
            startup.main(["serve"])
        self.assertEqual([call.args[0] for call in read.call_args_list], list(values))
        execute.assert_called_once_with(
            "opentelemetry-instrument",
            ["opentelemetry-instrument", "python", "server.py"],
            {
                "DATABASE_URL": "postgresql://vesta_runtime:test-runtime%40password@postgres:5432/vesta",
                "JWT_SECRET": "test-jwt",
                "VESTA_ENCRYPTION_KEY": "test-fernet",
            },
        )

    def test_database_error_is_not_exposed(self):
        with patch.object(startup, "secret", return_value="test-owner"), patch.object(
            startup, "prepare_schema", side_effect=RuntimeError("test-protected-detail")
        ):
            with self.assertRaisesRegex(SystemExit, "does not upgrade") as error:
                startup.main(["migrate"])
        self.assertNotIn("test-protected-detail", str(error.exception))


if __name__ == "__main__":
    unittest.main()
