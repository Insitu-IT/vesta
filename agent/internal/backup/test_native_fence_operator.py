"""Operator CLI routing only; mocked ioctls are not filesystem qualification."""

import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import native_fence_operator as operator
import native_write_fence as fence
from test_libvirt_push import request, ATTEMPT


class OperatorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "attempts"
        self.path = self.root / ATTEMPT / "intent.json"
        self.path.parent.mkdir(parents=True)
        self.request = request(self.path.parent)
        self.path.write_bytes(fence.canonical(self.request))
        self.path.chmod(0o600)
        for name in ("root_managed_ancestry", "require_ext4_staging"):
            patcher = patch.object(fence, name)
            patcher.start()
            self.addCleanup(patcher.stop)
        patcher = patch.object(os, "geteuid", return_value=0)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_explicit_fenced_operator_issues_only_original_receipt(self):
        with patch.object(
            fence, "save_fence_receipt", return_value={"receipt": "original"}
        ) as save:
            result = operator.operate(
                self.root,
                self.path,
                action="fence",
                producer_fenced=True,
                reader_gid=1234,
            )
            self.assertEqual(result, {"receipt": "original"})
            save.assert_called_once_with(
                self.root.parent / "fence-receipts",
                self.request,
                producer_fenced=True,
                reader_gid=1234,
            )

    def test_inspection_does_not_enroll_or_change_flags(self):
        with (
            patch.object(
                fence, "read_fence_receipt", return_value={"proof": "original"}
            ) as read,
            patch.object(fence, "save_fence_receipt") as save,
        ):
            self.assertEqual(
                operator.operate(self.root, self.path, action="inspect"),
                {"proof": "original"},
            )
            read.assert_called_once()
            save.assert_not_called()

    def test_missing_fencing_or_reader_never_issues_receipt(self):
        with patch.object(fence, "save_fence_receipt") as save:
            for options in (
                {},
                {"producer_fenced": True},
                {"producer_fenced": True, "reader_gid": True},
            ):
                with (
                    self.subTest(options=options),
                    self.assertRaises(fence.FenceRefused),
                ):
                    operator.operate(self.root, self.path, action="fence", **options)
            save.assert_not_called()

    def test_different_request_path_cannot_be_adopted(self):
        other = self.path.with_name("replacement.json")
        other.write_bytes(self.path.read_bytes())
        other.chmod(0o600)
        with patch.object(fence, "save_fence_receipt") as save:
            with self.assertRaises(fence.FenceRefused):
                operator.operate(
                    self.root,
                    other,
                    action="fence",
                    producer_fenced=True,
                    reader_gid=1234,
                )
            save.assert_not_called()


if __name__ == "__main__":
    unittest.main()
