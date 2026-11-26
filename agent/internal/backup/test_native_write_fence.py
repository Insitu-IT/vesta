"""Original-inode and failure-boundary tests; ioctl mocks are not filesystem proof."""

import errno
import json
import os
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import native_write_fence as fence


class FenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.attempt = Path(self.temp.name) / "attempt"
        self.attempt.mkdir(mode=0o711)
        data = self.attempt / "data"
        data.mkdir(mode=0o711)
        self.target = data / "vda.qcow2"
        self.target.write_bytes(b"failed, never publish this image")
        self.request = {
            "output_path": str(self.attempt),
            "disks": [{"target": "vda"}],
            "exclusions": [],
        }
        self.binding = {
            "schema": "libvirt-target-binding/1",
            "request_sha256": fence.hashlib.sha256(
                fence.canonical(self.request)
            ).hexdigest(),
            "directory": fence.identity(self.attempt.stat()),
            "data_directory": fence.identity(data.stat()),
            "targets": {"vda": fence.identity(self.target.stat())},
            "backup_xml_sha256": "a" * 64,
            "checkpoint_xml_sha256": "b" * 64,
        }
        self.record("intent.json", self.request)
        self.record("target-binding.json", self.binding)
        self.record(
            "begin-intent.json",
            {
                "schema": "libvirt-begin-intent/1",
                "request_sha256": self.binding["request_sha256"],
            },
        )
        self.immutable = []

    def record(self, name, value):
        path = self.attempt / name
        path.write_bytes(fence.canonical(value))
        path.chmod(0o600)

    def run_fence(self, enable=None, immutable=None):
        with (
            patch.object(fence, "root_managed_ancestry"),
            patch.object(
                fence,
                "make_immutable",
                side_effect=immutable
                or (lambda fd: self.immutable.append(fence.identity(os.fstat(fd)))),
            ),
            patch.object(
                fence,
                "enable_verity",
                side_effect=enable or (lambda fd: "c" * 64),
            ),
        ):
            return fence.fence_attempt(self.request, producer_fenced=True)

    def test_no_default_authority(self):
        with self.assertRaises(fence.FenceRefused):
            fence.fence_attempt(self.request)

    def test_mutable_ancestor_refused(self):
        with self.assertRaises(fence.FenceRefused):
            fence.root_managed_ancestry(self.attempt)

    def test_exact_original_target_and_no_success_claim(self):
        result = self.run_fence()
        self.assertEqual(result["schema"], "libvirt-failed-output-fence/1")
        self.assertEqual(result["artifacts"][0]["inode"], self.target.stat().st_ino)
        self.assertEqual(
            self.immutable[:2],
            [self.binding["directory"], self.binding["data_directory"]],
        )
        self.assertFalse((self.attempt / "producer-sealed.json").exists())
        self.assertEqual(self.target.read_bytes(), b"failed, never publish this image")

    def test_writer_refusal_keeps_partial_fences(self):
        def busy(fd):
            raise OSError(errno.ETXTBSY, "writer remains")

        with self.assertRaises(OSError):
            self.run_fence(enable=busy)
        self.assertEqual(len(self.immutable), 2)

    def test_restart_inspection_never_enrolls_or_changes_flags(self):
        with (
            patch.object(fence, "root_managed_ancestry"),
            patch.object(fence, "flags", return_value=fence.IMMUTABLE) as flags,
            patch.object(fence, "verity_digest", return_value="c" * 64),
            patch.object(fence, "enable_verity") as enroll,
            patch.object(fence, "make_immutable") as protect,
        ):
            proof = fence.inspect_fence(self.request)
            self.assertEqual(proof["artifacts"][0]["verity_sha256"], "c" * 64)
            enroll.assert_not_called()
            protect.assert_not_called()
            flags.return_value = 0
            with self.assertRaises(fence.FenceRefused):
                fence.inspect_fence(self.request)
            enroll.assert_not_called()
            protect.assert_not_called()

    def test_replaced_inode_refused_before_any_mutation(self):
        self.target.rename(self.target.with_suffix(".old"))
        self.target.write_bytes(b"replacement")
        with self.assertRaises(fence.FenceRefused):
            self.run_fence()
        self.assertFalse(self.immutable)

    def test_allocator_rejects_invalid_identity_and_capacity(self):
        req = {
            "attempt_id": "11111111-1111-4111-8111-111111111111",
            "output_path": "unused",
        }
        for uid, reserved in [(0, 1), (True, 1), (1000, 0), (1000, True)]:
            with (
                self.subTest(uid=uid, reserved=reserved),
                patch.object(fence.os, "geteuid", return_value=0),
            ):
                with self.assertRaises(fence.FenceRefused):
                    fence.allocate_attempt(
                        self.attempt,
                        req,
                        uid=uid,
                        gid=1000,
                        reserved_bytes=reserved,
                        capacity_bytes=10,
                        minimum_free_bytes=1,
                    )

    def test_allocator_capacity_and_exclusive_original_slot(self):
        root = Path(self.temp.name) / "root"
        root.mkdir()
        aid = "11111111-1111-4111-8111-111111111111"
        req = {"attempt_id": aid, "output_path": str(root / aid)}
        real_fstat = os.fstat

        def root_stat(fd):
            st = real_fstat(fd)
            return SimpleNamespace(
                st_uid=0,
                st_gid=0,
                st_mode=st.st_mode,
                st_nlink=st.st_nlink,
                st_dev=st.st_dev,
                st_ino=st.st_ino,
            )

        with (
            patch.object(fence.os, "geteuid", return_value=0),
            patch.object(fence, "root_managed_ancestry"),
            patch.object(fence, "require_ext4_staging"),
            patch.object(fence, "make_immutable"),
            patch.object(fence, "flags", return_value=fence.IMMUTABLE),
            patch.object(fence.os, "fchown"),
            patch.object(fence.os, "fstat", side_effect=root_stat),
        ):
            allocation = fence.allocate_attempt(
                root,
                req,
                uid=1000,
                gid=1000,
                reserved_bytes=2,
                capacity_bytes=4,
                minimum_free_bytes=1,
            )
            self.assertEqual(
                allocation["request_sha256"],
                fence.hashlib.sha256(fence.canonical(req)).hexdigest(),
            )
            marker = root / aid / "allocation.json"
            original = marker.read_bytes()
            with self.assertRaises(FileExistsError):
                fence.allocate_attempt(
                    root,
                    req,
                    uid=1000,
                    gid=1000,
                    reserved_bytes=2,
                    capacity_bytes=4,
                    minimum_free_bytes=1,
                )
            other = "22222222-2222-4222-8222-222222222222"
            with self.assertRaises(fence.FenceRefused):
                fence.allocate_attempt(
                    root,
                    {"attempt_id": other, "output_path": str(root / other)},
                    uid=1000,
                    gid=1000,
                    reserved_bytes=3,
                    capacity_bytes=4,
                    minimum_free_bytes=1,
                )
            self.assertFalse((root / other).exists())
            self.assertEqual(marker.read_bytes(), original)

    def test_path_replacement_during_freeze_refused(self):
        def swap(fd):
            if fence.identity(os.fstat(fd)) == self.binding["data_directory"]:
                self.target.rename(self.target.with_suffix(".old"))
                self.target.write_bytes(b"replacement")

        with self.assertRaises(fence.FenceRefused):
            self.run_fence(immutable=swap)

    def test_missing_binding_and_contradictions_refused(self):
        for name in (
            "producer-sealed.json",
            "producer-closed-failure.json",
            "prebegin-refusal.json",
            "admission.json",
            "published.json",
        ):
            with self.subTest(name=name):
                self.record(name, {})
                with self.assertRaises(fence.FenceRefused):
                    self.run_fence()
                (self.attempt / name).unlink()
        (self.attempt / "target-binding.json").unlink()
        with self.assertRaises(FileNotFoundError):
            self.run_fence()

    def test_request_and_directory_binding_cannot_be_changed(self):
        for field in (
            "request_sha256",
            "directory",
            "data_directory",
            "targets",
        ):
            with self.subTest(field=field):
                wrong = dict(self.binding)
                wrong[field] = None
                self.record("target-binding.json", wrong)
                with self.assertRaises((fence.FenceRefused, TypeError)):
                    self.run_fence()
        self.record("target-binding.json", self.binding)

    def test_symlink_and_hardlink_targets_refused(self):
        original = self.target.with_suffix(".original")
        self.target.rename(original)
        self.target.symlink_to(original)
        with self.assertRaises(OSError):
            self.run_fence()
        self.target.unlink()
        os.link(original, self.target)
        with self.assertRaises(fence.FenceRefused):
            self.run_fence()


class ReceiptTests(unittest.TestCase):
    def test_group_readable_receipt_replays_and_rechecks_current_kernel(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            req = {
                "attempt_id": "11111111-1111-4111-8111-111111111111",
                "output_path": "/original/attempt",
            }
            proof = {"schema": "libvirt-failed-output-fence/1", "bound": "original"}
            with (
                patch.object(fence, "root_managed_ancestry"),
                patch.object(fence, "fence_attempt", return_value=proof) as enroll,
                patch.object(fence, "inspect_fence", return_value=proof) as inspect,
            ):
                saved = fence.save_fence_receipt(
                    root, req, producer_fenced=True, reader_gid=1234
                )
                path = root / (req["attempt_id"] + ".json")
                self.assertEqual(path.stat().st_mode & 0o777, 0o640)
                self.assertEqual((path.stat().st_uid, path.stat().st_gid), (0, 1234))
                self.assertEqual(fence.read_fence_receipt(root, req), proof)
                self.assertEqual(
                    fence.save_fence_receipt(root, req, reader_gid=1234), saved
                )
                self.assertEqual(enroll.call_count, 1)
                with self.assertRaises(fence.FenceRefused):
                    fence.save_fence_receipt(root, req, reader_gid=1235)
                inspect.return_value = {"bound": "changed"}
                with self.assertRaises(fence.FenceRefused):
                    fence.read_fence_receipt(root, req)
                self.assertEqual(json.loads(path.read_text()), saved)

    def test_absent_receipt_is_not_closure_and_bad_permissions_hold(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            req = {
                "attempt_id": "11111111-1111-4111-8111-111111111111",
                "output_path": "/original/attempt",
            }
            with (
                patch.object(fence, "root_managed_ancestry"),
                patch.object(fence, "inspect_fence") as inspect,
            ):
                self.assertIsNone(fence.read_fence_receipt(root, req))
                inspect.assert_not_called()
                path = root / (req["attempt_id"] + ".json")
                for mode in (0o644, 0o660, 0o650):
                    path.write_bytes(b"{}")
                    path.chmod(mode)
                    with self.assertRaises(fence.FenceRefused):
                        fence.read_fence_receipt(root, req)
                    inspect.assert_not_called()

    def test_receipt_directory_must_not_poison_allocation_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            req = {
                "attempt_id": "11111111-1111-4111-8111-111111111111",
                "output_path": str(root / "attempt"),
            }
            with (
                patch.object(fence, "root_managed_ancestry"),
                patch.object(fence, "fence_attempt") as enroll,
            ):
                with self.assertRaises(fence.FenceRefused):
                    fence.save_fence_receipt(root, req, producer_fenced=True)
                enroll.assert_not_called()

    def test_receipt_replay_is_read_only_and_rejects_changed_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            req = {
                "attempt_id": "11111111-1111-4111-8111-111111111111",
                "output_path": "/original/attempt",
            }
            proof = {"schema": "libvirt-failed-output-fence/1", "bound": "original"}
            with (
                patch.object(fence.os, "geteuid", return_value=0),
                patch.object(fence, "root_managed_ancestry"),
                patch.object(fence, "fence_attempt", return_value=proof) as enroll,
                patch.object(fence, "inspect_fence", return_value=proof) as inspect,
            ):
                first = fence.save_fence_receipt(root, req, producer_fenced=True)
                second = fence.save_fence_receipt(root, req)
                self.assertEqual(first, second)
                self.assertEqual(enroll.call_count, 1)
                self.assertGreaterEqual(inspect.call_count, 2)
                inspect.return_value = {"bound": "replaced"}
                with self.assertRaises(fence.FenceRefused):
                    fence.save_fence_receipt(root, req)
                self.assertEqual(
                    json.loads((root / (req["attempt_id"] + ".json")).read_text()),
                    first,
                )

    def test_partial_receipt_is_preserved_not_overwritten(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            req = {
                "attempt_id": "11111111-1111-4111-8111-111111111111",
                "output_path": "/original/attempt",
            }
            path = root / (req["attempt_id"] + ".json")
            path.write_bytes(b'{"partial":')
            path.chmod(0o600)
            with (
                patch.object(fence.os, "geteuid", return_value=0),
                patch.object(fence, "root_managed_ancestry"),
                patch.object(fence, "fence_attempt") as enroll,
            ):
                with self.assertRaises(json.JSONDecodeError):
                    fence.save_fence_receipt(root, req, producer_fenced=True)
                enroll.assert_not_called()
            self.assertEqual(path.read_bytes(), b'{"partial":')


if __name__ == "__main__":
    unittest.main()
