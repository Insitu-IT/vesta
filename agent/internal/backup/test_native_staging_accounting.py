"""Accounting transitions with mocked kernel operations, never VM qualification."""

import copy
import errno
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import native_staging_accounting as accounting
import native_write_fence as fence
from test_libvirt_push import request


class AccountingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "33333333-3333-4333-8333-333333333333"
        self.path.mkdir()
        self.fd = os.open(self.path, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, self.fd)
        req = request(self.path)
        body = fence.canonical(req)
        self.allocation = dict(
            schema="libvirt-staging-allocation/1",
            request_sha256=accounting.sha(body),
            directory=fence.identity(os.fstat(self.fd)),
            uid=os.geteuid(),
            gid=os.getegid(),
            reserved_bytes=10,
        )
        self.allocation_body = fence.canonical(self.allocation)
        self.records = {
            "intent.json": req,
            "begin-intent.json": dict(
                schema="libvirt-begin-intent/1", request_sha256=accounting.sha(body)
            ),
            "begin-returned.json": dict(
                schema="libvirt-begin-returned/1", request_sha256=accounting.sha(body)
            ),
        }
        manifest = dict(
            schema="libvirt-push-qcow2/1",
            backup_id=req["backup_id"],
            attempt_id=req["attempt_id"],
            domain_uuid=req["domain_uuid"],
            checkpoint="vnbui-" + req["attempt_id"],
            source=req["disks"],
            exclusions=[],
        )
        result = dict(
            manifest=manifest, manifest_sha256=accounting.sha(fence.canonical(manifest))
        )
        members = [
            dict(
                path=name,
                device=10,
                inode=n + 3,
                size=100,
                mtime_ns=1,
                ctime_ns=1,
                member_backup_id=req["backup_id"],
                member_checkpoint=manifest["checkpoint"],
            )
            for n, name in enumerate(
                ["checkpoint.xml", "domain.xml", "manifest.json", "vda.qcow2"]
            )
        ]
        artifacts = [
            {
                k: m[k]
                for k in ("path", "device", "inode", "size", "mtime_ns", "ctime_ns")
            }
            for m in members
        ]
        self.records["producer-sealed.json"] = dict(
            schema="libvirt-producer-seal/1",
            request_sha256=accounting.sha(body),
            invocation_id="a" * 32,
            result=result,
            artifacts=artifacts,
        )
        inventory = dict(
            format="libvirt-native-fileset/1",
            backup_id=req["backup_id"],
            attempt_id=req["attempt_id"],
            domain_uuid=req["domain_uuid"],
            checkpoint=manifest["checkpoint"],
            job_id="vnbui-native-" + req["attempt_id"],
            files=members,
        )
        admission = dict(
            intent_sha256="b" * 64,
            inventory=inventory,
            push_result=result,
            closed_job=dict(
                job_id=inventory["job_id"],
                attempt_id=req["attempt_id"],
                invocation_id="c" * 32,
                state="exited",
                exit_code=0,
            ),
        )
        self.records["admission.json"] = admission
        self.records["published.json"] = dict(
            schema=1,
            backup_id=req["backup_id"],
            attempt_id=req["attempt_id"],
            intent_sha256="b" * 64,
            admission_sha256=accounting.sha(fence.canonical(admission)),
            receipt_sha256="d" * 64,
            acceptance_id="accepted",
        )
        self.records["target-binding.json"] = dict(
            schema="libvirt-target-binding/1",
            request_sha256=accounting.sha(body),
            directory=self.allocation["directory"],
            targets={"vda": [10, 6]},
        )
        self.write()

    def write(self):
        for name, value in self.records.items():
            (self.path / name).write_bytes(fence.canonical(value))
            (self.path / name).chmod(0o600)
        (self.path / "allocation.json").write_bytes(self.allocation_body)
        (self.path / "allocation.json").chmod(0o444)

    def retire(self):
        with (
            patch.object(fence, "make_immutable"),
            patch.object(fence, "enable_verity"),
        ):
            return accounting.retire_reclaimed(
                self.fd, self.allocation, self.allocation_body
            )

    def test_positive_reclamation_records_root_certificate_and_preserves_evidence(self):
        before = {n: (self.path / n).read_bytes() for n in accounting.RECORDS}
        self.assertTrue(self.retire())
        certificate = (self.path / accounting.RELEASE).read_bytes()
        self.assertTrue(self.retire())
        self.assertEqual((self.path / accounting.RELEASE).read_bytes(), certificate)
        self.assertEqual(
            {n: (self.path / n).read_bytes() for n in accounting.RECORDS}, before
        )

    def test_existing_payload_remains_charged(self):
        (self.path / "data").mkdir()
        self.assertFalse(self.retire())
        self.assertFalse((self.path / accounting.RELEASE).exists())

    def test_records_not_owned_by_original_worker_are_refused(self):
        self.allocation["uid"] = os.geteuid() + 1
        with self.assertRaises(fence.FenceRefused):
            self.retire()
        self.assertFalse((self.path / accounting.RELEASE).exists())

    def test_allocator_reuses_budget_without_deleting_original_journals(self):
        self.allocation.update(uid=1000, gid=1000)
        self.allocation_body = fence.canonical(self.allocation)
        self.write()
        os.chown(self.path, 1000, 1000)
        for name in accounting.RECORDS:
            os.chown(self.path / name, 1000, 1000)
        next_path = self.path.parent / "44444444-4444-4444-8444-444444444444"
        req = request(next_path)
        req["attempt_id"] = next_path.name
        with (
            patch.object(fence, "root_managed_ancestry"),
            patch.object(fence, "require_ext4_staging"),
            patch.object(fence, "make_immutable"),
            patch.object(fence, "enable_verity"),
            patch.object(fence, "flags", return_value=fence.IMMUTABLE),
        ):
            result = fence.allocate_attempt(
                self.path.parent,
                req,
                uid=1000,
                gid=1000,
                reserved_bytes=10,
                capacity_bytes=10,
                minimum_free_bytes=1,
            )
        self.assertEqual(result["request_sha256"], accounting.sha(fence.canonical(req)))
        self.assertTrue((self.path / accounting.RELEASE).exists())
        self.assertTrue((next_path / "allocation.json").exists())
        self.assertTrue(all((self.path / n).exists() for n in accounting.RECORDS))

    def test_absent_payload_and_publication_do_not_prove_closure(self):
        (self.path / "published.json").unlink()
        self.assertFalse(self.retire())
        self.assertFalse((self.path / accounting.RELEASE).exists())

    def test_rehashed_foreign_or_conflicting_evidence_never_credits(self):
        for fault in (
            "attempt",
            "phase",
            "seal",
            "inode",
            "intent",
            "extra",
            "missing",
        ):
            with self.subTest(fault=fault):
                original = copy.deepcopy(self.records)
                if fault == "attempt":
                    self.records["published.json"]["attempt_id"] = "foreign"
                elif fault == "phase":
                    self.records["admission.json"]["closed_job"]["state"] = "uncertain"
                elif fault == "seal":
                    self.records["producer-sealed.json"]["request_sha256"] = "e" * 64
                elif fault == "inode":
                    self.records["target-binding.json"]["targets"]["vda"] = [10, 999]
                elif fault == "intent":
                    self.records["published.json"]["intent_sha256"] = "e" * 64
                elif fault == "extra":
                    self.records["uncertain.json"] = dict(state="uncertain")
                else:
                    self.records.pop("producer-sealed.json")
                self.records["published.json"]["admission_sha256"] = accounting.sha(
                    fence.canonical(self.records["admission.json"])
                )
                self.write()
                if fault == "missing":
                    (self.path / "producer-sealed.json").unlink()
                with self.assertRaises(fence.FenceRefused):
                    self.retire()
                self.assertFalse((self.path / accounting.RELEASE).exists())
                if fault == "extra":
                    (self.path / "uncertain.json").unlink()
                self.records = original
                self.write()

    def test_partial_kernel_failure_never_credits_and_can_finish_exact_retry(self):
        with (
            patch.object(fence, "make_immutable"),
            patch.object(
                fence, "enable_verity", side_effect=OSError(errno.ETXTBSY, "writer")
            ),
        ):
            with self.assertRaises(OSError):
                accounting.retire_reclaimed(
                    self.fd, self.allocation, self.allocation_body
                )
        self.assertTrue((self.path / accounting.RELEASE).exists())
        self.assertTrue(self.retire())

    def test_changed_root_certificate_or_reappearing_data_holds(self):
        self.assertTrue(self.retire())
        (self.path / "data").mkdir()
        with self.assertRaises(fence.FenceRefused):
            self.retire()
        (self.path / "data").rmdir()
        (self.path / accounting.RELEASE).write_bytes(b"{}")
        with self.assertRaises(fence.FenceRefused):
            self.retire()


if __name__ == "__main__":
    unittest.main()
