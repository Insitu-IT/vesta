"""Focused native producer orchestration tests; no connection to libvirt."""

import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import threading
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch
import xml.etree.ElementTree as ET

import libvirt_push as push


class OperationBudgetTests(unittest.TestCase):
    def test_size_scaled_window_and_real_usable_reserve(self):
        with patch.dict(os.environ, {"OPERATION_BOOTSTRAP_BYTES_PER_SECOND": "1048576", "OPERATION_TIME_COEFFICIENT": "3"}), patch.object(push.os, "statvfs", return_value=SimpleNamespace(f_bavail=100 << 30, f_frsize=1)):
            small = push.operation_budget({"vda": 1 << 30}, "/unused", 86400)
            large = push.operation_budget({"vda": 10 << 30}, "/unused", 86400)
            self.assertGreater(large["run_seconds"], small["run_seconds"])
            self.assertEqual(large["required_output_bytes"], 12 << 30)
            with self.assertRaises(Exception):
                push.operation_budget({"vda": 10 << 30}, "/unused", 3600)
        with patch.object(push.os, "statvfs", return_value=SimpleNamespace(f_bavail=4096, f_frsize=1)):
            with self.assertRaisesRegex(Exception, "filesystem reserve unavailable"):
                push.operation_budget({"vda": 1 << 30}, "/unused", 86400)

DOMAIN = "11111111-1111-4111-8111-111111111111"
BACKUP = "22222222-2222-4222-8222-222222222222"
ATTEMPT = "33333333-3333-4333-8333-333333333333"
DISKS = [dict(target="vda", source="/vm/source.qcow2", bus="virtio", format="qcow2")]
XML = f'<domain><uuid>{DOMAIN}</uuid><devices><disk type="file" device="disk"><driver type="qcow2"/><source file="/vm/source.qcow2"/><target dev="vda" bus="virtio"/></disk></devices></domain>'


def job_success(transcript, job="backup-vda-node", length=4096):
    for state in ("created", "running", "waiting", "pending"):
        transcript.append("JOB_STATUS_CHANGE", dict(id=job, status=state))
    transcript.append(
        "BLOCK_JOB_COMPLETED",
        dict(device=job, type="backup", len=length, offset=length),
    )
    for state in ("concluded", "null"):
        transcript.append("JOB_STATUS_CHANGE", dict(id=job, status=state))
    transcript.append("DOMAIN_JOB_COMPLETED", dict(operation=9, success=True))


def request(directory, parent=None):
    return dict(
        schema=push.FORMAT,
        uri="qemu:///system",
        backup_id=BACKUP,
        attempt_id=ATTEMPT,
        domain_uuid=DOMAIN,
        disks=copy.deepcopy(DISKS),
        exclusions=[],
        parent=parent,
        output_path=str(directory),
        timeout_seconds=86400,
    )


class FakeDriver:
    def __init__(self, request, before=None, fault=None):
        self.request = request
        self.before = copy.deepcopy(
            before
            or {"foreign": "<domaincheckpoint><name>foreign</name></domaincheckpoint>"}
        )
        self.current = copy.deepcopy(self.before)
        self.transcript = push.Transcript()
        self.started = False
        self.closed = False
        self.fault = fault

    def xml(self):
        if self.started and self.fault == "source":
            return XML.replace("/vm/source.qcow2", "/vm/replaced.qcow2")
        return XML

    def query(self, _name):
        if not self.started:
            return (
                [{"device": "foreign", "type": "backup"}]
                if self.fault == "busy"
                else []
            )
        return [{"device": "backup-vda-node", "type": "backup"}]

    def checkpoints(self):
        return copy.deepcopy(self.current)

    def sizes(self, disks):
        if self.fault == "grow-before":
            return {d["target"]: 8192 for d in disks}
        if self.started and self.fault == "resize":
            return {d["target"]: 8192 for d in disks}
        return {d["target"]: 4096 for d in disks}

    def expected_jobs(self, _disks):
        return {"backup-vda-node"}

    def begin(self, backup_xml, checkpoint_xml):
        self.started = True
        self.active = backup_xml
        if self.fault != "foreign-failure":
            for target in ET.fromstring(backup_xml).findall("./disks/disk/target"):
                Path(target.get("file")).write_bytes(b"fixture-qcow2-image")
        cp = ET.fromstring(checkpoint_xml)
        cp.append(ET.fromstring(XML))
        name = cp.findtext("name")
        self.current[name] = ET.tostring(cp, encoding="unicode")
        if self.fault == "checkpoint":
            self.current["new-foreign"] = "foreign-owned"
        if self.fault == "foreign-delete":
            del self.current["foreign"]
        if self.fault == "atomic-source":
            self.current[name] = self.current[name].replace(
                "/vm/source.qcow2", "/vm/raced.qcow2"
            )
        if self.fault == "cancel":
            self.transcript.append(
                "BLOCK_JOB_CANCELLED", dict(device="backup-vda-node")
            )
        if self.fault == "foreign-failure":
            job_success(self.transcript, "foreign-job")
            self.transcript.append("BLOCK_JOB_ERROR", dict(device="foreign-job"))
        else:
            job_success(self.transcript)
        if self.fault in {"replacement", "fast-replacement"}:
            job_success(self.transcript)
        if self.fault == "gap":
            self.transcript.gap("lost connection")
        if self.fault == "lost-ack":
            raise OSError("lost begin acknowledgement")

    def backup_xml(self):
        if self.fault in {"fast", "fast-replacement", "foreign-failure"}:
            return None
        if self.fault == "targets":
            return self.active.replace("vda.qcow2", "other.qcow2")
        return self.active

    def close(self):
        self.closed = True


class TranscriptTests(unittest.TestCase):
    def test_failed_writer_closure_ignores_foreign_jobs_but_not_reused_own_ids(self):
        t = push.Transcript()
        job_success(t, "foreign-job")
        for state in ("created", "running", "aborting", "concluded", "null"):
            t.append("JOB_STATUS_CHANGE", dict(id="backup-vda-node", status=state))
        self.assertTrue(t.closed({"backup-vda-node"}))
        t.append("JOB_STATUS_CHANGE", dict(id="backup-vda-node", status="created"))
        with self.assertRaises(push.Uncertain):
            t.closed({"backup-vda-node"})

    def test_failed_writer_closure_requires_every_pinned_terminal_cycle(self):
        t = push.Transcript()
        job_success(t)
        self.assertFalse(t.closed({"backup-vda-node", "backup-vdb-node"}))
        t.gap("lost observation")
        with self.assertRaises(push.Uncertain):
            t.closed({"backup-vda-node"})

    def test_repeated_pinned_pause_resume_still_needs_exact_success(self):
        t = push.Transcript()
        job = "backup-vda-node"
        for state in (
            "created",
            "running",
            "paused",
            "running",
            "paused",
            "running",
            "waiting",
            "pending",
        ):
            t.append("JOB_STATUS_CHANGE", dict(id=job, status=state))
        t.append(
            "BLOCK_JOB_COMPLETED",
            dict(device=job, type="backup", len=4096, offset=4096),
        )
        for state in ("concluded", "null"):
            t.append("JOB_STATUS_CHANGE", dict(id=job, status=state))
        t.append("DOMAIN_JOB_COMPLETED", dict(operation=9, success=True))
        self.assertTrue(t.evaluate({job}, final=True))

        for fault in ("unresolved", "after-success", "skipped-resume", "foreign"):
            with self.subTest(fault=fault):
                bad = push.Transcript()
                bad.events = copy.deepcopy(t.events)
                if fault == "unresolved":
                    bad.events = bad.events[:3]
                elif fault == "after-success":
                    bad.events.insert(
                        9, ("JOB_STATUS_CHANGE", dict(id=job, status="paused"))
                    )
                elif fault == "skipped-resume":
                    bad.events[3][1]["status"] = "pending"
                else:
                    bad.events[2][1]["id"] = "foreign-job"
                with self.assertRaises(push.Uncertain):
                    bad.evaluate({job}, final=True)

    def test_success_needs_complete_single_cycle_and_domain_result(self):
        t = push.Transcript()
        t.append("DOMAIN_JOB_COMPLETED", dict(operation=9, success=True))
        self.assertFalse(t.evaluate({"backup-vda-node"}))
        with self.assertRaises(push.Uncertain):
            t.evaluate({"backup-vda-node"}, final=True)
        t = push.Transcript()
        job_success(t)
        self.assertTrue(t.evaluate({"backup-vda-node"}, final=True))
        t = push.Transcript()
        job_success(t, length=0)
        self.assertTrue(t.evaluate({"backup-vda-node"}, final=True))

    def test_reused_id_foreign_job_cancel_and_gap_refused(self):
        for fault in ("reused", "foreign", "cancelled", "gap", "failure"):
            with self.subTest(fault=fault):
                t = push.Transcript()
                job_success(t)
                if fault == "reused":
                    job_success(t)
                elif fault == "foreign":
                    t.append("JOB_STATUS_CHANGE", dict(id="foreign", status="created"))
                elif fault == "cancelled":
                    t.append("BLOCK_JOB_CANCELLED", {})
                elif fault == "gap":
                    t.gap("disconnected")
                else:
                    t.events[4][1]["error"] = "write failed"
                with self.assertRaises(push.Uncertain):
                    t.evaluate({"backup-vda-node"}, final=True)


class ObserverTeardownTests(unittest.TestCase):
    def driver(self):
        driver = object.__new__(push.LibvirtDriver)
        driver.stopped = False
        driver.transcript = push.Transcript()
        driver.conn = Mock()
        driver.qemu = Mock()
        driver.lv = Mock()
        driver.qmp_id = 7
        driver.ids = [8, 9]
        return driver

    def test_close_waits_for_inflight_callback_before_returning(self):
        driver = self.driver()
        wake = threading.Event()

        def inflight_callback():
            wake.wait()
            driver.transcript.gap("late callback from event worker")

        driver.event_thread = threading.Thread(target=inflight_callback, daemon=True)
        driver.event_thread.start()
        self.addCleanup(lambda: driver.event_thread.join(timeout=2))
        self.addCleanup(wake.set)

        def add_timeout(interval, _callback, _opaque):
            self.assertEqual(interval, 0)
            self.assertTrue(driver.stopped)
            driver.conn.unregisterCloseCallback.assert_called_once_with()
            wake.set()
            return 10

        driver.lv.virEventAddTimeout.side_effect = add_timeout
        driver.close()
        self.assertFalse(driver.event_thread.is_alive())
        self.assertEqual(driver.transcript.failure, "late callback from event worker")
        driver.lv.virEventRemoveTimeout.assert_called_once_with(10)
        driver.conn.close.assert_called_once_with()

    def test_unquiesced_worker_refuses_close_and_still_releases_connection(self):
        driver = self.driver()
        driver.event_thread = Mock()
        driver.event_thread.is_alive.return_value = True
        driver.lv.virEventAddTimeout.return_value = 10
        with self.assertRaisesRegex(push.Uncertain, "did not quiesce"):
            driver.close()
        driver.event_thread.join.assert_called_once_with(timeout=5)
        driver.lv.virEventRemoveTimeout.assert_called_once_with(10)
        driver.conn.close.assert_called_once_with()


class ProfileTests(unittest.TestCase):
    def test_completed_backup_view_absence_requires_transcript(self):
        class LibvirtError(Exception):
            def __init__(self, code):
                self.code = code

            def get_error_code(self):
                return self.code

        class Libvirt:
            libvirtError = LibvirtError
            VIR_ERR_OPERATION_INVALID = 55
            VIR_ERR_NO_DOMAIN_BACKUP = 104

        class Domain:
            result = "<domainbackup/>"

            def backupGetXMLDesc(self, _flags):
                if isinstance(self.result, Exception):
                    raise self.result
                return self.result

        driver = object.__new__(push.LibvirtDriver)
        driver.lv = Libvirt
        driver.dom = Domain()
        self.assertEqual(driver.backup_xml(), "<domainbackup/>")
        for absent_code in (55, 104):
            driver.dom.result = LibvirtError(absent_code)
            self.assertIsNone(driver.backup_xml())
        driver.dom.result = LibvirtError(999)
        with self.assertRaises(LibvirtError):
            driver.backup_xml()

        # Neither absence code substitutes for the exact job/domain history.
        with self.assertRaises(push.Uncertain):
            push.Transcript().evaluate({"backup-vda-node"}, final=True)

    def test_job_ids_bound_to_unique_admitted_source_nodes(self):
        driver = object.__new__(push.LibvirtDriver)
        block = dict(
            inserted={
                "node-name": "libvirt-1-format",
                "image": {"filename": "/vm/source.qcow2", "format": "qcow2"},
            }
        )
        driver.query = lambda _name: [block]
        self.assertEqual(driver.expected_jobs(DISKS), {"backup-vda-libvirt-1-format"})
        for blocks in (
            [],
            [block, block],
            [
                dict(
                    inserted={
                        "node-name": "foreign",
                        "image": {"filename": "/vm/other.qcow2", "format": "qcow2"},
                    }
                )
            ],
        ):
            driver.query = lambda _name: blocks
            with self.assertRaises(push.Uncertain):
                driver.expected_jobs(DISKS)

    def test_unrecognized_runtime_or_image_tool_refused(self):
        push.verify_runtime_versions(11010000, 10001000)
        push.verify_runtime_versions(11010999, 10001999)
        push.verify_runtime_versions(12007000, 10001000)
        for lv, qemu in (
            (11009000, 10001000),
            (11011000, 10001000),
            (12000000, 10001000),
            (12006000, 10001000),
            (12008000, 10001000),
            (12007000, 10000000),
            (12007000, 10002000),
            (11010000, 10002000),
        ):
            with self.assertRaises(push.Uncertain):
                push.verify_runtime_versions(lv, qemu)
        for version in (
            b"qemu-img version 10.0.0",
            b"qemu-img version 10.2.0",
            b"unknown",
        ):
            with (
                patch.object(push, "image_command", return_value=version),
                self.assertRaises(push.Uncertain),
            ):
                push.verify_image_tool()
        with patch.object(
            push, "image_command", return_value=b"qemu-img version 10.1.0 (fixture)\n"
        ):
            push.verify_image_tool()


class ProducerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.addCleanup(self.temp.cleanup)

    def produce(self, req, driver):
        backing = bool(req["parent"])

        def info(_path):
            result = {"format": "qcow2", "virtual-size": 4096}
            if backing:
                result["backing-filename"] = DISKS[0]["source"]
            return result

        def command(*args):
            nonlocal backing
            if args[0] == "create":
                Path(args[-2]).write_bytes(b"empty-owned-image")
            if args[0] == "rebase":
                self.assertEqual(args[1:6], ("-u", "-f", "qcow2", "-b", ""))
                backing = False
            return b""

        with (
            patch.object(push, "image_info", side_effect=info),
            patch.object(push, "image_command", side_effect=command),
            patch.object(push, "verify_image_tool"),
        ):
            return push.run_backup(req, lambda *_: driver)

    def test_full_then_incremental_preserves_foreign_checkpoint(self):
        full_req = request(self.root / "full")
        full_driver = FakeDriver(full_req)
        full = self.produce(full_req, full_driver)
        self.assertEqual(full["manifest"]["parent_backup_id"], None)
        self.assertEqual(full_driver.current["foreign"], full_driver.before["foreign"])
        inc_req = request(self.root / "incremental", full)
        inc_req["backup_id"] = "44444444-4444-4444-8444-444444444444"
        inc_req["attempt_id"] = "55555555-5555-4555-8555-555555555555"
        inc_driver = FakeDriver(inc_req, full_driver.current)
        inc = self.produce(inc_req, inc_driver)
        self.assertEqual(
            inc["manifest"]["parent_manifest_sha256"], full["manifest_sha256"]
        )
        self.assertEqual(inc_driver.current["foreign"], full_driver.before["foreign"])
        self.assertTrue(full_driver.closed and inc_driver.closed)
        self.assertEqual(
            json.loads(
                (self.root / "incremental" / "data" / "manifest.json").read_text()
            ),
            inc["manifest"],
        )

    def test_positive_seal_is_final_write_after_closed_verified_producer(self):
        req = request(self.root / "sealed")
        driver = FakeDriver(req)
        original = push.durable_file
        writes = []

        def record(path, body):
            if path.name == "producer-sealed.json":
                self.assertTrue(driver.closed)
            writes.append(path.name)
            return original(path, body)

        with patch.object(push, "durable_file", side_effect=record):
            result = self.produce(req, driver)
        self.assertEqual(writes[-1], "producer-sealed.json")
        seal = json.loads((Path(req["output_path"]) / writes[-1]).read_text())
        self.assertEqual(seal["schema"], "libvirt-producer-seal/1")
        self.assertEqual(seal["request_sha256"], push.sha(push.canonical(req)))
        self.assertEqual(seal["result"], result)
        self.assertRegex(seal["invocation_id"], r"^[0-9a-f]{32}$")
        tree = Path(req["output_path"]) / "data"
        self.assertEqual(
            [a["path"] for a in seal["artifacts"]],
            sorted(p.name for p in tree.iterdir()),
        )
        for a in seal["artifacts"]:
            path = tree / a["path"]
            info = path.stat()
            self.assertEqual(a["device"], info.st_dev)
            self.assertEqual(a["inode"], info.st_ino)
            self.assertEqual(a["size"], info.st_size)
            self.assertEqual(a["mtime_ns"], info.st_mtime_ns)
            self.assertEqual(a["ctime_ns"], info.st_ctime_ns)
            self.assertEqual(a["sha256"], push.sha(path.read_bytes()))

    def test_failed_closed_artifact_durability_never_emits_positive_seal(self):
        req = request(self.root / "seal-fsync-failure")
        with patch.object(push, "sealed_artifact", side_effect=OSError("fsync")):
            with self.assertRaises(OSError):
                self.produce(req, FakeDriver(req))
        directory = Path(req["output_path"])
        self.assertTrue((directory / "data" / "manifest.json").exists())
        self.assertTrue((directory / "uncertain.json").exists())
        self.assertFalse((directory / "producer-sealed.json").exists())

    def test_observer_teardown_must_not_hide_late_gap_or_foreign_event(self):
        for fault in ("gap", "foreign-job", "replacement", "io-error"):
            with self.subTest(fault=fault):
                req = request(self.root / ("teardown-" + fault))
                driver = FakeDriver(req)

                def close():
                    driver.closed = True
                    if fault == "gap":
                        driver.transcript.gap("connection lost during unsubscribe")
                    elif fault == "foreign-job":
                        job_success(driver.transcript, "foreign-job")
                    elif fault == "replacement":
                        job_success(driver.transcript)
                    else:
                        driver.transcript.append(
                            "BLOCK_JOB_ERROR", dict(device="backup-vda-node")
                        )

                driver.close = close
                with self.assertRaises(push.Uncertain):
                    self.produce(req, driver)
                directory = Path(req["output_path"])
                self.assertTrue(driver.closed)
                self.assertTrue((directory / "uncertain.json").is_file())
                self.assertTrue((directory / "data" / "vda.qcow2").is_file())
                self.assertFalse((directory / "producer-sealed.json").exists())
                self.assertFalse((directory / "prebegin-refusal.json").exists())
                self.assertFalse((directory / "producer-closed-failure.json").exists())
                self.assertEqual(driver.current["foreign"], driver.before["foreign"])

    def test_image_tool_failure_has_positive_refusal_without_libvirt(self):
        req = request(self.root / "tool-failure")
        with (
            patch.object(
                push,
                "verify_image_tool",
                side_effect=push.Uncertain("unsupported qemu-img"),
            ),
            patch.object(push, "LibvirtDriver") as driver,
        ):
            with self.assertRaises(push.Uncertain):
                push.run_backup(req, driver)
        driver.assert_not_called()
        directory = Path(req["output_path"])
        self.assertEqual((directory / "intent.json").read_bytes(), push.canonical(req))
        proof = json.loads((directory / "prebegin-refusal.json").read_text())
        self.assertEqual(proof["request_sha256"], push.sha(push.canonical(req)))
        self.assertEqual(proof["reason"], "unsupported qemu-img")
        self.assertFalse((directory / "begin-intent.json").exists())
        self.assertFalse((directory / "data" / "manifest.json").exists())
        # An existing attempt cannot be rerun or have its terminal fact replaced.
        with patch.object(push, "verify_image_tool") as verify:
            with self.assertRaises(FileExistsError):
                push.run_backup(req, driver)
        verify.assert_not_called()
        driver.assert_not_called()

    def test_failed_intent_write_never_produces_refusal(self):
        req = request(self.root / "intent-failure")
        with (
            patch.object(
                push, "durable_file", side_effect=OSError("intent fsync failed")
            ),
            patch.object(push, "LibvirtDriver") as driver,
        ):
            with self.assertRaises(OSError):
                push.run_backup(req, driver)
        driver.assert_not_called()
        self.assertFalse((Path(req["output_path"]) / "prebegin-refusal.json").exists())

    def test_prebegin_busy_refusal_has_positive_bound_evidence(self):
        req = request(self.root / "prebegin")
        driver = FakeDriver(req, fault="busy")
        with self.assertRaises(push.Uncertain):
            self.produce(req, driver)
        proof = json.loads(
            (Path(req["output_path"]) / "prebegin-refusal.json").read_text()
        )
        self.assertEqual(proof["schema"], "libvirt-prebegin-refusal/1")
        self.assertEqual(proof["request_sha256"], push.sha(push.canonical(req)))
        self.assertEqual(proof["attempt_id"], req["attempt_id"])
        self.assertFalse(driver.started)
        self.assertFalse((Path(req["output_path"]) / "begin-intent.json").exists())
        self.assertEqual(driver.current, driver.before)

    def test_lost_begin_ack_never_has_no_effect_proof(self):
        req = request(self.root / "unknown-begin")
        with self.assertRaises(OSError):
            self.produce(req, FakeDriver(req, fault="lost-ack"))
        self.assertTrue((Path(req["output_path"]) / "begin-intent.json").is_file())
        self.assertFalse((Path(req["output_path"]) / "prebegin-refusal.json").exists())

    def test_target_binding_is_durable_before_begin_even_when_ack_is_lost(self):
        req = request(self.root / "bound-lost-ack")
        driver = FakeDriver(req, fault="lost-ack")
        begin = driver.begin

        def bound_begin(backup, checkpoint):
            directory = Path(req["output_path"])
            binding = json.loads((directory / "target-binding.json").read_text())
            self.assertEqual(binding["schema"], "libvirt-target-binding/1")
            self.assertEqual(binding["request_sha256"], push.sha(push.canonical(req)))
            self.assertEqual(binding["backup_xml_sha256"], push.sha(backup.encode()))
            self.assertEqual(
                binding["checkpoint_xml_sha256"], push.sha(checkpoint.encode())
            )
            self.assertEqual(
                binding["targets"]["vda"],
                list(push.file_identity(directory / "data/vda.qcow2")),
            )
            self.assertTrue((directory / "begin-intent.json").is_file())
            return begin(backup, checkpoint)

        driver.begin = bound_begin
        with self.assertRaises(OSError):
            self.produce(req, driver)
        self.assertFalse((Path(req["output_path"]) / "begin-returned.json").exists())

    def test_failed_target_binding_write_does_not_call_begin(self):
        req = request(self.root / "binding-failure")
        driver = FakeDriver(req)
        original = push.durable_file

        def fail_binding(path, body):
            if path.name == "target-binding.json":
                raise OSError("binding fsync failed")
            return original(path, body)

        with patch.object(push, "durable_file", side_effect=fail_binding):
            with self.assertRaises(OSError):
                self.produce(req, driver)
        self.assertFalse(driver.started)
        self.assertFalse((Path(req["output_path"]) / "begin-intent.json").exists())

    def test_root_allocation_claim_binds_request_and_cannot_be_reused(self):
        req = request(self.root / "allocated")
        directory = Path(req["output_path"])
        directory.mkdir(mode=0o711)
        directory.chmod(0o711)
        st = directory.stat()
        allocation = {"schema": "libvirt-staging-allocation/1",
                      "request_sha256": push.sha(push.canonical(req)),
                      "directory": [st.st_dev, st.st_ino], "uid": st.st_uid,
                      "gid": st.st_gid, "reserved_bytes": 4096}
        marker = directory / "allocation.json"
        marker.write_bytes(push.canonical(allocation))
        marker.chmod(0o444)
        original_fstat = os.fstat

        def issuer_stat(fd):
            info = original_fstat(fd)
            values = list(info)
            if push.stat.S_ISREG(info.st_mode):
                values[4] = 0
            return os.stat_result(values)

        def immutable_flag(fd, operation, body, mutate=True):
            body[:4] = (0x10).to_bytes(4, "little")

        with (patch.object(push, "allocation_ancestry"),
              patch.object(push.os, "fstat", side_effect=issuer_stat),
              patch("fcntl.ioctl", side_effect=immutable_flag)):
            push.claim_staging_allocation(directory, req)
            wrong = dict(req, backup_id="44444444-4444-4444-8444-444444444444")
            with self.assertRaises(push.Uncertain):
                push.claim_staging_allocation(directory, wrong)
            push.durable_file(directory / "intent.json", push.canonical(req))
            with self.assertRaises(push.Uncertain):
                push.claim_staging_allocation(directory, req)

    def test_root_allocation_cannot_claim_mutable_ancestry(self):
        with self.assertRaises(push.Uncertain):
            push.allocation_ancestry(self.root / "unallocated")

    def test_failed_begin_boundary_write_cannot_claim_no_effect(self):
        req = request(self.root / "failed-boundary")
        driver = FakeDriver(req)
        original = push.durable_file

        def fail_boundary(path, body):
            if path.name == "begin-intent.json":
                raise OSError("fsync unavailable")
            return original(path, body)

        with patch.object(push, "durable_file", side_effect=fail_boundary):
            with self.assertRaises(OSError):
                self.produce(req, driver)
        self.assertFalse(driver.started)
        self.assertFalse((Path(req["output_path"]) / "prebegin-refusal.json").exists())

    def test_foreign_checkpoint_between_incrementals_keeps_exact_parent(self):
        full_req = request(self.root / "full")
        full_driver = FakeDriver(full_req)
        full = self.produce(full_req, full_driver)

        first_req = request(self.root / "first", full)
        first_req["backup_id"] = "44444444-4444-4444-8444-444444444444"
        first_req["attempt_id"] = "55555555-5555-4555-8555-555555555555"
        first_driver = FakeDriver(first_req, full_driver.current)
        first = self.produce(first_req, first_driver)

        checkpoints = first_driver.current.copy()
        foreign_xml = (
            "<domaincheckpoint><name>foreign-between-incrementals</name>"
            "<disks><disk name='vda' checkpoint='bitmap'/></disks>"
            "</domaincheckpoint>"
        )
        checkpoints["foreign-between-incrementals"] = foreign_xml
        second_req = request(self.root / "second", first)
        second_req["backup_id"] = "66666666-6666-4666-8666-666666666666"
        second_req["attempt_id"] = "77777777-7777-4777-8777-777777777777"
        second_driver = FakeDriver(second_req, checkpoints)
        second = self.produce(second_req, second_driver)

        self.assertEqual(
            ET.fromstring(second_driver.active).findtext("incremental"),
            first["manifest"]["checkpoint"],
        )
        self.assertEqual(second["manifest"]["parent_backup_id"], first_req["backup_id"])
        self.assertEqual(
            second["manifest"]["parent_manifest_sha256"], first["manifest_sha256"]
        )
        self.assertEqual(
            second_driver.current["foreign-between-incrementals"], foreign_xml
        )
        self.assertTrue(second_driver.closed)

    def test_foreign_checkpoint_deleted_after_begin_holds_only_attempt(self):
        req = request(self.root / "foreign-delete")
        driver = FakeDriver(req, fault="foreign-delete")
        with self.assertRaises(push.Uncertain):
            self.produce(req, driver)
        path = self.root / "foreign-delete"
        self.assertTrue((path / "intent.json").exists())
        self.assertTrue((path / "uncertain.json").exists())
        self.assertFalse((path / "data" / "manifest.json").exists())
        self.assertTrue((path / "data" / "vda.qcow2").exists())
        self.assertNotIn("foreign", driver.current)
        self.assertIn("vnbui-" + req["attempt_id"], driver.current)
        self.assertTrue(driver.closed)

    def test_postbegin_failure_records_closed_writer_without_accepting_partial_data(
        self,
    ):
        req = request(self.root / "closed-failure")
        driver = FakeDriver(req, fault="checkpoint")
        with self.assertRaises(push.Uncertain):
            self.produce(req, driver)
        directory = Path(req["output_path"])
        certificate = json.loads(
            (directory / "producer-closed-failure.json").read_text()
        )
        self.assertEqual(certificate["schema"], "libvirt-closed-failure/1")
        self.assertEqual(certificate["request_sha256"], push.sha(push.canonical(req)))
        self.assertEqual(certificate["job_ids"], ["backup-vda-node"])
        ack = (directory / "begin-returned.json").read_bytes()
        self.assertEqual(certificate["begin_ack_sha256"], push.sha(ack))
        self.assertEqual(certificate["artifacts"][0]["path"], "vda.qcow2")
        self.assertTrue(driver.closed)
        self.assertFalse((directory / "producer-sealed.json").exists())
        self.assertFalse((directory / "data/manifest.json").exists())
        self.assertEqual(driver.current["foreign"], driver.before["foreign"])
        self.assertIn("new-foreign", driver.current)

    def test_lost_begin_ack_or_observer_gap_cannot_certify_failure_closure(self):
        for fault in ("lost-ack", "gap", "replacement", "fast-replacement"):
            with self.subTest(fault=fault):
                req = request(self.root / ("closure-" + fault))
                driver = FakeDriver(req, fault=fault)
                with self.assertRaises((push.Uncertain, OSError)):
                    self.produce(req, driver)
                self.assertFalse(
                    (Path(req["output_path"]) / "producer-closed-failure.json").exists()
                )

    def test_failed_attempt_keeps_observing_its_writer_without_cancelling_it(self):
        req = request(self.root / "delayed-closure")
        driver = FakeDriver(req, fault="checkpoint")
        original_begin = driver.begin

        def begin(*args):
            original_begin(*args)
            driver.transcript.events = []
            for state in ("created", "running"):
                driver.transcript.append(
                    "JOB_STATUS_CHANGE", dict(id="backup-vda-node", status=state)
                )

        def finish(_delay):
            for state in ("concluded", "null"):
                driver.transcript.append(
                    "JOB_STATUS_CHANGE", dict(id="backup-vda-node", status=state)
                )

        driver.begin = begin
        with patch.object(push.time, "sleep", side_effect=finish) as wait:
            with self.assertRaises(push.Uncertain):
                self.produce(req, driver)
        wait.assert_called_once()
        self.assertTrue(
            (Path(req["output_path"]) / "producer-closed-failure.json").exists()
        )
        self.assertFalse((Path(req["output_path"]) / "producer-sealed.json").exists())
        self.assertIn("new-foreign", driver.current)

    def test_failed_begin_ack_durability_never_certifies_writer_closure(self):
        req = request(self.root / "ack-fsync-failure")
        driver = FakeDriver(req, fault="checkpoint")
        original_write = push.durable_file

        def fail_ack(path, body):
            if path.name == "begin-returned.json":
                raise OSError("ACK durability failed")
            return original_write(path, body)

        with patch.object(push, "durable_file", side_effect=fail_ack):
            with self.assertRaises(OSError):
                self.produce(req, driver)
        self.assertTrue(driver.closed)
        self.assertFalse(
            (Path(req["output_path"]) / "producer-closed-failure.json").exists()
        )

    def test_interleavings_retain_output_without_manifest_or_cleanup(self):
        for fault in (
            "source",
            "resize",
            "checkpoint",
            "atomic-source",
            "cancel",
            "replacement",
            "gap",
            "lost-ack",
            "targets",
            "busy",
            "fast-replacement",
            "foreign-failure",
        ):
            with self.subTest(fault=fault):
                req = request(self.root / fault)
                driver = FakeDriver(req, fault=fault)
                with self.assertRaises((push.Uncertain, OSError)):
                    self.produce(req, driver)
                path = self.root / fault
                self.assertTrue((path / "intent.json").exists())
                self.assertTrue((path / "uncertain.json").exists())
                self.assertFalse((path / "producer-sealed.json").exists())
                self.assertFalse((path / "data" / "manifest.json").exists())
                self.assertEqual(driver.current["foreign"], driver.before["foreign"])
                self.assertTrue(driver.closed)
                if driver.started:
                    self.assertTrue((path / "data" / "vda.qcow2").exists())
                if fault == "foreign-failure":
                    self.assertEqual(
                        (path / "data" / "vda.qcow2").read_bytes(), b"empty-owned-image"
                    )

    def test_fast_success_uses_prebound_cycle_not_current_domain_state(self):
        req = request(self.root / "fast")
        result = self.produce(req, FakeDriver(req, fault="fast"))
        self.assertEqual(result["manifest"]["backup_id"], req["backup_id"])

    def test_retry_cannot_adopt_existing_attempt_directory(self):
        req = request(self.root / "attempt")
        self.produce(req, FakeDriver(req))
        driver = FakeDriver(req)
        with self.assertRaises(FileExistsError):
            self.produce(req, driver)
        self.assertFalse(driver.started)

    def test_incremental_refuses_changed_ancestor_before_mutation(self):
        full_req = request(self.root / "full")
        full_driver = FakeDriver(full_req)
        full = self.produce(full_req, full_driver)
        req = request(self.root / "inc", full)
        req["backup_id"] = "44444444-4444-4444-8444-444444444444"
        req["attempt_id"] = "55555555-5555-4555-8555-555555555555"
        checkpoints = full_driver.current.copy()
        checkpoints[full["manifest"]["checkpoint"]] += " "
        driver = FakeDriver(req, checkpoints)
        with self.assertRaises(push.Uncertain):
            self.produce(req, driver)
        self.assertFalse(driver.started)

    def test_incremental_refuses_resized_source_before_mutation(self):
        full_req = request(self.root / "full")
        full_driver = FakeDriver(full_req)
        full = self.produce(full_req, full_driver)
        req = request(self.root / "resized", full)
        req["backup_id"] = "44444444-4444-4444-8444-444444444444"
        req["attempt_id"] = "55555555-5555-4555-8555-555555555555"
        driver = FakeDriver(req, full_driver.current, fault="grow-before")
        with self.assertRaises(push.Uncertain):
            self.produce(req, driver)
        self.assertFalse(driver.started)
        self.assertFalse((self.root / "resized" / "data" / "manifest.json").exists())
        self.assertFalse((self.root / "resized" / "data" / "vda.qcow2").exists())
        self.assertEqual(driver.current, full_driver.current)


@unittest.skipUnless(
    shutil.which("qemu-img") and shutil.which("qemu-io"),
    "offline qemu image tools not installed",
)
class RealImageRestoreTests(unittest.TestCase):
    """Actual qcow2 changed/zero extent reconstruction; no hypervisor required."""

    def test_full_incremental_zero_bytes_and_corruption_order_refusal(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            full_dir, inc_dir = root / "full", root / "inc"
            full_dir.mkdir()
            inc_dir.mkdir()
            full, inc = full_dir / "vda.qcow2", inc_dir / "vda.qcow2"
            push.image_command("create", "-f", "qcow2", str(full), "262144")
            subprocess.run(
                ["qemu-io", "-f", "qcow2", "-c", "write -P 0x41 0 262144", str(full)],
                check=True,
                capture_output=True,
            )
            push.image_command(
                "create", "-f", "qcow2", "-F", "qcow2", "-b", str(full), str(inc)
            )
            subprocess.run(
                [
                    "qemu-io",
                    "-f",
                    "qcow2",
                    "-c",
                    "write -P 0x42 65536 65536",
                    "-c",
                    "write -z 131072 65536",
                    str(inc),
                ],
                check=True,
                capture_output=True,
            )
            push.image_command("rebase", "-u", "-f", "qcow2", "-b", "", str(inc))

            def member(path, backup_id, attempt_id, parent=None):
                size, digest = push.hash_file(path)
                manifest = dict(
                    schema=push.FORMAT,
                    backup_id=backup_id,
                    attempt_id=attempt_id,
                    domain_uuid=DOMAIN,
                    checkpoint="vnbui-" + attempt_id,
                    checkpoint_sha256="a" * 64,
                    parent_backup_id=(
                        parent["manifest"]["backup_id"] if parent else None
                    ),
                    parent_manifest_sha256=(
                        parent["manifest_sha256"] if parent else None
                    ),
                    source=copy.deepcopy(DISKS),
                    exclusions=[],
                    domain_xml_sha256="b" * 64,
                    disks=[
                        dict(
                            target="vda",
                            file="vda.qcow2",
                            size_bytes=size,
                            virtual_size=262144,
                            sha256=digest,
                        )
                    ],
                )
                return dict(
                    manifest=manifest,
                    manifest_sha256=push.sha(push.canonical(manifest)),
                    directory=str(path.parent),
                )

            base = member(full, BACKUP, ATTEMPT)
            delta = member(
                inc,
                "44444444-4444-4444-8444-444444444444",
                "55555555-5555-4555-8555-555555555555",
                base,
            )
            result = push.run_restore(
                dict(members=[base, delta], output_path=str(root / "restored"))
            )
            self.assertEqual(
                Path(result[0]["path"]).read_bytes(),
                b"A" * 65536 + b"B" * 65536 + bytes(65536) + b"A" * 65536,
            )
            self.assertEqual(
                push.hash_file(full),
                (
                    base["manifest"]["disks"][0]["size_bytes"],
                    base["manifest"]["disks"][0]["sha256"],
                ),
            )
            self.assertEqual(
                push.hash_file(inc),
                (
                    delta["manifest"]["disks"][0]["size_bytes"],
                    delta["manifest"]["disks"][0]["sha256"],
                ),
            )
            with self.assertRaises(push.Uncertain):
                push.run_restore(
                    dict(members=[delta, base], output_path=str(root / "wrong-order"))
                )
            with inc.open("r+b") as damaged:
                damaged.seek(100000)
                damaged.write(b"bad")
            with self.assertRaises(push.Uncertain):
                push.run_restore(
                    dict(members=[base, delta], output_path=str(root / "corrupt"))
                )


if __name__ == "__main__":
    unittest.main()
