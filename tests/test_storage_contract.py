"""C01 design fixtures and probe controls, without provider credentials/network."""

import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest

from botocore.exceptions import ClientError
from botocore.hooks import HierarchicalEmitter

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "probe", ROOT / "scripts/probe_storage_contract.py"
)
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def sha(value):
    return hashlib.sha256(value).hexdigest()


class FakeS3:
    def __init__(
        self,
        ignore_conditions=False,
        ignore_checksum=False,
        omit_head_checksum=False,
        ignore_completion=False,
        absent_abort=False,
        ignore_root_control=None,
        reject_current_update=False,
        absent_parts_code="NoSuchUpload",
    ):
        self.meta = SimpleNamespace(events=HierarchicalEmitter())
        self.objects, self.uploads, self.calls = {}, {}, []
        self.ignore_conditions, self.ignore_checksum = (
            ignore_conditions,
            ignore_checksum,
        )
        self.omit_head_checksum = omit_head_checksum
        self.ignore_completion = ignore_completion
        self.absent_abort = absent_abort
        self.ignore_root_control = ignore_root_control
        self.reject_current_update = reject_current_update
        self.absent_parts_code = absent_parts_code

    def __getattr__(self, name):
        def operation(**args):
            request = SimpleNamespace(headers={})
            self.meta.events.emit("before-sign.s3", request=request)
            headers = request.headers
            self.calls.append((name, args.get("Key"), dict(headers)))
            key = args.get("Key")

            def fail(code):
                raise ClientError({"Error": {"Code": code}}, name)

            if name == "get_bucket_versioning":
                return {}
            if name == "create_multipart_upload":
                upload = str(len(self.uploads) + 1)
                self.uploads[upload] = {"parts": {}, "metadata": args["Metadata"]}
                return {"UploadId": upload}
            if name in {"put_object", "complete_multipart_upload", "delete_object"}:
                old = self.objects.get(key)
                if (
                    name == "put_object"
                    and "If-Match" in headers
                    and self.reject_current_update
                ):
                    fail("PreconditionFailed")
                ignored_root = key.endswith("/root") and (
                    (
                        self.ignore_root_control == "create"
                        and args.get("Body") == b"stale create"
                    )
                    or (
                        self.ignore_root_control == "update"
                        and args.get("Body") == b"stale update"
                    )
                    or (
                        self.ignore_root_control == "delete" and name == "delete_object"
                    )
                )
                if (
                    not self.ignore_conditions
                    and not (
                        self.ignore_completion and name == "complete_multipart_upload"
                    )
                    and not ignored_root
                ):
                    if headers.get("If-None-Match") == "*" and old:
                        fail("PreconditionFailed")
                    if "If-Match" in headers and (
                        not old or old["ETag"] != headers["If-Match"]
                    ):
                        fail("PreconditionFailed")
            if name == "upload_part":
                if (
                    not self.ignore_checksum
                    and args.get("ChecksumSHA256")
                    and args["ChecksumSHA256"] != probe.digest(args["Body"])
                ):
                    fail("BadDigest")
                self.uploads[args["UploadId"]]["parts"][args["PartNumber"]] = args[
                    "Body"
                ]
                return {"ETag": probe.digest(args["Body"])}
            if name in {"put_object", "complete_multipart_upload"}:
                if name == "put_object":
                    body, metadata = args["Body"], args.get("Metadata", {})
                    if (
                        not self.ignore_checksum
                        and args.get("ChecksumSHA256")
                        and args["ChecksumSHA256"] != probe.digest(body)
                    ):
                        fail("BadDigest")
                    checksum_type = "FULL_OBJECT"
                else:
                    upload = self.uploads.pop(args["UploadId"])
                    body = b"".join(upload["parts"][i] for i in sorted(upload["parts"]))
                    metadata, checksum_type = upload["metadata"], "COMPOSITE"
                item = {
                    "ETag": '"' + sha(body) + '"',
                    "ContentLength": len(body),
                    "Metadata": metadata,
                    "ChecksumType": checksum_type,
                    "ChecksumSHA256": (
                        probe.digest(body)
                        if checksum_type == "FULL_OBJECT"
                        else "composite-2"
                    ),
                    "body": body,
                }
                self.objects[key] = item
                return {"ETag": item["ETag"]}
            if name == "abort_multipart_upload":
                if self.absent_abort and args["UploadId"] not in self.uploads:
                    fail("NoSuchUpload")
                self.uploads.pop(args["UploadId"], None)
                return {}
            if name == "list_parts":
                if args["UploadId"] not in self.uploads:
                    fail(self.absent_parts_code)
                return {}
            if name == "delete_object":
                self.objects.pop(key, None)
                return {}
            if name in {"head_object", "get_object"}:
                if key not in self.objects:
                    fail("404")
                item = self.objects[key]
                result = {k: v for k, v in item.items() if k != "body"}
                if name == "head_object" and self.omit_head_checksum:
                    result.pop("ChecksumSHA256", None)
                    result.pop("ChecksumType", None)
                if name == "get_object":
                    if not key.endswith("/root"):
                        raise AssertionError(
                            "ordinary verification consumed a payload body"
                        )
                    result["Body"] = io.BytesIO(item["body"])
                return result
            raise AssertionError("unexpected operation " + name)

        return operation


class ProbeControls(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "journal.json"
        self.state = {
            "schema": 1,
            "run_id": "fixture",
            "bucket": "disposable",
            "prefix": "vnbui-c01-probe/fixture/",
            "objects": {},
            "uploads": {},
            "unknown_uploads": [],
            "uploaded_bytes": 0,
            "read_body_bytes": 0,
            "copied_bytes": 0,
            "calls": 0,
            "verdict": "INCOMPLETE",
        }

    def test_complete_probe_and_exact_cleanup(self):
        client = FakeS3()
        probe.Probe(client, self.path, self.state).run()
        self.assertEqual(self.state["verdict"], "PASS")
        self.assertFalse(client.objects)
        self.assertFalse(client.uploads)
        self.assertLess(self.state["uploaded_bytes"], 12 * probe.MIB)
        self.assertLess(self.state["read_body_bytes"], 4096)
        self.assertEqual(self.state["copied_bytes"], 0)
        self.assertEqual(
            self.state["multipart_assurance"], "identity_metadata_only/scrub_required"
        )
        self.assertFalse(
            any(
                name in {"list_objects_v2", "list_object_versions", "copy_object"}
                for name, _, _ in client.calls
            )
        )
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)

    def test_ignored_cas_is_not_pass(self):
        with self.assertRaisesRegex(RuntimeError, "deliberately invalid"):
            probe.Probe(FakeS3(ignore_conditions=True), self.path, self.state).run()
        self.assertNotEqual(self.state["verdict"], "PASS")

    def test_ignored_checksum_is_not_pass(self):
        with self.assertRaisesRegex(RuntimeError, "deliberately invalid"):
            probe.Probe(FakeS3(ignore_checksum=True), self.path, self.state).run()

    def test_db_rooted_hetzner_shape_passes_without_root_or_reads(self):
        self.state["capability_profile"] = "db-rooted-consumer-verified/1"
        client = FakeS3(
            ignore_checksum=True,
            ignore_completion=True,
            omit_head_checksum=True,
            absent_abort=True,
            reject_current_update=True,
            absent_parts_code="NoSuchKey",
        )
        p = probe.Probe(client, self.path, self.state)
        p.run()
        resumed = probe.Probe(client, self.path, json.loads(self.path.read_text()))
        resumed.cleanup()
        resumed.cleanup()
        self.assertEqual(resumed.state["verdict"], "PASS")
        self.assertEqual(
            resumed.state["root_replace_capability"], "root_replace_unsupported"
        )
        self.assertEqual(resumed.state["root_pointer_cas"], "not_used_db_rooted")
        self.assertEqual(resumed.state["generation_create_precondition"], "enforced")
        self.assertFalse(client.objects)
        self.assertFalse(client.uploads)
        self.assertLess(resumed.state["uploaded_bytes"], 12 * probe.MIB)
        self.assertEqual(resumed.state["read_body_bytes"], 0)
        self.assertEqual(resumed.state["copied_bytes"], 0)
        self.assertFalse(
            any(
                key == p.key("root")
                or operation in {"get_object", "list_objects_v2", "copy_object"}
                for operation, key, _ in client.calls
            )
        )

    def test_mutable_profile_correct_update_rejection_stays_incomplete(self):
        client = FakeS3(reject_current_update=True, absent_parts_code="NoSuchKey")
        p = probe.Probe(client, self.path, self.state)
        with self.assertRaises(ClientError):
            p.run()
        resumed = probe.Probe(client, self.path, json.loads(self.path.read_text()))
        resumed.cleanup()
        self.assertEqual(resumed.state["verdict"], "INCOMPLETE")
        self.assertEqual(resumed.state["root_pointer_cas"], "unmeasured")
        self.assertFalse(client.objects)

    def test_db_rooted_ignored_generation_create_is_not_pass(self):
        self.state["capability_profile"] = "db-rooted-consumer-verified/1"
        client = FakeS3(ignore_conditions=True)
        p = probe.Probe(client, self.path, self.state)
        with self.assertRaisesRegex(RuntimeError, "generation create"):
            p.run()
        resumed = probe.Probe(client, self.path, json.loads(self.path.read_text()))
        resumed.cleanup()
        self.assertEqual(resumed.state["verdict"], "INCOMPLETE")
        self.assertFalse(client.objects)

    def test_each_ignored_root_control_resumes_exact_cleanup(self):
        for control in ("create", "update", "delete"):
            with self.subTest(control=control):
                state = dict(self.state, objects={}, uploads={}, unknown_uploads=[])
                client = FakeS3(ignore_root_control=control)
                p = probe.Probe(client, self.path, state)
                with self.assertRaisesRegex(RuntimeError, "deliberately invalid"):
                    p.run()
                saved = json.loads(self.path.read_text())
                intent = saved["negative_root_cleanup"]
                self.assertEqual(intent["key"], p.key("root"))
                self.assertEqual(intent["metadata"], p.metadata("root"))
                self.assertTrue(intent["accepted"])
                resumed = probe.Probe(client, self.path, saved)
                resumed.cleanup()
                resumed.cleanup()
                self.assertFalse(client.objects)
                self.assertFalse(client.uploads)
                self.assertFalse(resumed.state["uploads"])
                self.assertEqual(resumed.state["verdict"], "INCOMPLETE")
                self.assertEqual(resumed.state["read_body_bytes"], 0)
                self.assertEqual(resumed.state["copied_bytes"], 0)
                self.assertFalse(
                    any(
                        call[0]
                        in {
                            "get_object",
                            "list_objects",
                            "list_objects_v2",
                            "copy_object",
                        }
                        for call in client.calls
                    )
                )

    def test_negative_root_cleanup_refuses_foreign_and_unexpected_replacement(self):
        for mutation in ("metadata", "etag", "size", "lost_response"):
            with self.subTest(mutation=mutation):
                state = dict(self.state, objects={}, uploads={}, unknown_uploads=[])
                client = FakeS3(ignore_root_control="create")
                p = probe.Probe(client, self.path, state)
                with self.assertRaises(RuntimeError):
                    p.run()
                saved = json.loads(self.path.read_text())
                obj = client.objects[p.key("root")]
                if mutation == "metadata":
                    obj["Metadata"] = {"vnbui-probe-id": "foreign"}
                elif mutation == "etag":
                    obj["ETag"] = '"unexpected"'
                elif mutation == "size":
                    obj["ContentLength"] += 1
                else:
                    saved["negative_root_cleanup"].pop("accepted_etag")
                with self.assertRaises(RuntimeError):
                    probe.Probe(client, self.path, saved).cleanup()
                self.assertIn(p.key("root"), client.objects)

    def test_enforced_root_controls_leave_no_replacement_authority(self):
        p = probe.Probe(FakeS3(), self.path, self.state)
        p.run()
        self.assertNotIn("negative_root_cleanup", json.loads(self.path.read_text()))

    def test_negative_root_intent_is_durable_before_provider_call(self):
        client = FakeS3(ignore_root_control="create")
        original = client.put_object
        observed = []

        def put(**kwargs):
            if kwargs.get("Body") == b"stale create":
                saved = json.loads(self.path.read_text())
                intent = saved["negative_root_cleanup"]
                self.assertEqual(intent["key"], kwargs["Key"])
                self.assertEqual(intent["body_sha256"], probe.digest(kwargs["Body"]))
                self.assertEqual(intent["body_bytes"], len(kwargs["Body"]))
                self.assertEqual(intent["metadata"], kwargs["Metadata"])
                self.assertTrue(intent["prior_etag"])
                self.assertNotIn("accepted", intent)
                observed.append(True)
            return original(**kwargs)

        client.put_object = put
        with self.assertRaises(RuntimeError):
            probe.Probe(client, self.path, self.state).run()
        self.assertEqual(observed, [True])

    def test_ignored_completion_is_independent_of_enforced_root_cas(self):
        self.state["capability_profile"] = "consumer-verified/1"
        client = FakeS3(
            ignore_checksum=True,
            omit_head_checksum=True,
            ignore_completion=True,
            absent_abort=True,
        )
        probe.Probe(client, self.path, self.state).run()
        self.assertEqual(self.state["verdict"], "PASS")
        self.assertEqual(self.state["multipart_create_precondition"], "ignored")
        self.assertEqual(self.state["root_pointer_cas"], "enforced")
        self.assertFalse(client.objects)
        self.assertFalse(client.uploads)
        self.assertFalse(self.state["uploads"])
        self.assertLess(self.state["uploaded_bytes"], 12 * probe.MIB)
        self.assertLessEqual(self.state["read_body_bytes"], 4096)
        self.assertEqual(self.state["copied_bytes"], 0)

    def test_strict_completion_failure_can_cleanup_consumed_upload_and_replacement(
        self,
    ):
        client = FakeS3(ignore_completion=True, absent_abort=True)
        p = probe.Probe(client, self.path, self.state)
        with self.assertRaisesRegex(RuntimeError, "deliberately invalid"):
            p.run()
        self.assertEqual(self.state["root_pointer_cas"], "unmeasured")
        resumed = probe.Probe(client, self.path, json.loads(self.path.read_text()))
        resumed.cleanup()
        self.assertFalse(resumed.state["uploads"])
        self.assertFalse(client.objects)
        self.assertEqual(resumed.state["verdict"], "INCOMPLETE")

    def test_negative_completion_cleanup_never_adopts_foreign_metadata(self):
        client = FakeS3(ignore_completion=True, absent_abort=True)
        p = probe.Probe(client, self.path, self.state)
        with self.assertRaises(RuntimeError):
            p.run()
        client.objects[p.key("multipart")]["Metadata"]["vnbui-probe-id"] = "foreign"
        with self.assertRaisesRegex(RuntimeError, "metadata"):
            p.cleanup()
        self.assertIn(p.key("multipart"), client.objects)

    def test_cleanup_persists_consumed_upload_absence_before_object_failure(self):
        client = FakeS3(ignore_completion=True, absent_abort=True)
        p = probe.Probe(client, self.path, self.state)
        with self.assertRaises(RuntimeError):
            p.run()
        original = client.head_object

        def unavailable(**kwargs):
            raise RuntimeError("injected HEAD outage")

        client.head_object = unavailable
        with self.assertRaisesRegex(RuntimeError, "HEAD outage"):
            p.cleanup()
        persisted = json.loads(self.path.read_text())
        self.assertEqual(persisted["uploads"], {})
        client.head_object = original
        resumed = probe.Probe(client, self.path, persisted)
        resumed.cleanup()
        resumed.cleanup()
        self.assertFalse(client.objects)
        self.assertEqual(resumed.state["verdict"], "INCOMPLETE")

    def test_consumer_profile_records_ignored_checksums_and_finishes_exact_cleanup(
        self,
    ):
        for omit in (False, True):
            with self.subTest(omit_head_checksum=omit):
                state = dict(self.state, objects={}, uploads={}, unknown_uploads=[])
                state["capability_profile"] = "consumer-verified/1"
                client = FakeS3(ignore_checksum=True, omit_head_checksum=omit)
                probe.Probe(client, self.path, state).run()
                self.assertEqual(state["verdict"], "PASS")
                for kind in ("put", "part"):
                    self.assertEqual(state[f"{kind}_checksum_enforcement"], "ignored")
                for kind in ("put", "multipart"):
                    self.assertEqual(
                        state[f"{kind}_assurance"],
                        "identity_metadata_only/scrub_required",
                    )
                self.assertLessEqual(state["uploaded_bytes"], 12 * probe.MIB)
                self.assertLessEqual(state["read_body_bytes"], 4096)
                self.assertEqual(state["copied_bytes"], 0)
                self.assertFalse(client.objects)
                self.assertFalse(client.uploads)

    def test_consumer_profile_never_waives_cas(self):
        self.state["capability_profile"] = "consumer-verified/1"
        with self.assertRaisesRegex(RuntimeError, "deliberately invalid"):
            probe.Probe(
                FakeS3(ignore_checksum=True, ignore_conditions=True),
                self.path,
                self.state,
            ).run()
        self.assertNotEqual(self.state["verdict"], "PASS")
        self.assertEqual(self.state["multipart_create_precondition"], "ignored")
        self.assertEqual(self.state["root_pointer_cas"], "ignored")

    def test_missing_head_checksum_does_not_waive_upload_enforcement(self):
        client = FakeS3(omit_head_checksum=True)
        probe.Probe(client, self.path, self.state).run()
        self.assertEqual(self.state["verdict"], "PASS")
        self.assertEqual(
            self.state["put_assurance"], "identity_metadata_only/scrub_required"
        )
        self.assertFalse(client.objects)
        self.assertFalse(client.uploads)

    def test_checksum_ignoring_provider_requires_explicit_profile(self):
        # Bounded reproduction of the OPS-reported Hetzner shape, not a live test.
        client = FakeS3(ignore_checksum=True, omit_head_checksum=True)
        p = probe.Probe(client, self.path, self.state)
        with self.assertRaisesRegex(RuntimeError, "deliberately invalid"):
            p.run()
        self.assertEqual(self.state["verdict"], "INCOMPLETE")
        self.assertEqual(
            self.state["put_assurance"], "identity_metadata_only/scrub_required"
        )
        self.assertEqual(self.state["uploaded_bytes"], 1048600)
        self.assertEqual(self.state["read_body_bytes"], 0)
        self.assertEqual(self.state["copied_bytes"], 0)
        self.assertEqual(self.state["calls"], 4)
        self.assertEqual(set(client.objects), {p.key("put"), p.key("bad-checksum")})
        self.assertFalse(client.uploads)
        self.assertFalse(
            any(name == "create_multipart_upload" for name, _, _ in client.calls)
        )
        p.cleanup()
        self.assertFalse(client.objects)
        self.assertFalse(client.uploads)
        self.assertEqual(self.state["verdict"], "INCOMPLETE")
        self.assertFalse(
            any(
                name
                in {
                    "get_object",
                    "list_objects_v2",
                    "list_object_versions",
                    "copy_object",
                }
                for name, _, _ in client.calls
            )
        )

    def test_unknown_upload_id_holds_cleanup(self):
        self.state["unknown_uploads"] = ["multipart"]
        client = FakeS3()
        with self.assertRaisesRegex(RuntimeError, "lost MPU"):
            probe.Probe(client, self.path, self.state).cleanup()
        self.assertEqual(client.calls, [])

    def test_changed_object_holds_cleanup(self):
        client = FakeS3()
        p = probe.Probe(client, self.path, self.state)
        p.put("put", b"first")
        client.objects[p.key("put")]["ETag"] = '"replacement"'
        with self.assertRaisesRegex(RuntimeError, "changed"):
            p.cleanup()
        self.assertIn(p.key("put"), client.objects)

    def test_resume_exact_cleanup_from_disk(self):
        client = FakeS3()
        p = probe.Probe(client, self.path, self.state)
        p.put("put", b"first")
        state = json.loads(self.path.read_text())
        probe.Probe(client, self.path, state).cleanup()
        self.assertFalse(client.objects)

    def test_upload_budget_prevents_call(self):
        client = FakeS3()
        self.state["uploaded_bytes"] = 12 * probe.MIB
        with self.assertRaisesRegex(RuntimeError, "budget"):
            probe.Probe(client, self.path, self.state).call("put_object", Body=b"x")
        self.assertEqual(client.calls, [])

    def test_unknown_key_never_reaches_provider(self):
        client = FakeS3()
        with self.assertRaisesRegex(ValueError, "unknown disposable"):
            probe.Probe(client, self.path, self.state).put("production-key", b"x")
        self.assertEqual(client.calls, [])

    def test_deadline_prevents_call(self):
        client = FakeS3()
        p = probe.Probe(client, self.path, self.state)
        p.deadline = 0
        with self.assertRaisesRegex(RuntimeError, "deadline"):
            p.call("get_bucket_versioning")
        self.assertEqual(client.calls, [])

    def test_versioned_bucket_requires_separate_acceptance(self):
        client = FakeS3()
        client.get_bucket_versioning = lambda **kwargs: {"Status": "Enabled"}
        with self.assertRaisesRegex(RuntimeError, "unversioned"):
            probe.Probe(client, self.path, self.state).run()
        self.assertFalse(client.objects)

    def test_missing_head_checksum_is_explicitly_weaker(self):
        client = FakeS3()
        head = client.head_object

        def without_checksum(**kwargs):
            value = head(**kwargs)
            value.pop("ChecksumType", None)
            value.pop("ChecksumSHA256", None)
            return value

        client.head_object = without_checksum
        probe.Probe(client, self.path, self.state).run()
        self.assertEqual(
            self.state["put_assurance"], "identity_metadata_only/scrub_required"
        )
        self.assertEqual(
            self.state["multipart_assurance"], "identity_metadata_only/scrub_required"
        )

    def test_conditions_are_sigv4_signed_with_installed_sdk(self):
        import boto3
        from botocore.awsrequest import AWSResponse
        from botocore.config import Config

        client = boto3.client(
            "s3",
            endpoint_url="https://example.test",
            region_name="us-east-1",
            aws_access_key_id="fixture",
            aws_secret_access_key="fixture",
            config=Config(signature_version="s3v4", retries={"total_max_attempts": 1}),
        )
        self.addCleanup(client.close)

        class Raw:
            def stream(self, **kwargs):
                return iter([b""])

        def send(request):
            self.assertEqual(request.headers["If-Match"], b'"prior"')
            self.assertIn(b"if-match", request.headers["Authorization"])
            return AWSResponse(request.url, 200, {"ETag": '"result"'}, Raw())

        client._endpoint.http_session.send = send
        probe.Probe(client, self.path, self.state).call(
            "put_object", Key="fixture", Body=b"x", headers={"If-Match": '"prior"'}
        )


class ContractFixtures(unittest.TestCase):
    def test_libvirt_http_contract_independent_of_generator(self):
        value = json.loads(
            (ROOT / "tests/fixtures/storage-contract-v1/libvirt.json").read_text()
        )
        backup = "22222222-2222-4222-8222-222222222224"
        for key, path, body, response in (
            (
                "upload_exchange",
                f"/api/backups/{backup}/upload",
                "request",
                "dispatch_ack",
            ),
            (
                "local_completion_exchange",
                f"/api/v1/agents/backups/{backup}/local-completion-proof",
                "local_completion_proof",
                "local_completion_ack",
            ),
        ):
            exchange = value[key]
            self.assertEqual(
                set(exchange), {"method", "path", "body", "response_status", "response"}
            )
            self.assertEqual(exchange["method"], "POST")
            self.assertEqual(exchange["path"], path)
            self.assertEqual(exchange["response_status"], 202)
            self.assertEqual(exchange["body"], value[body])
            self.assertEqual(exchange["response"], value[response])
            self.assertEqual(
                exchange["response"]["reservation_id"],
                value["request"]["reservation_id"],
            )
        self.assertEqual(value["upload_exchange"]["response"]["status"], "accepted")
        self.assertEqual(
            value["local_completion_exchange"]["response"]["status"],
            "awaiting_manifest",
        )
        proof = value["local_completion_exchange"]["body"]
        self.assertEqual(proof["exit_code"], 0)
        self.assertIs(proof["inventory_closed"], True)
        self.assertEqual(
            proof["receipt_sha256"], sha(canonical(value["prepared_receipt"]))
        )
        self.assertEqual(proof["acceptance_id"], value["acceptance"]["acceptance_id"])
        self.assertEqual(
            proof["domain_uuid"], value["request"]["plan"]["source"]["vm_uid"]
        )

    def test_canonical_mapping_is_explicit_and_hash_bound(self):
        import copy

        for name in ("1-disk", "2-disk", "incremental", "libvirt"):
            value = json.loads(
                (ROOT / f"tests/fixtures/storage-contract-v1/{name}.json").read_text()
            )
            plan = value["request"]["plan"]
            for i, volume in enumerate(plan["source"]["volumes"]):
                expected = (
                    {
                        "target_dev": "vda",
                        "device": "disk",
                        "bus": "virtio",
                        "serial": "fixture-disk-1",
                    }
                    if name == "libvirt"
                    else {
                        "disk_name": f"data{i + 1}",
                        "device": "disk",
                        "bus": "virtio",
                        "serial": None,
                    }
                )
                self.assertEqual(volume["mapping"], expected)
                for field in expected:
                    changed = copy.deepcopy(plan)
                    changed["source"]["volumes"][i]["mapping"][field] = "changed"
                    self.assertNotEqual(
                        sha(canonical(changed)), value["request"]["plan_sha256"]
                    )
            self.assertEqual(sha(canonical(plan)), value["request"]["plan_sha256"])

    def test_incremental_and_libvirt_exact_exchanges(self):
        from storage_contract_examples import example

        for kind in ("incremental", "libvirt"):
            value = json.loads(
                (ROOT / f"tests/fixtures/storage-contract-v1/{kind}.json").read_text()
            )
            self.assertEqual(value, example(kind))
            request, receipt = value["request"], value["prepared_receipt"]
            self.assertEqual(request["plan_sha256"], sha(canonical(request["plan"])))
            self.assertEqual(
                value["acceptance"]["receipt_sha256"], sha(canonical(receipt))
            )
            self.assertEqual(
                value["pointer"]["sha256"], sha(canonical(value["generation"]))
            )
            self.assertEqual(
                {
                    (a["volume_id"], a["role"], a["key"])
                    for a in request["plan"]["artifacts"]
                },
                {(a["volume_id"], a["role"], a["key"]) for a in receipt["objects"]},
            )
            recipe = value["artifact_contents"]["payload_recipe"]
            bodies = [
                bytes([recipe["repeat_byte"]]) * recipe["length"],
                canonical(value["artifact_contents"]["metadata"]),
            ]
            for obj, body in zip(receipt["objects"], bodies):
                self.assertEqual(obj["ciphertext_sha256"], sha(body))
                self.assertEqual(obj["ciphertext_bytes"], len(body))
            if kind == "incremental":
                parent = request["plan"]["parent"]
                self.assertEqual(
                    value["checkpoint_proof"]["parent_checkpoint"], parent["checkpoint"]
                )
                self.assertEqual(
                    value["generation"]["predecessor_generation_id"],
                    parent["generation_id"],
                )
                self.assertEqual(len(value["generation"]["members"]), 2)
                self.assertEqual(
                    value["artifact_contents"]["metadata"]["extents"][0]["offset"],
                    16 << 20,
                )
            else:
                self.assertNotIn("checkpoint_proof", value)
                self.assertEqual(
                    value["local_completion_proof"]["inventory_sha256"],
                    sha(canonical(request["plan"]["local_inventory"])),
                )
                self.assertEqual(
                    value["local_inventory_exchange"]["response"]["plan_sha256"],
                    request["plan_sha256"],
                )
                self.assertIn(
                    "backup_metadata", {a["role"] for a in receipt["objects"]}
                )

    def test_failure_matrix_is_complete_and_not_a_production_pass(self):
        value = json.loads(
            (ROOT / "tests/fixtures/storage-contract-v1/recovery.json").read_text()
        )
        self.assertEqual(
            [case["id"] for case in value["cases"]], [f"F{i:02}" for i in range(1, 22)]
        )
        self.assertEqual(
            len({case["production_test_id"] for case in value["cases"]}), 21
        )
        for case in value["cases"]:
            self.assertTrue(case["expected_state"])
            self.assertTrue(case["invariants"])
            self.assertEqual(
                case["production_test_status"], "required_not_claimed_implemented"
            )

    def test_consumer_profile_reuses_existing_receipt_fields(self):
        directory = ROOT / "tests/fixtures/storage-contract-v1"
        contract = json.loads((directory / "consumer-integrity.json").read_text())
        self.assertEqual(contract["capability_profile"], "consumer-verified/1")
        variant = contract["db_rooted_variant"]
        self.assertFalse(variant["mutable_s3_root"])
        self.assertEqual(variant["conditional_generation_create"], "enforced_required")
        self.assertEqual(variant["replacement_412"], "root_replace_unsupported")
        self.assertEqual(
            contract["provider_capabilities"]["root_pointer_cas"], "enforced_required"
        )
        self.assertFalse(
            contract["provider_capabilities"]["provider_immutability_claimed"]
        )
        self.assertFalse(contract["checksum_sidecars"])
        self.assertEqual(contract["publication"]["payload_get_bytes"], 0)
        self.assertTrue(contract["publication"]["scrub_required"])
        self.assertFalse(contract["mismatch"]["completion"])
        self.assertFalse(contract["mismatch"]["guest_exposure"])
        self.assertFalse(contract["unanchored"]["publication"])
        self.assertEqual(
            set(contract["consumers"]),
            {"restore", "scrub", "export", "import", "chain_assembly"},
        )
        for name in contract["wire_examples"]:
            wire = json.loads((directory / f"{name}.json").read_text())
            receipt = wire["prepared_receipt"]
            self.assertEqual(
                wire["acceptance"]["receipt_sha256"], sha(canonical(receipt))
            )
            for artifact in receipt["objects"]:
                self.assertTrue(set(contract["expected_fields"]) <= set(artifact))

    def test_one_and_two_disk_exchanges(self):
        for disks in (1, 2):
            value = json.loads(
                (
                    ROOT / f"tests/fixtures/storage-contract-v1/{disks}-disk.json"
                ).read_text()
            )
            request, receipt = value["request"], value["prepared_receipt"]
            plan = request["plan"]
            for obj in receipt["objects"]:
                metadata = value["initiation_metadata"][obj["key"]]
                self.assertEqual(metadata["vnbui-plan-sha256"], request["plan_sha256"])
                self.assertEqual(
                    metadata["vnbui-reservation-id"], request["reservation_id"]
                )
                self.assertNotIn("vnbui-plaintext-sha256", metadata)
                self.assertLess(len(canonical(metadata)), 2048)
            self.assertEqual(request["plan_sha256"], sha(canonical(plan)))
            self.assertEqual(len(plan["source"]["volumes"]), disks)
            expected = {
                (a["volume_id"], a["role"], a["key"]) for a in plan["artifacts"]
            }
            actual = {(a["volume_id"], a["role"], a["key"]) for a in receipt["objects"]}
            self.assertEqual(len(actual), disks * 2)
            self.assertEqual(actual, expected)
            self.assertEqual(receipt["schema"], 2)
            self.assertEqual(
                value["acceptance"]["receipt_sha256"], sha(canonical(receipt))
            )
            self.assertEqual(
                value["checkpoint_proof"]["acceptance_id"],
                value["acceptance"]["acceptance_id"],
            )
            self.assertEqual(
                value["pointer"]["sha256"], sha(canonical(value["generation"]))
            )
            for key, limit in (
                ("request", 4 << 20),
                ("prepared_receipt", 4 << 20),
                ("acceptance", 4 << 20),
                ("generation", 16 << 20),
                ("pointer", 4096),
            ):
                self.assertLess(len(canonical(value[key])), limit)
            for artifact in plan["artifacts"]:
                if artifact["role"] == "volume_manifest":
                    self.assertEqual(artifact["plaintext_max"], 16 << 20)
            self.assertTrue(value["completion"]["scrub_required"])


if __name__ == "__main__":
    unittest.main()
