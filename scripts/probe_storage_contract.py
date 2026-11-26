#!/usr/bin/env python3
"""C01 disposable S3 protocol probe. OPS only; no production-prefix input."""

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import signal
import stat
import tempfile
import time
import uuid
from urllib.parse import urlsplit

MIB = 1024 * 1024
NAMES = (
    "put",
    "multipart",
    "unfinished",
    "bad-checksum",
    "generation-1",
    "generation-2",
    "tombstone",
    "root",
)


def digest(body):
    return base64.b64encode(hashlib.sha256(body).digest()).decode()


def save(path, value):
    """Journal intents before IO and responses before the next operation."""
    fd, name = tempfile.mkstemp(prefix=".c01-", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as stream:
            json.dump(value, stream, sort_keys=True, indent=2)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
        fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    finally:
        if os.path.exists(name):
            os.unlink(name)


class Probe:
    def __init__(self, client, path, state):
        self.client, self.path, self.state = client, path, state
        self.deadline = time.monotonic() + 180

    def persist(self):
        save(self.path, self.state)

    def call(self, operation, *, headers=None, **kwargs):
        if time.monotonic() >= self.deadline:
            raise RuntimeError("probe deadline exceeded")
        n = len(kwargs.get("Body", b""))
        if self.state["uploaded_bytes"] + n > 12 * MIB:
            raise RuntimeError("12 MiB upload budget exceeded")
        self.state["uploaded_bytes"] += n  # Includes rejected write attempts.
        self.state["calls"] += 1
        if self.state["calls"] > 100:
            raise RuntimeError("100 operation budget exceeded")
        self.persist()
        # Public botocore signing event also supports older installed SDK models.
        # Conditions are inserted BEFORE signing, never after request signing.
        event = "before-sign.s3"
        hook_id = "c01-conditional-headers"

        def add_headers(request, **unused):
            for key, value in (headers or {}).items():
                request.headers[key] = value

        self.client.meta.events.register(event, add_headers, unique_id=hook_id)
        try:
            result = getattr(self.client, operation)(
                Bucket=self.state["bucket"], **kwargs
            )
            self.state.setdefault("observations", []).append(
                {
                    "operation": operation,
                    "key": kwargs.get("Key"),
                    "http_status": result.get("ResponseMetadata", {}).get(
                        "HTTPStatusCode"
                    ),
                    "result": "success",
                }
            )
            self.persist()
            return result
        except Exception as exc:
            response = getattr(exc, "response", {})
            self.state.setdefault("observations", []).append(
                {
                    "operation": operation,
                    "key": kwargs.get("Key"),
                    "http_status": response.get("ResponseMetadata", {}).get(
                        "HTTPStatusCode"
                    ),
                    "error_code": response.get("Error", {}).get("Code"),
                    "result": "error",
                }
            )
            self.persist()
            raise
        finally:
            self.client.meta.events.unregister(event, unique_id=hook_id)

    def key(self, name):
        if name not in NAMES:
            raise ValueError("unknown disposable object")
        return self.state["prefix"] + name

    def metadata(self, name):
        return {"vnbui-probe-id": self.state["run_id"], "vnbui-artifact-id": name}

    def intent(self, name):
        self.state["objects"].setdefault(name, {"state": "intent"})
        self.persist()

    def head(self, name, replacement=False):
        response = self.call("head_object", Key=self.key(name), ChecksumMode="ENABLED")
        if response["Metadata"] != self.metadata(name):
            raise RuntimeError("foreign or changed object metadata")
        known = self.state["objects"].get(name, {}).get("etag")
        if known and response["ETag"] != known and not replacement:
            raise RuntimeError("changed object ETag; retained for OPS")
        if response.get("VersionId") not in (None, "null"):
            raise RuntimeError("probe requires an unversioned disposable bucket")
        return response

    def remember(self, name, response):
        self.state["objects"][name] = {"state": "present", "etag": response["ETag"]}
        self.persist()

    def put(self, name, body, condition=None):
        self.intent(name)
        result = self.call(
            "put_object",
            Key=self.key(name),
            Body=body,
            Metadata=self.metadata(name),
            ChecksumSHA256=digest(body),
            headers=condition or {"If-None-Match": "*"},
        )
        self.remember(name, result)
        return result

    def reject(self, operation, codes, **kwargs):
        from botocore.exceptions import ClientError

        root_control = kwargs.get("Key") == self.key("root") and operation in {
            "put_object",
            "delete_object",
        }
        if root_control:
            body = kwargs.get("Body", b"")
            self.state["negative_root_cleanup"] = {
                "key": self.key("root"),
                "operation": operation,
                "prior_etag": self.state["objects"]["root"]["etag"],
                "metadata": self.metadata("root"),
                "body_sha256": digest(body),
                "body_bytes": len(body),
                "condition": kwargs["headers"],
            }
            if operation == "put_object":
                kwargs["Metadata"] = self.metadata("root")
            self.persist()
        try:
            result = self.call(operation, **kwargs)
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in codes:
                raise
            if root_control:
                del self.state["negative_root_cleanup"]
                self.persist()
            return
        if root_control:
            self.state["negative_root_cleanup"]["accepted"] = True
            self.state["negative_root_cleanup"]["accepted_etag"] = result.get("ETag")
            self.state["root_pointer_cas"] = "ignored"
            self.persist()
        raise RuntimeError("provider accepted a deliberately invalid operation")

    def checksum_control(self, fact, operation, **kwargs):
        from botocore.exceptions import ClientError

        try:
            response = self.call(operation, **kwargs)
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in {"BadDigest", "InvalidDigest"}:
                raise
            self.state[fact] = "enforced"
            self.persist()
            return None
        self.state[fact] = "ignored"
        # Persist the negative capability even when strict-profile admission fails.
        self.state["put_assurance"] = "identity_metadata_only/scrub_required"
        self.persist()
        if self.state["capability_profile"] not in {
            "consumer-verified/1",
            "db-rooted-consumer-verified/1",
        }:
            raise RuntimeError("provider accepted a deliberately invalid operation")
        return response

    def run(self):
        self.state["root_pointer_cas"] = "unmeasured"
        self.state["multipart_create_precondition"] = "unmeasured"
        profile = self.state.setdefault("capability_profile", "checksum-enforced/1")
        if profile not in {
            "checksum-enforced/1",
            "consumer-verified/1",
            "db-rooted-consumer-verified/1",
        }:
            raise RuntimeError("unknown capability profile")
        versioning = self.call("get_bucket_versioning")
        if versioning.get("Status"):
            raise RuntimeError("use an OPS-provisioned unversioned disposable bucket")
        block = b"C" * MIB  # Reused, bounded local data; never an existing object.
        self.put("put", block)
        head = self.head("put")
        if head["ContentLength"] != len(block) or (
            head.get("ChecksumSHA256") is not None
            and head["ChecksumSHA256"] != digest(block)
        ):
            raise RuntimeError("single PUT stored checksum/size mismatch")
        self.state["put_assurance"] = (
            "provider_checksum_verified"
            if head.get("ChecksumSHA256") == digest(block)
            else "identity_metadata_only/scrub_required"
        )
        # Demonstrate that the server checks, rather than merely echoes, checksums.
        self.intent("bad-checksum")
        accepted = self.checksum_control(
            "put_checksum_enforcement",
            "put_object",
            Key=self.key("bad-checksum"),
            Body=b"invalid checksum control",
            Metadata=self.metadata("bad-checksum"),
            ChecksumSHA256=digest(b"different bytes"),
            headers={"If-None-Match": "*"},
        )
        if accepted is not None:
            self.remember("bad-checksum", accepted)
            self.state["put_assurance"] = "identity_metadata_only/scrub_required"
        else:
            self.state["objects"]["bad-checksum"]["state"] = "absent"
            self.reject(
                "head_object",
                {"404", "NoSuchKey", "NotFound"},
                Key=self.key("bad-checksum"),
            )
        self.persist()

        self.intent("multipart")
        self.state["unknown_uploads"].append("multipart")
        self.persist()
        upload = self.call(
            "create_multipart_upload",
            Key=self.key("multipart"),
            Metadata=self.metadata("multipart"),
            ChecksumAlgorithm="SHA256",
        )["UploadId"]
        self.state["uploads"]["multipart"] = upload
        self.state["unknown_uploads"].remove("multipart")
        self.persist()
        self.checksum_control(
            "part_checksum_enforcement",
            "upload_part",
            Key=self.key("multipart"),
            UploadId=upload,
            PartNumber=1,
            Body=b"invalid part control",
            ChecksumSHA256=digest(b"different part"),
        )
        parts = []
        for number, body in enumerate((block * 5, block), 1):
            response = self.call(
                "upload_part",
                Key=self.key("multipart"),
                UploadId=upload,
                PartNumber=number,
                Body=body,
                ChecksumSHA256=digest(body),
            )
            parts.append(
                {
                    "PartNumber": number,
                    "ETag": response["ETag"],
                    "ChecksumSHA256": digest(body),
                }
            )
        result = self.call(
            "complete_multipart_upload",
            Key=self.key("multipart"),
            UploadId=upload,
            MultipartUpload={"Parts": parts},
            headers={"If-None-Match": "*"},
        )
        self.remember("multipart", result)
        del self.state["uploads"]["multipart"]
        self.persist()
        head = self.head("multipart")
        if head["ContentLength"] != 6 * MIB:
            raise RuntimeError("multipart size mismatch")
        checksum_type = head.get("ChecksumType") or head.get(
            "ResponseMetadata", {}
        ).get("HTTPHeaders", {}).get("x-amz-checksum-type")
        checksum = head.get("ChecksumSHA256")
        if checksum_type == "FULL_OBJECT" and checksum != digest(block * 6):
            raise RuntimeError("provider full-object checksum mismatch")
        self.state["multipart_assurance"] = (
            "provider_checksum_verified"
            if checksum_type == "FULL_OBJECT"
            and self.state["part_checksum_enforcement"] == "enforced"
            and self.state["put_checksum_enforcement"] == "enforced"
            else "identity_metadata_only/scrub_required"
        )
        self.state["multipart_checksum_type"] = checksum_type
        self.state["multipart_checksum"] = checksum

        # Measure completion preconditions independently of root-pointer CAS.
        self.state["unknown_uploads"].append("multipart")
        self.persist()
        upload = self.call(
            "create_multipart_upload",
            Key=self.key("multipart"),
            Metadata=self.metadata("multipart"),
        )["UploadId"]
        self.state["uploads"]["multipart"] = upload
        self.state["unknown_uploads"].remove("multipart")
        self.persist()
        part = self.call(
            "upload_part",
            Key=self.key("multipart"),
            UploadId=upload,
            PartNumber=1,
            Body=block,
        )
        self.state["negative_completion_cleanup"] = {
            "key": self.key("multipart"),
            "upload_id": upload,
            "previous_etag": self.state["objects"]["multipart"]["etag"],
        }
        self.persist()  # Exact disposable replacement authority BEFORE the call.
        from botocore.exceptions import ClientError

        try:
            self.call(
                "complete_multipart_upload",
                Key=self.key("multipart"),
                UploadId=upload,
                MultipartUpload={"Parts": [{"PartNumber": 1, "ETag": part["ETag"]}]},
                headers={"If-None-Match": "*"},
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in {
                "PreconditionFailed",
                "ConditionalRequestConflict",
            }:
                raise
            self.state["multipart_create_precondition"] = "enforced"
            del self.state["negative_completion_cleanup"]
        else:
            self.state["multipart_create_precondition"] = "ignored"
            self.persist()
            if self.state["capability_profile"] not in {
                "consumer-verified/1",
                "db-rooted-consumer-verified/1",
            }:
                raise RuntimeError("provider accepted a deliberately invalid operation")
        self.persist()

        # Exact upload-ID cleanup control, with a real stored part.
        self.intent("unfinished")
        self.state["unknown_uploads"].append("unfinished")
        self.persist()
        upload = self.call(
            "create_multipart_upload",
            Key=self.key("unfinished"),
            Metadata=self.metadata("unfinished"),
        )["UploadId"]
        self.state["uploads"]["unfinished"] = upload
        self.state["unknown_uploads"].remove("unfinished")
        self.persist()
        self.call(
            "upload_part",
            Key=self.key("unfinished"),
            UploadId=upload,
            PartNumber=1,
            Body=block,
        )

        if profile == "db-rooted-consumer-verified/1":
            self.run_db_rooted_publication()
            self.finish()
            return

        self.put("generation-1", b'{"generation":1,"members":["example"]}')
        first = self.put("root", b'{"generation":1,"key":"generation-1"}')
        self.reject(
            "put_object",
            {"PreconditionFailed", "ConditionalRequestConflict"},
            Key=self.key("root"),
            Body=b"stale create",
            headers={"If-None-Match": "*"},
        )
        self.put("generation-2", b'{"generation":2,"members":["example","next"]}')
        self.put(
            "root",
            b'{"generation":2,"key":"generation-2"}',
            {"If-Match": first["ETag"]},
        )
        self.reject(
            "put_object",
            {"PreconditionFailed", "ConditionalRequestConflict"},
            Key=self.key("root"),
            Body=b"stale update",
            headers={"If-Match": first["ETag"]},
        )
        self.reject(
            "delete_object",
            {"PreconditionFailed"},
            Key=self.key("root"),
            headers={"If-Match": first["ETag"]},
        )
        self.state["root_pointer_cas"] = "enforced"
        self.persist()
        # Simulate the consumer losing the successful reply before journaling it.
        # Keep the intent, deliberately discard the response identity and recover.
        self.state["objects"]["root"] = {"state": "intent"}
        self.persist()
        head = self.head("root")
        response = self.call("get_object", Key=self.key("root"), IfMatch=head["ETag"])
        try:
            body = response["Body"].read(4097)
        finally:
            response["Body"].close()
        self.state["read_body_bytes"] += len(body)
        if len(body) > 4096 or json.loads(body) != {
            "generation": 2,
            "key": "generation-2",
        }:
            raise RuntimeError("lost-reply pointer reconciliation failed")
        self.remember("root", head)
        self.put("tombstone", b'{"generation":3,"members":[],"deleted":true}')
        self.put(
            "root", b'{"generation":3,"key":"tombstone"}', {"If-Match": head["ETag"]}
        )
        self.finish()

    def run_db_rooted_publication(self):
        from botocore.exceptions import ClientError

        self.state["root_pointer_cas"] = "not_used_db_rooted"
        for name, body in (
            ("generation-1", b'{"generation":1,"members":["example"]}'),
            (
                "generation-2",
                b'{"generation":2,"predecessor":1,"members":["example","next"]}',
            ),
            (
                "tombstone",
                b'{"generation":3,"predecessor":2,"members":[],"deleted":true}',
            ),
        ):
            created = self.put(name, body)
            # Same exact content/ownership: even an ignored negative create
            # cannot introduce unjournaled bytes or foreign cleanup authority.
            try:
                result = self.call(
                    "put_object",
                    Key=self.key(name),
                    Body=body,
                    Metadata=self.metadata(name),
                    ChecksumSHA256=digest(body),
                    headers={"If-None-Match": "*"},
                )
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "PreconditionFailed":
                    raise
            else:
                self.remember(name, result)
                self.state["generation_create_precondition"] = "ignored"
                self.persist()
                raise RuntimeError(
                    "provider ignored immutable generation create condition"
                )
            if name == "generation-1":
                # Disposable capability discriminator only, not a publication
                # operation. No stable root is created; bytes are unchanged.
                try:
                    result = self.call(
                        "put_object",
                        Key=self.key(name),
                        Body=body,
                        Metadata=self.metadata(name),
                        ChecksumSHA256=digest(body),
                        headers={"If-Match": created["ETag"]},
                    )
                except ClientError as exc:
                    if exc.response["Error"]["Code"] != "PreconditionFailed":
                        raise
                    self.state["root_replace_capability"] = "root_replace_unsupported"
                else:
                    self.remember(name, result)
                    self.state["root_replace_capability"] = (
                        "correct_update_accepted_not_cas_proof"
                    )
                self.persist()
            self.head(name)
        self.state["generation_create_precondition"] = "enforced"
        self.persist()

    def finish(self):
        self.state["verdict"] = "operations_passed_cleanup_pending"
        self.persist()
        self.cleanup()
        self.state["verdict"] = "PASS"
        self.persist()

    def cleanup(self):
        from botocore.exceptions import ClientError

        if self.state["unknown_uploads"]:
            raise RuntimeError(
                "lost MPU creation reply: exact upload ID requires OPS reconciliation"
            )
        for name, upload in list(self.state["uploads"].items()):
            try:
                self.call("abort_multipart_upload", Key=self.key(name), UploadId=upload)
            except ClientError as exc:
                if exc.response["Error"]["Code"] not in {"NoSuchUpload", "404"}:
                    raise
            else:
                self.reject(
                    "list_parts",
                    {"NoSuchUpload", "NoSuchKey", "404"},
                    Key=self.key(name),
                    UploadId=upload,
                )
            del self.state["uploads"][name]
            self.persist()
        # This is disposable-probe teardown only. Production tombstone pointers
        # are retained forever; this tool cannot address a production prefix.
        for name, item in self.state["objects"].items():
            if item["state"] == "absent":
                continue
            replacement = self.state.get("negative_completion_cleanup")
            allow_replacement = bool(
                name == "multipart"
                and replacement
                and replacement.get("key") == self.key(name)
                and replacement.get("upload_id")
                and replacement.get("previous_etag") == item.get("etag")
            )
            root_intent = (
                self.state.get("negative_root_cleanup") if name == "root" else None
            )
            if root_intent:
                if (
                    root_intent.get("key") != self.key(name)
                    or root_intent.get("metadata") != self.metadata(name)
                    or root_intent.get("prior_etag") != item.get("etag")
                ):
                    raise RuntimeError("negative root cleanup identity mismatch")
                allow_replacement = True
            try:
                head = self.head(name, replacement=allow_replacement)
            except ClientError as exc:
                if exc.response["Error"]["Code"] not in {
                    "404",
                    "NoSuchKey",
                    "NotFound",
                }:
                    raise
                if root_intent and not (
                    root_intent.get("operation") == "delete_object"
                    or root_intent.get("cleanup_delete_started")
                ):
                    raise RuntimeError("negative root PUT outcome ambiguous")
                item["state"] = "absent"
                self.persist()
                continue
            if root_intent:
                if (
                    root_intent.get("operation") != "put_object"
                    or not root_intent.get("accepted")
                    or not root_intent.get("accepted_etag")
                    or root_intent["accepted_etag"] != head["ETag"]
                    or root_intent.get("body_bytes") != head["ContentLength"]
                ):
                    raise RuntimeError("negative root outcome ambiguous or changed")
                # Response identity, size and exact ownership establish this
                # probe's accepted write, not provider checksum enforcement.
                root_intent["cleanup_delete_started"] = True
                root_intent["cleanup_etag"] = head["ETag"]
                self.persist()
            if (
                not allow_replacement
                and item.get("etag")
                and item["etag"] != head["ETag"]
            ):
                raise RuntimeError("cleanup object changed; retained for OPS")
            if not root_intent:
                self.remember(name, head)
            self.call(
                "delete_object", Key=self.key(name), headers={"If-Match": head["ETag"]}
            )
            self.reject(
                "head_object", {"404", "NoSuchKey", "NotFound"}, Key=self.key(name)
            )
            self.state["objects"][name]["state"] = "absent"
            self.persist()


def main():
    parser = argparse.ArgumentParser(
        description=__doc__,
        epilog=(
            "Example: python3 scripts/probe_storage_contract.py --endpoint https://s3.example.test "
            "--bucket ops-disposable --credentials-file /run/secrets/c01-s3.json "
            "--journal /var/tmp/c01-run.json --execute"
        ),
    )
    parser.add_argument("--endpoint", required=True)
    parser.add_argument("--bucket", required=True)
    parser.add_argument("--credentials-file", type=Path)
    parser.add_argument("--journal", type=Path, required=True)
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument(
        "--capability-profile",
        default="checksum-enforced/1",
        choices=(
            "checksum-enforced/1",
            "consumer-verified/1",
            "db-rooted-consumer-verified/1",
        ),
    )
    parser.add_argument("--ca-file")
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--cleanup", action="store_true")
    args = parser.parse_args()
    url = urlsplit(args.endpoint)
    if (
        url.scheme != "https"
        or not url.hostname
        or url.username
        or url.password
        or url.path
        or url.query
        or url.fragment
        or "/" in args.bucket
    ):
        parser.error("explicit HTTPS origin and bare disposable bucket required")
    if not args.execute:
        print(
            json.dumps(
                {
                    "objects": NAMES,
                    "capability_profile": args.capability_profile,
                    "uploaded_bytes_max": 12 * MIB,
                    "payload_get_bytes": 0,
                    "copies": 0,
                    "operations_max": 100,
                    "seconds_max": 180,
                    "execution": "OPS authorization required",
                }
            )
        )
        return
    if not args.credentials_file:
        parser.error("--execute requires --credentials-file (no secret values on CLI)")
    if args.cleanup:
        state = json.loads(args.journal.read_text())
        expected_prefix = "vnbui-c01-probe/" + str(uuid.UUID(state["run_id"])) + "/"
        if (
            state["prefix"] != expected_prefix
            or state["endpoint"] != args.endpoint
            or state["bucket"] != args.bucket
            or set(state["objects"]) - set(NAMES)
            or set(state["uploads"]) - set(NAMES)
        ):
            parser.error("journal identity mismatch; no cleanup authorized")
    else:
        if args.journal.exists():
            parser.error("journal already exists; use --cleanup for its exact objects")
        run_id = str(uuid.uuid4())
        state = {
            "schema": 1,
            "capability_profile": args.capability_profile,
            "run_id": run_id,
            "endpoint": args.endpoint,
            "bucket": args.bucket,
            "prefix": "vnbui-c01-probe/" + run_id + "/",
            "objects": {},
            "uploads": {},
            "unknown_uploads": [],
            "uploaded_bytes": 0,
            "read_body_bytes": 0,
            "copied_bytes": 0,
            "calls": 0,
            "verdict": "INCOMPLETE",
        }
    mode = args.credentials_file.stat().st_mode
    if not stat.S_ISREG(mode) or mode & 0o077:
        parser.error("credential file must be regular, owner-only readable")
    credentials = json.loads(args.credentials_file.read_text())
    import boto3
    from botocore.config import Config

    client = boto3.client(
        "s3",
        endpoint_url=args.endpoint,
        region_name=args.region,
        aws_access_key_id=credentials["access_key_id"],
        aws_secret_access_key=credentials["secret_access_key"],
        aws_session_token=credentials.get("session_token"),
        verify=args.ca_file or True,
        config=Config(
            signature_version="s3v4",
            connect_timeout=5,
            read_timeout=10,
            retries={"total_max_attempts": 1},
            s3={"addressing_style": "path"},
        ),
    )
    probe = Probe(client, args.journal, state)

    def deadline(signum, frame):
        raise TimeoutError("180 second probe deadline")

    signal.signal(signal.SIGALRM, deadline)
    signal.alarm(180)
    try:
        probe.cleanup() if args.cleanup else probe.run()
    except Exception as exc:
        # Do not print raw provider exceptions or request headers/credentials.
        state["verdict"] = "INCOMPLETE"
        state["failure_class"] = type(exc).__name__
        if isinstance(exc, RuntimeError):
            state["failure_reason"] = str(exc)
        probe.persist()
        print("INCOMPLETE: see owner-only journal; exact cleanup may be required")
        raise SystemExit(1) from None
    finally:
        signal.alarm(0)
        client.close()
    print(json.dumps(state, sort_keys=True))


if __name__ == "__main__":
    main()
