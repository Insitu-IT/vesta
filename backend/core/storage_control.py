"""Attempt-bound provider control, not publication or cleanup authority.

create/complete are single backend calls behind durable intent. An uncertain
call is held, never retried. Only exact part writes receive signed authority.
"""

import base64
from copy import deepcopy
import hashlib
import json
import re
import time
from xml.etree import ElementTree

from core.s3_ownership import StorageOwnershipError
from core.settings_service import SettingsService
from core.storage_attempt_key import _admit, _credential
from core.storage_dispatch import read_target
from core.storage_signing import sign, control_call, xml_fields, TTL
from core.metrics import storage_control_step_seconds

MAX_STATE = 16 * 1024 * 1024
PART_WINDOW = 300
HASH = re.compile(r"[0-9a-f]{64}\Z")


def refuse():
    raise StorageOwnershipError("Transaction control unavailable")


def metadata(request, artifact):
    return {
        "vnbui-protocol": "1",
        "vnbui-org-id": request["org_id"],
        "vnbui-backup-id": request["backup_id"],
        "vnbui-reservation-id": request["reservation_id"],
        "vnbui-plan-sha256": request["plan_sha256"],
        "vnbui-artifact-id": (
            artifact["artifact_id"]
            if request["plan"]["provider"] == "libvirt"
            else hashlib.sha256(
                (artifact["volume_id"] + ":" + artifact["role"]).encode()
            ).hexdigest()
        ),
    }


def part_size(artifact, transfer_profile=None):
    from core.storage_wire import TRANSFER_PROFILE_32

    if transfer_profile not in (None, TRANSFER_PROFILE_32):
        refuse()
    maximum = artifact["ciphertext_max"]
    if type(maximum) is not int or not 0 <= maximum <= 1024 * 1024 * 1024 * 10000:
        refuse()
    size = (maximum + 9999) // 10000
    minimum = (
        32 * 1024 * 1024
        if transfer_profile == TRANSFER_PROFILE_32
        and artifact["role"] == "volume_payload"
        else 8 * 1024 * 1024
    )
    return max(
        minimum,
        ((size + 8 * 1024 * 1024 - 1) // (8 * 1024 * 1024)) * 8 * 1024 * 1024,
    )


@storage_control_step_seconds.labels("admission").time()
def admit(db, backup, agent, binding, proof):
    claim, request = _admit(db, backup, agent, binding)
    if "capability_evidence" in request["plan"]:
        # The qualified successor has only the unmounted one-send consumers.
        refuse()
    _credential(db, agent, proof)
    from core.callback_intents import require_committed_key

    require_committed_key(db, claim, request)
    if (
        request["plan"]["encryption"]["format"] != "none"
        and claim.wrapped_attempt_key is None
    ):
        refuse()
    return claim, request


@storage_control_step_seconds.labels("persistence").time()
def save(db, claim, state):
    if len(json.dumps(state, separators=(",", ":"))) > MAX_STATE:
        refuse()
    claim.provider_control = deepcopy(state)
    db.commit()


@storage_control_step_seconds.labels("signing_configuration").time()
def authority(
    db,
    request,
    key,
    method,
    query,
    headers,
    *,
    signing_window=None,
    callback_identity=None,
    operation=None,
):
    snapshot = None
    if "capability_evidence" in request["plan"]:
        from core.storage_configuration import capture, tls_context

        snapshot = capture(db, request)
        if snapshot.source_material is not None:
            from core.storage_installation_source import admit_resolved

            admit_resolved(db, request, key, callback_identity, operation)
    settings = (
        SettingsService(db)
        if snapshot is None
        else SettingsService(db, secret_snapshot=snapshot.secrets)
    )
    target = request["plan"]["target"]
    expected = dict(
        endpoint=target["endpoint"],
        bucket=target["bucket"],
        region=target["region"],
        prefix=target["configuration_prefix"],
        capability_profile=request["plan"]["capability_profile"],
    )
    if snapshot is None and read_target(settings) != expected:
        refuse()
    if snapshot is not None and snapshot.source_material is not None:
        access = snapshot.source_material.access
        secret = snapshot.source_material.secret
    else:
        access = settings.get_secret("storage.s3.access_key")
        secret = settings.get_secret("storage.s3.secret_key")
    if (
        not isinstance(access, str)
        or not access
        or not isinstance(secret, str)
        or not secret
        or snapshot is None
        and read_target(settings) != expected
    ):
        refuse()
    signed = sign(
        target,
        key,
        method,
        query,
        headers,
        access,
        secret,
        **({"signing_window": signing_window} if signing_window is not None else {}),
    )
    # Internal transport only. PUT delivery remains a plain memory-only wire;
    # producer trust installation is a separate mounting gate.
    if snapshot is not None and method != "PUT":
        signed["_tls_context"] = tls_context(snapshot)
    return signed


def object_info(request, artifact, headers):
    etag = headers.get("etag", "")
    version = headers.get("x-amz-version-id")
    if not isinstance(etag, str) or not re.fullmatch(r'"[^"\r\n]{1,1022}"', etag):
        refuse()
    if version is not None and (
        not version or len(version) > 1024 or any(ord(c) < 32 for c in version)
    ):
        refuse()
    size = int(headers["content-length"])
    if not artifact["ciphertext_min"] <= size <= artifact["ciphertext_max"]:
        refuse()
    meta = {k[11:]: v for k, v in headers.items() if k.startswith("x-amz-meta-")}
    if meta != metadata(request, artifact):
        refuse()
    checksum_type = headers.get("x-amz-checksum-type", "")
    checksum = ""
    if checksum_type not in ("", "FULL_OBJECT", "COMPOSITE"):
        refuse()
    if headers.get("x-amz-checksum-sha256") and checksum_type == "FULL_OBJECT":
        raw = base64.b64decode(headers["x-amz-checksum-sha256"], validate=True)
        if len(raw) != 32:
            refuse()
        checksum = raw.hex()
    return dict(
        etag=etag,
        version_id=version,
        bytes=size,
        sha256=checksum,
        checksum_type=checksum_type,
        metadata=meta,
    )


def resolve_control(db, backup, agent, body, proof):
    try:
        db.info["provider_control"] = True
        if (
            db.new
            or db.dirty
            or db.deleted
            or type(body) is not dict
            or set(body) != {"schema", "binding", "artifact_key", "operation", "args"}
            or type(body["schema"]) is not int
            or body["schema"] != 1
        ):
            refuse()
        binding, key, op, args = (
            body["binding"],
            body["artifact_key"],
            body["operation"],
            body["args"],
        )
        if op == "compensate_pre_finalize":
            from core.storage_compensation import compensate_pre_finalize

            return compensate_pre_finalize(db, backup, agent, body, proof)
        if type(args) is not dict or op not in {
            "create",
            "part",
            "part_ack",
            "complete",
            "head",
        }:
            refuse()
        claim, request = admit(db, backup, agent, binding, proof)
        artifacts = [a for a in request["plan"]["artifacts"] if a["key"] == key]
        if len(artifacts) != 1:
            refuse()
        artifact = artifacts[0]
        state = deepcopy(claim.provider_control or {})
        item = state.get(key)
        if op == "create":
            if args:
                refuse()
            if item is not None:
                if item["phase"] == "uploading":
                    db.commit()
                    return dict(schema=1, upload_id=item["upload_id"])
                refuse()
            item = state[key] = dict(
                phase="create_intent",
                parts=[],
                upload_id=None,
                intent_deadline=int(time.time()) + PART_WINDOW,
            )
            save(db, claim, state)
            # A commit with lost acknowledgement never enters this leg.
            claim, request = admit(db, backup, agent, binding, proof)
            if (
                claim.provider_control != state
                or int(time.time()) + TTL > item["intent_deadline"]
            ):
                refuse()
            headers = {
                "x-amz-meta-" + k: v for k, v in metadata(request, artifact).items()
            }
            headers.update(
                {
                    "content-type": "application/octet-stream",
                    "x-amz-checksum-algorithm": "SHA256",
                }
            )
            signed = authority(db, request, key, "POST", {"uploads": ""}, headers)
            _, data = control_call(signed)
            fields = xml_fields(data, "InitiateMultipartUploadResult")
            upload = fields.get("UploadId", "")
            if (
                fields.get("Bucket") != request["plan"]["target"]["bucket"]
                or fields.get("Key") != key
                or not upload
                or len(upload) > 1024
                or any(ord(c) < 32 for c in upload)
            ):
                refuse()
            item.update(phase="uploading", upload_id=upload)
            save(db, claim, state)
            return dict(schema=1, upload_id=upload)
        if item is None or (
            op != "head"
            and (
                type(args.get("upload_id")) is not str
                or args["upload_id"] != item["upload_id"]
            )
        ):
            refuse()
        if op in {"part", "part_ack"}:
            fields = {"upload_id", "number", "bytes", "sha256"} | (
                {"etag"} if op == "part_ack" else set()
            )
            if set(args) != fields or item["phase"] != "uploading":
                refuse()
            n, size, checksum = args["number"], args["bytes"], args["sha256"]
            if (
                type(n) is not int
                or not 1 <= n <= 10000
                or type(size) is not int
                or not 0
                <= size
                <= part_size(artifact, request["plan"].get("transfer_profile"))
                or not isinstance(checksum, str)
                or not HASH.fullmatch(checksum)
            ):
                refuse()
            parts = item["parts"]
            expected = dict(number=n, bytes=size, sha256=checksum)
            if n > len(parts) + 1:
                refuse()
            if n == len(parts) + 1:
                if (
                    op != "part"
                    or (
                        parts
                        and (
                            parts[-1]["etag"] is None
                            or parts[-1]["bytes"]
                            != part_size(
                                artifact, request["plan"].get("transfer_profile")
                            )
                        )
                    )
                    or sum(p["bytes"] for p in parts) + size
                    > artifact["ciphertext_max"]
                ):
                    refuse()
                parts.append(
                    dict(**expected, etag=None, deadline=int(time.time()) + PART_WINDOW)
                )
            part = parts[n - 1]
            if any(part[k] != v for k, v in expected.items()):
                refuse()
            if op == "part_ack":
                etag = args["etag"]
                if (
                    not isinstance(etag, str)
                    or not re.fullmatch(r'[^"\r\n]{1,1022}', etag)
                    or (part["etag"] is not None and part["etag"] != etag)
                ):
                    refuse()
                part["etag"] = etag
                save(db, claim, state)
                return dict(schema=1, acknowledged=True)
            if part["etag"] is not None or int(time.time()) + TTL > part["deadline"]:
                refuse()
            save(db, claim, state)
            claim, request = admit(db, backup, agent, binding, proof)
            if (
                claim.provider_control != state
                or int(time.time()) + TTL > part["deadline"]
            ):
                refuse()
            headers = {
                "content-length": str(size),
                "x-amz-checksum-sha256": base64.b64encode(
                    bytes.fromhex(checksum)
                ).decode(),
                "x-amz-content-sha256": checksum,
            }
            signed = authority(
                db,
                request,
                key,
                "PUT",
                {"uploadId": args["upload_id"], "partNumber": str(n)},
                headers,
            )
            db.commit()
            if int(time.time()) >= signed["expires_at"]:
                refuse()
            return dict(schema=1, authority=signed)
        if op == "complete":
            if set(args) != {"upload_id", "parts"} or type(args["parts"]) is not list:
                refuse()
            expected = [
                {k: p[k] for k in ("number", "bytes", "sha256", "etag")}
                for p in item["parts"]
            ]
            if (
                args["parts"] != expected
                or not expected
                or any(p["etag"] is None for p in expected)
            ):
                refuse()
            if (
                not artifact["ciphertext_min"]
                <= sum(p["bytes"] for p in expected)
                <= artifact["ciphertext_max"]
            ):
                refuse()
            if item["phase"] == "completed":
                db.commit()
                return dict(schema=1, object=item["object"])
            if item["phase"] != "uploading":
                refuse()
            item["phase"] = "complete_intent"
            item["intent_deadline"] = int(time.time()) + PART_WINDOW
            save(db, claim, state)
            claim, request = admit(db, backup, agent, binding, proof)
            if (
                claim.provider_control != state
                or int(time.time()) + TTL > item["intent_deadline"]
            ):
                refuse()
            root = ElementTree.Element("CompleteMultipartUpload")
            for p in expected:
                node = ElementTree.SubElement(root, "Part")
                for field, value in (
                    ("PartNumber", p["number"]),
                    ("ETag", p["etag"]),
                    (
                        "ChecksumSHA256",
                        base64.b64encode(bytes.fromhex(p["sha256"])).decode(),
                    ),
                ):
                    ElementTree.SubElement(node, field).text = str(value)
            data = ElementTree.tostring(root, encoding="utf-8")
            headers = {
                "content-type": "application/xml",
                "content-length": str(len(data)),
                "x-amz-content-sha256": hashlib.sha256(data).hexdigest(),
                "if-none-match": "*",
            }
            signed = authority(
                db, request, key, "POST", {"uploadId": item["upload_id"]}, headers
            )
            returned, response = control_call(signed, data)
            fields = xml_fields(response, "CompleteMultipartUploadResult")
            if (
                fields.get("Bucket") != request["plan"]["target"]["bucket"]
                or fields.get("Key") != key
            ):
                refuse()
            etag = fields.get("ETag", "")
            if not re.fullmatch(r'"[^"\r\n]{1,1022}"', etag):
                refuse()
            version = returned.get("x-amz-version-id")
            if version is not None and (
                not version or len(version) > 1024 or any(ord(c) < 32 for c in version)
            ):
                refuse()
            item.update(
                phase="completed",
                object=dict(
                    etag=etag,
                    version_id=version,
                    bytes=0,
                    sha256="",
                    checksum_type="",
                    metadata={},
                ),
            )
            save(db, claim, state)
            return dict(schema=1, object=item["object"])
        if (
            set(args) != {"etag", "version_id"}
            or item["phase"] != "completed"
            or any(args[k] != item["object"][k] for k in ("etag", "version_id"))
        ):
            refuse()
        query = {} if args["version_id"] is None else {"versionId": args["version_id"]}
        signed = authority(
            db,
            request,
            key,
            "HEAD",
            query,
            {"if-match": args["etag"], "x-amz-checksum-mode": "ENABLED"},
        )
        headers, _ = control_call(signed)
        info = object_info(request, artifact, headers)
        if (
            info["etag"] != args["etag"]
            or info["version_id"] != args["version_id"]
            or info["bytes"] != sum(p["bytes"] for p in item["parts"])
        ):
            refuse()
        db.commit()
        return dict(schema=1, object=info)
    except Exception:
        try:
            db.rollback()
        except Exception:
            db.close()
        raise StorageOwnershipError("Transaction control unavailable") from None
    finally:
        db.info.pop("provider_control", None)
