"""Read-only S3 discovery and fresh VM recovery from independently trusted points."""

import base64
from contextlib import closing
from copy import deepcopy
from datetime import timezone
import hashlib
import re
from types import SimpleNamespace
from urllib.parse import urlsplit
from xml.etree.ElementTree import ParseError

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError
from cryptography.exceptions import InvalidTag
from pydantic import BaseModel, ConfigDict, Field

from core.agent_scope import provider_name
from core.kubevirt_restore import require_restore_capability
from core.s3_ownership import StorageOwnershipError, storage_identity
from core.settings_service import SettingsService
from core.storage_publication import MAX_MANIFEST, MAX_MEMBERS
from core.storage_receipt_v2 import canonical, decode, validate
from core.storage_semantics import UUID
from core.tenant_context import commercial_mode
from core.vm_agent_peer import vm_agent_peer
from models import Agent, EncryptionKey, VM

POINT_PREFIX = "vesta-recovery/v1/"
LEGACY_PREFIX = "vnbui-owned/v1/"
ENVELOPE_BYTES = 64 * 1024
DISCOVERY_LIMIT = 12
LEGACY_SCAN_LIMIT = 250
RESTORE_INPUT_LIMIT = 900 * 1024
LEGACY_IDENTITY_KEY = re.compile(
    r"vnbui-owned/v1/[0-9a-f]{64}/[0-9a-f]{64}/chain\.json\Z"
)
LEGACY_KEY = re.compile(
    r"vnbui-owned/v1/([0-9a-f]{64})/([0-9a-f]{64})/generations/"
    r"([0-9a-f-]{36})\.json\Z"
)


class BucketRecoveryError(StorageOwnershipError):
    pass


class TrustAnchor(BaseModel):
    model_config = ConfigDict(extra="forbid")
    installation_id: str = Field(pattern="^" + UUID.pattern.removesuffix(r"\Z") + "$")
    org_id: str = Field(pattern="^" + UUID.pattern.removesuffix(r"\Z") + "$")
    public_key: str = Field(pattern=r"^[A-Za-z0-9_-]{43}$")
    schema: str | None = Field(default=None, max_length=64)
    key_id: str | None = Field(default=None, max_length=128)


def _fail(
    message="Recovery point is unavailable or inconsistent with the configured repository",
):
    raise BucketRecoveryError(message)


def _digest_string(value):
    return hashlib.sha256(value.encode()).hexdigest()


def _point_key(trust, backup_id):
    return (
        f"{POINT_PREFIX}{trust['installation_id']}/{trust['org_id']}/{backup_id}.json"
    )


def _generation_key(point):
    org = _digest_string(point["org_id"])
    root = _digest_string(point["root_backup_id"])
    return f"{LEGACY_PREFIX}{org}/{root}/generations/{point['generation_id']}.json"


def recovery_admin(user):
    return (
        user.is_active is True
        and user.role == "admin"
        and (not commercial_mode() or user.is_platform_admin is True)
    )


def configured_repository(db):
    cfg = SettingsService(db).get_s3_recovery_config()
    if cfg is None:
        _fail("Configure dedicated read-only S3 recovery credentials")
    endpoint, bucket = storage_identity(cfg)
    if not endpoint.startswith("https://") or cfg["endpoint"] != endpoint:
        _fail(
            "Configure an explicit HTTPS S3 endpoint, bucket, region and read credentials"
        )
    return {
        **cfg,
        "endpoint": endpoint,
        "bucket": bucket,
        "region": cfg.get("region") or "us-east-1",
    }


def _client(cfg):
    endpoint = urlsplit(cfg["endpoint"])
    client = boto3.client(
        "s3",
        endpoint_url=cfg["endpoint"],
        aws_access_key_id=cfg["access_key"],
        aws_secret_access_key=cfg["secret_key"],
        aws_session_token=cfg.get("session_token"),
        region_name=cfg["region"],
        config=Config(
            connect_timeout=3,
            read_timeout=6,
            retries={"total_max_attempts": 1},
            s3={"addressing_style": "path"},
            request_checksum_calculation="when_required",
            response_checksum_validation="when_required",
        ),
    )

    def pin_request(request, **kwargs):
        actual = urlsplit(request.url)
        path = "/" + cfg["bucket"]
        if (
            (actual.scheme, actual.netloc) != (endpoint.scheme, endpoint.netloc)
            or not (actual.path == path or actual.path.startswith(path + "/"))
            or request.method not in {"GET", "HEAD"}
        ):
            _fail("S3 recovery attempted to leave the configured read-only repository")

    client.meta.events.register("before-send.s3", pin_request)
    return client


def _read(client, bucket, key, maximum, identity=None, *, version_id=None):
    args = {"Bucket": bucket, "Key": key}
    if identity is not None:
        args["IfMatch"] = identity["etag"]
        version_id = identity["version_id"]
    if version_id is not None:
        args["VersionId"] = version_id
    result = client.get_object(**args)
    stream = result["Body"]
    try:
        size = result.get("ContentLength")
        if type(size) is not int or not 0 < size <= maximum:
            _fail()
        if identity is not None and (
            size != identity["bytes"] or result.get("ETag") != identity["etag"]
        ):
            _fail()
        observed_version = result.get("VersionId")
        if version_id is not None and (observed_version or "null") != version_id:
            _fail()
        if identity is not None and version_id is None and observed_version is not None:
            _fail()
        data = bytearray()
        while len(data) <= size:
            part = stream.read(min(1024 * 1024, size + 1 - len(data)))
            if not part:
                break
            data.extend(part)
        if len(data) != size or (
            identity is not None
            and hashlib.sha256(data).hexdigest() != identity["sha256"]
        ):
            _fail()
        return bytes(data)
    finally:
        stream.close()


def _assert_repository(target, cfg):
    if (
        any(target.get(field) != cfg[field] for field in ("endpoint", "bucket"))
        or (target.get("region") or "us-east-1") != cfg["region"]
    ):
        _fail("This recovery point belongs to a different S3 repository")


def _verify_envelope(raw, trust, backup_id, cfg):
    from core.recovery_signing import verify_point_envelope, RecoveryUnavailable

    try:
        signed = verify_point_envelope(raw, trust)
    except RecoveryUnavailable:
        _fail("Recovery point signature or source scope is invalid")
    if signed["backup_id"] != backup_id:
        _fail()
    _assert_repository(signed["generation"], cfg)
    if signed["generation"]["key"] != _generation_key(signed):
        _fail()
    return signed


def public_point(point, status="verified", **fields):
    return {
        **{
            name: point.get(name)
            for name in (
                "backup_id",
                "name",
                "provider",
                "completed_at",
                "installation_id",
                "org_id",
            )
        },
        "status": status,
        **fields,
    }


def _valid_version(value):
    return (
        isinstance(value, str)
        and 0 < len(value.encode()) <= 1024
        and all(32 <= ord(character) != 127 for character in value)
    )


def _object_version(client, bucket, key, *, historical=False):
    """Use exact-key version listings with the same read-only IAM as discovery."""
    response = client.list_object_versions(Bucket=bucket, Prefix=key, MaxKeys=1)
    if historical:
        return any(
            item.get("Key") == key
            for field in ("Versions", "DeleteMarkers")
            for item in response.get(field, ())
        )
    for item in response.get("Versions", ()):
        if item.get("Key") == key and item.get("IsLatest") is True:
            version_id = item.get("VersionId")
            if _valid_version(version_id):
                return version_id
    _fail("The signed recovery envelope is unavailable")


def _version_cursor(key, version_id):
    return base64.urlsafe_b64encode(canonical([key, version_id])).decode("ascii")


def _version_markers(cursor, prefix):
    try:
        key, version_id = decode(
            base64.b64decode(cursor, altchars=b"-_", validate=True)
        )
        if not isinstance(key, str) or not key.startswith(prefix):
            raise ValueError()
        if version_id is not None and not _valid_version(version_id):
            raise ValueError()
    except (ValueError, TypeError):
        _fail("Resume discovery from the same repository and source scope")
    return {"KeyMarker": key, **({"VersionIdMarker": version_id} if version_id else {})}


def _listed_point(client, cfg, key, trust, version_id):
    path = key.removeprefix(POINT_PREFIX).split("/")
    if len(path) != 3 or not path[2].endswith(".json"):
        return None
    installation, org, filename = path
    identity = filename.removesuffix(".json")
    if any(not UUID.fullmatch(value) for value in (installation, org, identity)):
        return None
    candidate = {"installation_id": installation, "org_id": org, "backup_id": identity}
    try:
        raw = _read(client, cfg["bucket"], key, ENVELOPE_BYTES, version_id=version_id)
        if trust is None:
            # Validate intrinsic integrity for display only. Never admit or
            # persist self-supplied bucket trust as a recovery authorization.
            authority = {
                "installation_id": installation,
                "org_id": org,
                "public_key": decode(raw)["public_key"],
            }
            return public_point(
                _verify_envelope(raw, authority, identity, cfg), "trust_required"
            )
        point = _verify_envelope(raw, trust, identity, cfg)
        location = point["generation"]
        target = {
            "Bucket": cfg["bucket"],
            "Key": location["key"],
            "IfMatch": location["etag"],
        }
        if location["version_id"] is not None:
            target["VersionId"] = location["version_id"]
        try:
            current = client.head_object(**target)
        except (BotoCoreError, ClientError):
            return public_point(point, "unavailable")
        available = (
            current.get("ContentLength") == location["bytes"]
            and current.get("VersionId") == location["version_id"]
            and current.get("ETag") == location["etag"]
        )
        return public_point(point, "verified" if available else "unavailable")
    except (
        StorageOwnershipError,
        BotoCoreError,
        ClientError,
        ValueError,
        KeyError,
        TypeError,
    ):
        return public_point(candidate, "invalid")


def _listed_legacy_point(client, cfg, key, modified, version_id):
    if LEGACY_IDENTITY_KEY.fullmatch(key):
        return public_point({}, "incomplete", generation_key=key)
    match = LEGACY_KEY.fullmatch(key)
    if match is None or not UUID.fullmatch(match[3]):
        return None
    try:
        raw = _read(client, cfg["bucket"], key, MAX_MANIFEST, version_id=version_id)
        manifest = decode(raw)
        identity = {
            name: manifest[name]
            for name in (
                "installation_id",
                "org_id",
                "backup_id",
                "root_backup_id",
                "generation_id",
            )
        }
        if any(
            type(value) is not str or not UUID.fullmatch(value)
            for value in identity.values()
        ) or key != _generation_key(identity):
            _fail()
        request = manifest["members"][-1]["request"]
        point = {
            **identity,
            "name": request["plan"].get("vm_name"),
            "provider": request["plan"]["provider"],
            "completed_at": (
                modified.astimezone(timezone.utc).isoformat() if modified else None
            ),
            "generation": manifest["target"],
        }
        bundle, _ = _generation_bundle(manifest, point, cfg)
    except (
        StorageOwnershipError,
        BotoCoreError,
        ClientError,
        ValueError,
        KeyError,
        IndexError,
        TypeError,
        AttributeError,
    ):
        return public_point({}, "incomplete", generation_key=key)

    # A deleted or malformed signed record still takes precedence over an
    # unsigned record of the same point.
    try:
        if _object_version(
            client,
            cfg["bucket"],
            _point_key(identity, identity["backup_id"]),
            historical=True,
        ):
            return None
    except (BotoCoreError, ClientError):
        # Failure to look for signed authority never permits unsigned recovery.
        return public_point(
            point, "incomplete", generation_key=key, version_id=version_id
        )
    return public_point(
        point,
        "unsigned",
        generation_key=key,
        version_id=version_id,
        requires_kek=any(
            member["request"]["plan"]["encryption"]["format"] != "none"
            for member in bundle["members"]
        ),
    )


def discover(db, trust=None, cursor=None, legacy=False):
    cfg = configured_repository(db)
    prefix = LEGACY_PREFIX if legacy else POINT_PREFIX
    if trust:
        prefix += (
            _digest_string(trust["org_id"]) + "/"
            if legacy
            else f"{trust['installation_id']}/{trust['org_id']}/"
        )
    args = {
        "Bucket": cfg["bucket"],
        "Prefix": prefix,
        "MaxKeys": LEGACY_SCAN_LIMIT if legacy else DISCOVERY_LIMIT,
    }
    if cursor:
        args.update(_version_markers(cursor, prefix))

    with closing(_client(cfg)) as client:
        response = client.list_object_versions(**args)
        points = []
        next_cursor = (
            _version_cursor(
                response["NextKeyMarker"], response.get("NextVersionIdMarker")
            )
            if response.get("IsTruncated") and response.get("NextKeyMarker")
            else None
        )
        items = response.get("Versions", [])[: args["MaxKeys"]]
        inspected = 0
        for index, item in enumerate(items):
            key, version_id = item.get("Key"), item.get("VersionId")
            if (
                not isinstance(key, str)
                or not key.startswith(prefix)
                or item.get("IsLatest") is not True
                or not _valid_version(version_id)
            ):
                continue
            if legacy:
                if not (
                    LEGACY_KEY.fullmatch(key) or LEGACY_IDENTITY_KEY.fullmatch(key)
                ):
                    continue
                point = _listed_legacy_point(
                    client, cfg, key, item.get("LastModified"), version_id
                )
                inspected += 1
            else:
                point = _listed_point(client, cfg, key, trust, version_id)
            if point is not None:
                points.append(point)
            if legacy and inspected == DISCOVERY_LIMIT:
                if next_cursor is not None or index + 1 < len(items):
                    next_cursor = _version_cursor(key, version_id)
                break
        points.sort(key=lambda point: point["completed_at"] or "", reverse=True)
        return {"points": points, "next_cursor": next_cursor}


def _generation_bundle(manifest, point, cfg):
    from core.native_manifest import validate_receipt_binding
    from core.storage_lineage import stable_source

    if (
        manifest["protocol"] != "vnbui-storage-generation/1"
        or any(
            manifest[field] != point[field]
            for field in (
                "installation_id",
                "org_id",
                "backup_id",
                "root_backup_id",
                "generation_id",
            )
        )
        or not 0 < len(manifest["members"]) <= MAX_MEMBERS
    ):
        _fail()
    _assert_repository(manifest["target"], cfg)
    native = point["provider"] == "libvirt"
    if point["provider"] not in {"libvirt", "kubevirt"}:
        _fail()
    members, wrapped, seen = [], [], set()
    stable, prior = None, None
    for entry in manifest["members"]:
        request = entry["request"]
        plan = request["plan"]
        claim = SimpleNamespace(
            id=request["reservation_id"],
            backup_id=request["backup_id"],
            org_id=point["org_id"],
            endpoint=cfg["endpoint"],
            bucket=cfg["bucket"],
            state="reserved",
            dispatch_token=True,
            expected_plan={"schema": 3, "transaction": request},
        )
        request, receipt, receipt_hash = validate(claim, entry["receipt"])
        if (
            plan["provider"] != point["provider"]
            or plan["target"] != manifest["target"]
            or request["backup_id"] in seen
            or entry["receipt_sha256"] != receipt_hash
            or entry["acceptance"]["accepted"] is not True
            or entry["acceptance"]["receipt_sha256"] != receipt_hash
        ):
            _fail()
        seen.add(request["backup_id"])
        source = plan["source"]
        if native:
            inventory = source["inventory"]
            push = validate_receipt_binding(
                request,
                receipt,
                {
                    "push_result": entry["native_result"],
                    "inventory": inventory,
                    "inventory_sha256": hashlib.sha256(
                        canonical(inventory)
                    ).hexdigest(),
                },
            )
            push_manifest = push["manifest"]
            if (
                push_manifest["backup_id"] != request["backup_id"]
                or push_manifest["attempt_id"] != plan["attempt_id"]
                or push_manifest["domain_uuid"] != inventory["domain_uuid"]
                or push_manifest["checkpoint"] != inventory["checkpoint"]
                or push_manifest["exclusions"] != plan["exclusions"]
                or push_manifest["parent_backup_id"] != (prior[0] if prior else None)
                or push_manifest["parent_manifest_sha256"]
                != (prior[4] if prior else None)
            ):
                _fail()
            source_binding = (
                source["vm_id"],
                push_manifest["domain_uuid"],
                push_manifest["source"],
                push_manifest["exclusions"],
            )
            tracker, checkpoint, push_hash = (
                push_manifest["domain_uuid"],
                push_manifest["checkpoint"],
                push["manifest_sha256"],
            )
        else:
            source_binding = stable_source(source)
            tracker, checkpoint, push_hash = (
                entry["checkpoint"]["tracker_uid"],
                entry["checkpoint"]["checkpoint"],
                None,
            )
        binding = (request["agent_id"], plan.get("vm_name"), source_binding)
        parent = plan["parent"]
        if prior is None:
            if (
                parent is not None
                or plan["backup_type"] != "full"
                or request["backup_id"] != point["root_backup_id"]
            ):
                _fail()
            stable = binding
        elif (
            binding != stable
            or plan["backup_type"] != "incremental"
            or parent is None
            or tuple(
                parent[k]
                for k in ("backup_id", "receipt_sha256", "tracker_uid", "checkpoint")
            )
            != prior[:4]
            or parent["root_backup_id"] != point["root_backup_id"]
        ):
            _fail()
        member = {"request": request, "receipt": receipt}
        if native:
            member["push_result"] = push
        members.append(member)
        wrapped.append(entry["wrapped_attempt_key"])
        prior = (request["backup_id"], receipt_hash, tracker, checkpoint, push_hash)
    selected = members[-1]["request"]
    selected_plan = selected["plan"]
    if (
        selected["backup_id"] != point["backup_id"]
        or selected_plan["source"] != manifest["source"]
        or (not native and selected_plan["vm_name"] != point["name"])
        or (
            selected_plan["parent"] is not None
            and selected_plan["parent"]["generation_id"] != manifest["predecessor_id"]
        )
    ):
        _fail()
    schema = "vnbui-native-restore/1" if native else "vnbui-kubevirt-restore/1"
    return {"schema": schema, "members": members}, wrapped


def load_point(db, trust, backup_id):
    if not UUID.fullmatch(backup_id):
        _fail()
    cfg = configured_repository(db)
    try:
        with closing(_client(cfg)) as client:
            envelope_key = _point_key(trust, backup_id)
            version_id = _object_version(client, cfg["bucket"], envelope_key)
            raw = _read(
                client,
                cfg["bucket"],
                envelope_key,
                ENVELOPE_BYTES,
                version_id=version_id,
            )
            point = _verify_envelope(raw, trust, backup_id, cfg)
            identity = point["generation"]
            raw = _read(client, cfg["bucket"], identity["key"], MAX_MANIFEST, identity)
        manifest = decode(raw)
        if canonical(manifest) != raw:
            _fail()
        bundle, wrapped = _generation_bundle(manifest, point, cfg)
    except (
        BotoCoreError,
        ClientError,
        ValueError,
        KeyError,
        TypeError,
        AttributeError,
        IndexError,
    ):
        _fail()
    return cfg, point, bundle, wrapped


def compatible_destination(db, agent, provider, bundle):
    if (
        agent.status != "online"
        or provider_name(agent) != provider
        or (agent.capabilities or {}).get("s3_recovery_restore") is not True
    ):
        _fail("An online enrolled destination with S3 recovery support is required")
    if provider == "kubevirt":
        require_restore_capability(agent, bundle)
        namespaces = (agent.capabilities or {}).get("s3_recovery_restore_namespaces")
        if namespaces is None:
            namespaces = ((agent.metrics or {}).get("scope") or {}).get(
                "restore_namespaces"
            )
        if not isinstance(namespaces, list) or not namespaces:
            _fail("Set the KubeVirt agent's allowed restore namespaces")
    else:
        namespaces = []
    vm_agent_peer(db, agent)
    return namespaces


def destination(
    db,
    org_id,
    agent_id,
    provider,
    bundle,
    target=None,
    *,
    lock=False,
    check_existing=True,
):
    query = db.query(Agent).filter_by(id=agent_id, org_id=org_id).populate_existing()
    if lock:
        query = query.with_for_update(nowait=True)
    agent = query.one_or_none()
    if agent is None:
        _fail("Destination agent is unavailable")
    namespaces = compatible_destination(db, agent, provider, bundle)
    if target is not None:
        candidate = db.query(VM).filter_by(
            org_id=org_id,
            agent_id=agent_id,
            name=target["vm_name"],
            inventory_present=True,
        )
        if provider == "kubevirt":
            if target["namespace"] not in namespaces:
                _fail(
                    "Destination is outside the enrolled agent's restore namespace scope"
                )
            candidate = candidate.filter_by(namespace=target["namespace"])
        if check_existing and candidate.first() is not None:
            _fail("Destination VM already exists")
    return agent


def build_plan(db, user, agent_id, restore_id, trust, point, bundle, target):
    from core import kubevirt_restore, native_restore

    native = point["provider"] == "libvirt"
    selected = bundle["members"][-1]
    request = selected["request"]
    if native:
        mapped = native_restore.validate_target(
            target, selected["push_result"]["manifest"], point["name"]
        )
        profile = native_restore
    else:
        mapped = kubevirt_restore.validate_target(
            target, request["plan"]["source"], point["name"]
        )
        profile = kubevirt_restore
    destination(db, user.org_id, agent_id, point["provider"], bundle, mapped, lock=True)
    plan = dict(
        schema=profile.SCHEMA,
        org_id=user.org_id,
        agent_id=agent_id,
        restore_id=restore_id,
        target=mapped,
        recovery_origin={"org_id": trust["org_id"], "agent_id": request["agent_id"]},
        bundle=bundle,
    )
    # Agents store the hydrated request in private journals with a fixed size.
    # Leave room for credentials, key framing and the transport envelope.
    if len(canonical(plan)) > RESTORE_INPUT_LIMIT - 32 * 1024:
        _fail(
            "This chain exceeds the enrolled agent's restore input limit. Use the standalone S3 reader."
        )
    return plan


def check_point(db, restore):
    recorded = restore.s3_recovery
    cfg, selected, bundle, wrapped = load_point(
        db, recorded["trust"], recorded["point"]["backup_id"]
    )
    plan = restore.native_plan or restore.kubevirt_plan
    if selected != recorded["point"] or bundle != plan["bundle"]:
        _fail("The bucket recovery point changed after approval")
    return cfg, bundle, wrapped


def require_imported_keys(db, org_id, bundle, wrapped):
    for member, saved in zip(bundle["members"], wrapped, strict=True):
        encryption = member["request"]["plan"]["encryption"]
        if encryption["format"] == "none":
            if saved is not None:
                _fail()
            continue
        if not isinstance(saved, dict):
            _fail("Recovery generation lacks wrapped key custody")
        _, key_id, fingerprint = encryption["key_ref"].split(":")
        key = (
            db.query(EncryptionKey.id)
            .filter(
                EncryptionKey.org_id == org_id,
                EncryptionKey.id == key_id,
                EncryptionKey.key_hash == fingerprint,
                EncryptionKey.provider == "local",
                EncryptionKey.status.in_(("active", "rotated")),
            )
            .first()
        )
        if key is None:
            _fail(
                "Import the matching independently saved recovery key export into this organization"
            )


def _member_key(db, org_id, member, wrapped):
    from core.storage_attempt_key import unwrap_retained_attempt_key

    request = member["request"]
    claim = SimpleNamespace(
        id=request["reservation_id"],
        org_id=request["org_id"],
        backup_id=request["backup_id"],
        wrapped_attempt_key=wrapped,
        state="published",
        prepared_receipt=member["receipt"],
        expected_plan={"transaction": request},
    )
    return unwrap_retained_attempt_key(db, claim, request, recovery_org_id=org_id)


def _capture_object(client, cfg, receipt, maximum):
    if not 0 < receipt["ciphertext_bytes"] <= maximum:
        _fail("Captured VM definition exceeds the recovery preview limit")
    return _read(
        client,
        cfg["bucket"],
        receipt["key"],
        maximum,
        {
            "etag": receipt["etag"],
            "version_id": receipt["version_id"],
            "bytes": receipt["ciphertext_bytes"],
            "sha256": receipt["ciphertext_sha256"],
        },
    )


def inspect_definition(db, org_id, cfg, bundle, wrapped):
    """Inspect exact, signed source metadata after local recovery-admin admission."""
    from core import recovery_definition as capture

    selected = bundle["members"][-1]
    plan = selected["request"]["plan"]
    objects = selected["receipt"]["objects"]
    try:
        with closing(_client(cfg)) as client:
            if plan["provider"] == "libvirt":
                (obj,) = [obj for obj in objects if obj["role"] == "domain_config"]
                if not 0 < obj["plaintext_bytes"] <= capture.MAX_DOMAIN_XML:
                    _fail("Captured domain XML exceeds the recovery preview limit")
                body = _capture_object(client, cfg, obj, capture.MAX_DOMAIN_XML + 37)
                key = _member_key(db, org_id, selected, wrapped[-1])
                plaintext = capture.decrypt_capture(body, key, capture.MAX_DOMAIN_XML)
                if (
                    len(plaintext) != obj["plaintext_bytes"]
                    or hashlib.sha256(plaintext).hexdigest() != obj["plaintext_sha256"]
                ):
                    _fail("Captured domain XML differs from its accepted receipt")
                return capture.native_requirements(
                    plaintext, selected["push_result"]["manifest"]
                )

            manifests = {
                obj["volume_id"]: obj
                for obj in objects
                if obj["role"] == "volume_manifest"
            }
            payloads = {
                obj["volume_id"]: obj["key"]
                for obj in objects
                if obj["role"] == "volume_payload"
            }
            if (
                sum(obj["ciphertext_bytes"] for obj in manifests.values())
                > capture.MAX_MANIFEST_TOTAL
            ):
                _fail("Captured volume metadata exceeds the recovery preview limit")
            archive = None
            source = plan["source"]
            for volume in source["volumes"]:
                obj = manifests[volume["pvc_uid"]]
                manifest = decode(_capture_object(client, cfg, obj, MAX_MANIFEST))
                encoded = manifest["vm_definition"]
                if (
                    manifest["format"] != "vnbui-kubevirt-cbt-v1"
                    or manifest["vm_namespace"] != source["namespace"]
                    or manifest["vm_uid"] != source["vm_uid"]
                    or manifest["volume"] != volume["name"]
                    or manifest["backup_type"] != plan["backup_type"]
                    or manifest["encrypted"]
                    is not (plan["encryption"]["format"] != "none")
                    or manifest["payload_key"] != payloads[volume["pvc_uid"]]
                    or not isinstance(encoded, str)
                    or not 0 < len(encoded) <= capture.MAX_ENCODED_DEFINITION
                    or (archive is not None and archive != encoded)
                ):
                    _fail(
                        "Captured VM definition differs across accepted volume manifests"
                    )
                archive = encoded
        key = _member_key(db, org_id, selected, wrapped[-1])
        return capture.kubevirt_requirements(
            capture.kubevirt_definition(archive, key), plan
        )
    except (
        BotoCoreError,
        ClientError,
        ValueError,
        KeyError,
        TypeError,
        AttributeError,
        ParseError,
        InvalidTag,
    ):
        _fail("Verified VM definition is unavailable or invalid")


def require_capture_mappings(plan, source_name, required):
    target = plan["target"]
    if "interfaces" in required:
        if target["vm_name"] == source_name or {
            entry["source_mac"] for entry in target["networks"]
        } != {entry["source_mac"] for entry in required["interfaces"]}:
            _fail("Use a fresh name and explicitly map every captured source interface")
    elif {entry["name"] for entry in target["networks"]} != {
        entry["name"] for entry in required["networks"]
    } or set(target["dependencies"]) != {
        entry["kind"] + "/" + entry["name"] for entry in required["dependencies"]
    }:
        _fail("Map every captured source network and dependency explicitly")


def hydrate_request(db, restore, material):
    read_cfg, bundle, wrapped = material
    cfg = configured_repository(db)
    if cfg != read_cfg:
        _fail("The configured repository changed before restore dispatch")
    plan = deepcopy(restore.native_plan or restore.kubevirt_plan)
    plan["s3"] = {
        key: cfg[key]
        for key in ("endpoint", "bucket", "region", "access_key", "secret_key")
    }
    if cfg.get("session_token"):
        plan["s3"]["session_token"] = cfg["session_token"]
    plan["keys"] = {}
    # Validate the original wrapping context but unwrap against an explicitly
    # imported key with the same identity in the destination organization.
    for member, saved in zip(bundle["members"], wrapped, strict=True):
        key = _member_key(db, restore.org_id, member, saved)
        if key is not None:
            plan["keys"][member["request"]["backup_id"]] = base64.b64encode(key).decode(
                "ascii"
            )
    profile = "native" if restore.native_plan else "kubevirt"
    return {"restore_id": restore.id, profile: plan}
