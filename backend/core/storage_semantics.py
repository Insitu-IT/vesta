"""Semantic admission for the currently held transaction wire capability.

This validates an envelope, not persisted authority or observed cluster state.
Incremental syntax is not acceptance: persisted lineage admission is separate.
"""

import hashlib
import re
from urllib.parse import urlsplit

UUID = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z"
)
NAME = re.compile(r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?\Z")
IDENTITY = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,252}\Z")
MAX_CAPACITY = (2**63 - 1) // 2
MANIFEST_LIMIT = 16 * 1024 * 1024


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


def validate_target(t, require):
    """Shared literal destination rules, independent of source representation."""
    url = urlsplit(t.endpoint)
    require(url.scheme == "https" and bool(url.hostname))
    require(
        not url.username
        and not url.password
        and not url.path
        and not url.query
        and not url.fragment
    )
    require(
        t.endpoint == "https://" + url.netloc
        and url.netloc.isascii()
        and not any(c.isspace() for c in url.netloc)
        and "%" not in url.netloc
    )
    require(url.port is None or 0 < url.port <= 65535)
    require(
        NAME.fullmatch(t.bucket) is not None
        and 3 <= len(t.bucket) <= 63
        and ".." not in t.bucket
    )
    require(t.region == "" or IDENTITY.fullmatch(t.region) is not None)
    require(len(t.configuration_prefix.encode()) <= 1024)
    require(not any(ord(c) < 32 or ord(c) == 127 for c in t.configuration_prefix))
    require(
        not t.configuration_prefix.startswith("/")
        and "\\" not in t.configuration_prefix
        and not any(x in {".", ".."} for x in t.configuration_prefix.split("/"))
    )


def validate_semantics(request):
    """Raise a value-free error; caller must never log the rejected envelope."""
    p, s = request.plan, request.plan.source

    def require(condition):
        if not condition:
            raise ValueError("Invalid storage transaction semantics")

    for value in (
        request.org_id,
        request.agent_id,
        request.backup_id,
        request.reservation_id,
        s.agent_id,
        s.vm_id,
        p.attempt_id,
    ):
        require(UUID.fullmatch(value) is not None)
    require(request.agent_id == s.agent_id)
    require(request.reservation_id == p.attempt_id)
    require(p.attempt_id[14] == "4")
    require(IDENTITY.fullmatch(s.vm_uid) is not None)
    require(s.vmi_uid is None or IDENTITY.fullmatch(s.vmi_uid) is not None)
    require(NAME.fullmatch(s.namespace) is not None and len(s.namespace) <= 63)
    require(NAME.fullmatch(p.vm_name) is not None)
    require(p.credential_ref == "installation/storage.s3")
    require(p.checksum_policy == "sha256-parts-receipt-v2")
    if p.backup_type == "full":
        require(p.parent is None)
    else:
        require(p.backup_type == "incremental" and p.parent is not None)
        parent = p.parent
        for value in (parent.backup_id, parent.root_backup_id, parent.generation_id):
            require(UUID.fullmatch(value) is not None and value != request.backup_id)
        require(re.fullmatch(r"[0-9a-f]{64}", parent.receipt_sha256) is not None)
        require(IDENTITY.fullmatch(parent.tracker_uid) is not None)
        require(IDENTITY.fullmatch(parent.checkpoint) is not None)
    encrypted = p.encryption.format == "vnbu1-aes256gcm-chunk5242880"
    if encrypted:
        parts = (p.encryption.key_ref or "").split(":")
        require(len(parts) == 3 and parts[0] == "kek")
        require(UUID.fullmatch(parts[1]) is not None)
        require(re.fullmatch(r"(?:[0-9a-f]{16}|[0-9a-f]{64})", parts[2]) is not None)
    else:
        require(p.encryption.format == "none" and p.encryption.key_ref is None)
    validate_target(p.target, require)
    require(1 <= len(s.volumes) <= 256)
    validate_volume_set(s.volumes, require)
    names = {v.name for v in s.volumes}
    volumes = {v.pvc_uid: v for v in s.volumes}
    if s.schema == 2:
        validate_volume_set(s.native_volumes, require)
        native = {v.name: v for v in s.native_volumes}
        require(all(native.get(v.name) == v for v in s.volumes))
        require(
            all(v.name in names or v.name in p.exclusions for v in s.native_volumes)
        )
    require(len(p.exclusions) <= 256 and p.exclusions == sorted(set(p.exclusions)))
    require(all(NAME.fullmatch(x) is not None and x not in names for x in p.exclusions))
    require(len(p.artifacts) == 2 * len(volumes))
    root = f"vnbui-owned/v1/{digest(request.org_id)}/{digest(request.backup_id)}/payload/{p.attempt_id}/"
    pairs, keys = set(), set()
    for a in p.artifacts:
        require(
            a.volume_id in volumes and a.role in {"volume_payload", "volume_manifest"}
        )
        pair = (a.volume_id, a.role)
        require(pair not in pairs and a.key not in keys)
        pairs.add(pair)
        keys.add(a.key)
        require(a.key == root + digest(a.volume_id) + "/" + a.role)
        maximum = (
            volumes[a.volume_id].capacity_bytes
            if a.role == "volume_payload"
            else MANIFEST_LIMIT
        )
        ciphertext_min, ciphertext_max = 0, maximum
        if encrypted and a.role == "volume_payload":
            ciphertext_min = 5
            ciphertext_max = 5 + maximum + 32 * ((maximum + 5242880 - 1) // 5242880)
        require(
            a.plaintext_min == 0
            and a.ciphertext_min == ciphertext_min
            and a.plaintext_max == maximum
            and a.ciphertext_max == ciphertext_max
        )
    require([a.key for a in p.artifacts] == sorted(keys))


def validate_volume_set(volumes_set, require):
    require(1 <= len(volumes_set) <= 256)
    names, volumes, pvcs, serials = set(), {}, set(), set()
    for v in volumes_set:
        require(
            NAME.fullmatch(v.name) is not None
            and NAME.fullmatch(v.pvc_name) is not None
        )
        require(IDENTITY.fullmatch(v.pvc_uid) is not None)
        require(re.fullmatch(r"[1-9][0-9]{0,19}", v.pvc_resource_version) is not None)
        require(0 < v.capacity_bytes <= MAX_CAPACITY)
        require(
            v.name not in names and v.pvc_uid not in volumes and v.pvc_name not in pvcs
        )
        names.add(v.name)
        volumes[v.pvc_uid] = v
        pvcs.add(v.pvc_name)
        m = v.mapping
        require(
            m.disk_name == v.name
            and m.device == "disk"
            and m.bus in {"virtio", "sata", "scsi", "usb"}
        )
        if m.serial is not None:
            require(
                IDENTITY.fullmatch(m.serial) is not None and m.serial not in serials
            )
            serials.add(m.serial)
