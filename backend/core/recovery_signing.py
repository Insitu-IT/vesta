"""Installation-local signing key and tenant-scoped public recovery trust."""

import base64
from datetime import datetime
import re
from urllib.parse import urlsplit
import hashlib
import json
from uuid import UUID

from cryptography.exceptions import InvalidSignature
from cryptography.fernet import InvalidToken
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from sqlalchemy import or_, select, text

from core import settings_service
from core.installation_config import RECOVERY_SIGNER_IDENTITY, RECOVERY_SIGNING_SEED
from core.recovery_key_identity import (
    base64url,
    public_identity as _public_identity,
    signer_identity as _signer_identity,
    unique_object as _unique_object,
    verify_signing_seed,
)
from core.singleton import lock_key
from core.tenant_context import PlatformContext, TenantContext
from database import SessionLocal
from models import (
    Organization,
    RecoveryPublication,
    SecretV3,
    SettingV3,
    StorageConfigurationClock,
)

SIGNING_SEED = RECOVERY_SIGNING_SEED
TRUST_SCHEMA = "vesta-recovery-trust/1"
POINT_FORMAT = "vesta-recovery-point/1"
ENVELOPE_FORMAT = "vesta-recovery-envelope/1"
JWS_TYPE = "vesta-recovery-point+jws"


class RecoveryUnavailable(RuntimeError):
    """No recoverable point should be attested by this operation."""


def canonical_json(document):
    return json.dumps(
        document, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode()


def canonical_id(value):
    try:
        return (
            isinstance(value, str)
            and str(UUID(value)) == value
            and UUID(value).int != 0
        )
    except ValueError:
        return False


def installation_id(db):
    identity = db.get(StorageConfigurationClock, 1)
    if identity is None or not canonical_id(identity.installation_id):
        raise RecoveryUnavailable("Recovery installation identity unavailable")
    return identity.installation_id


def _signed_history(factory, organizations):
    for org in organizations:
        with TenantContext(org), factory() as db:
            if (
                db.scalar(
                    select(RecoveryPublication.generation_id)
                    .where(
                        RecoveryPublication.org_id == org,
                        or_(
                            RecoveryPublication.envelope.is_not(None),
                            RecoveryPublication.published_at.is_not(None),
                        ),
                    )
                    .limit(1)
                )
                is not None
            ):
                return True
    return False


def signing_key(factory=SessionLocal, *, create=True):
    # Both rows are installation custody, not tenant-authored settings. One
    # advisory lock serializes bootstrap and the marker never changes.
    with PlatformContext(), factory() as db:
        if db.get_bind().dialect.name == "postgresql":
            db.execute(
                text("SELECT pg_advisory_xact_lock(:key)"),
                {"key": lock_key(SIGNING_SEED)},
            )
        row = db.get(SecretV3, SIGNING_SEED)
        marker = db.get(SettingV3, RECOVERY_SIGNER_IDENTITY)
        identifier = installation_id(db)
        cipher = settings_service._fernet
        if cipher is None:
            raise RecoveryUnavailable("Recovery signing custody unavailable")
        if row is None and marker is None:
            if not create:
                raise RecoveryUnavailable("Recovery signing custody is not initialized")
            organizations = tuple(
                db.scalars(select(Organization.id).order_by(Organization.id))
            )
            if _signed_history(factory, organizations):
                raise RecoveryUnavailable(
                    "Recovery signing custody is missing for retained records"
                )
            private = Ed25519PrivateKey.generate()
            seed = private.private_bytes(
                serialization.Encoding.Raw,
                serialization.PrivateFormat.Raw,
                serialization.NoEncryption(),
            )
            db.add(
                SecretV3(
                    key=SIGNING_SEED,
                    encrypted_value=cipher.encrypt(base64.b64encode(seed)).decode(
                        "ascii"
                    ),
                    source="installation",
                )
            )
            db.add(
                SettingV3(
                    key=RECOVERY_SIGNER_IDENTITY,
                    value=canonical_json(_signer_identity(private, identifier)).decode(
                        "ascii"
                    ),
                    value_type="json",
                    source="installation",
                )
            )
            db.commit()
            return private
        if (
            row is None
            or marker is None
            or row.source != "installation"
            or row.vault_path is not None
            or marker.source != "installation"
            or marker.value_type != "json"
        ):
            raise RecoveryUnavailable("Recovery signing custody is incomplete")
        try:
            encoded = cipher.decrypt(row.encrypted_value.encode("ascii"))
            return verify_signing_seed(encoded, marker.value, identifier)
        except (AttributeError, InvalidToken, TypeError, ValueError):
            raise RecoveryUnavailable("Recovery signing custody unavailable") from None


def recovery_trust(db, org_id, *, factory=SessionLocal, create=False):
    if not canonical_id(org_id):
        raise RecoveryUnavailable("Recovery organization identity unavailable")
    identifier = installation_id(db)
    key_id, public_key = _public_identity(signing_key(factory, create=create))
    return {
        "schema": TRUST_SCHEMA,
        "installation_id": identifier,
        "org_id": org_id,
        "key_id": key_id,
        "public_key": public_key,
    }


def sign_point(point, key):
    key_id, public_key = _public_identity(key)
    protected = base64url(
        canonical_json({"alg": "EdDSA", "kid": key_id, "typ": JWS_TYPE})
    )
    payload = base64url(canonical_json(point))
    signed = f"{protected}.{payload}"
    jws = f"{signed}.{base64url(key.sign(signed.encode('ascii')))}"
    return canonical_json(
        {"format": ENVELOPE_FORMAT, "public_key": public_key, "jws": jws}
    )


def _decode_base64url(text_value):
    if not isinstance(text_value, str) or not re.fullmatch(
        r"[A-Za-z0-9_-]+", text_value
    ):
        raise ValueError("Invalid base64url")
    result = base64.urlsafe_b64decode(text_value + "=" * (-len(text_value) % 4))
    if base64url(result) != text_value:
        raise ValueError("Noncanonical base64url")
    return result


def validate_recovery_trust(value):
    """Return a detached trust document from an independently supplied source."""
    try:
        if (
            type(value) is not dict
            or set(value)
            != {"schema", "installation_id", "org_id", "key_id", "public_key"}
            or value["schema"] != TRUST_SCHEMA
            or not canonical_id(value["installation_id"])
            or not canonical_id(value["org_id"])
        ):
            raise ValueError("Recovery trust scope unavailable")
        raw = _decode_base64url(value["public_key"])
        Ed25519PublicKey.from_public_bytes(raw)
        if value["key_id"] != hashlib.sha256(raw).hexdigest():
            raise ValueError("Recovery trust key identity differs")
        return dict(value)
    except (KeyError, TypeError, ValueError):
        raise RecoveryUnavailable(
            "Recovery trust document could not be verified"
        ) from None


def _verified_point_shape(point, trust):
    if (
        type(point) is not dict
        or set(point)
        != {
            "format",
            "installation_id",
            "org_id",
            "backup_id",
            "generation_id",
            "root_backup_id",
            "provider",
            "name",
            "completed_at",
            "generation",
        }
        or point["format"] != POINT_FORMAT
        or any(
            not canonical_id(point[name])
            for name in (
                "installation_id",
                "org_id",
                "backup_id",
                "generation_id",
                "root_backup_id",
            )
        )
        or (point["installation_id"], point["org_id"])
        != (trust["installation_id"], trust["org_id"])
        or point["provider"] not in {"libvirt", "kubevirt"}
        or type(point["name"]) is not str
        or not 1 <= len(point["name"]) <= 255
        or not point["completed_at"].endswith("Z")
        or datetime.fromisoformat(point["completed_at"]).utcoffset().total_seconds()
        != 0
    ):
        raise ValueError("Recovery point scope differs")
    location = point["generation"]
    if type(location) is not dict or set(location) != {
        "endpoint",
        "bucket",
        "region",
        "key",
        "version_id",
        "etag",
        "bytes",
        "sha256",
    }:
        raise ValueError("Generation location unavailable")
    address = urlsplit(location["endpoint"])
    key = (
        f"vnbui-owned/v1/{hashlib.sha256(point['org_id'].encode()).hexdigest()}/"
        f"{hashlib.sha256(point['root_backup_id'].encode()).hexdigest()}/"
        f"generations/{point['generation_id']}.json"
    )
    if (
        address.scheme != "https"
        or not address.hostname
        or address.username is not None
        or location["endpoint"] != "https://" + address.netloc
        or not re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]", location["bucket"])
        or not isinstance(location["region"], str)
        or (
            location["region"] != ""
            and not re.fullmatch(
                r"[A-Za-z0-9][A-Za-z0-9._-]{0,252}", location["region"]
            )
        )
        or location["key"] != key
        or (
            location["version_id"] is not None
            and (
                not isinstance(location["version_id"], str)
                or not 1 <= len(location["version_id"]) <= 1024
            )
        )
        or not re.fullmatch(r'"[^"\r\n]{1,1022}"', location["etag"])
        or type(location["bytes"]) is not int
        or not 1 <= location["bytes"] <= 16 * 1024 * 1024
        or not re.fullmatch(r"[0-9a-f]{64}", location["sha256"])
    ):
        raise ValueError("Generation location unavailable")


def verify_point_envelope(raw, trust):
    """Verify exact compact JWS bytes using independent public trust."""
    try:
        if type(raw) is not bytes or not 0 < len(raw) <= 65536:
            raise ValueError("Recovery envelope size unavailable")
        envelope = json.loads(raw, object_pairs_hook=_unique_object)
        if (
            type(envelope) is not dict
            or set(envelope) != {"format", "public_key", "jws"}
            or envelope["format"] != ENVELOPE_FORMAT
            or envelope["public_key"] != trust["public_key"]
            or trust.get("schema", TRUST_SCHEMA) != TRUST_SCHEMA
        ):
            raise ValueError("Independent recovery trust unavailable")
        public = _decode_base64url(trust["public_key"])
        verifier = Ed25519PublicKey.from_public_bytes(public)
        key_id = hashlib.sha256(public).hexdigest()
        protected, payload, signature = envelope["jws"].split(".")
        if trust.get("key_id", key_id) != key_id or json.loads(
            _decode_base64url(protected), object_pairs_hook=_unique_object
        ) != {"alg": "EdDSA", "kid": key_id, "typ": JWS_TYPE}:
            raise ValueError("Recovery signing identity differs")
        verifier.verify(
            _decode_base64url(signature), f"{protected}.{payload}".encode("ascii")
        )
        point = json.loads(_decode_base64url(payload), object_pairs_hook=_unique_object)
        _verified_point_shape(point, trust)
        return point
    except (AttributeError, KeyError, TypeError, ValueError, InvalidSignature):
        raise RecoveryUnavailable(
            "Signed recovery point could not be verified"
        ) from None
