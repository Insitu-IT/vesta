"""The public marker that binds a recovery signing seed to its installation."""

import base64
import hashlib
import json

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def base64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def public_identity(key):
    public = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return hashlib.sha256(public).hexdigest(), base64url(public)


def signer_identity(private, identifier):
    key_id, public_key = public_identity(private)
    return {
        "schema": "vesta-recovery-signer/1",
        "installation_id": identifier,
        "key_id": key_id,
        "public_key": public_key,
    }


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Repeated recovery field")
        result[key] = value
    return result


def verify_signing_seed(encoded, marker, installation_id):
    private = Ed25519PrivateKey.from_private_bytes(
        base64.b64decode(encoded, validate=True)
    )
    recorded = json.loads(marker, object_pairs_hook=unique_object)
    if recorded != signer_identity(private, installation_id):
        raise ValueError("Recovery signing identity differs")
    return private
