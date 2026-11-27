"""Installation-key rotation preserves the recovery identity saved at a different site."""

import base64
import json
from unittest.mock import Mock
from uuid import uuid4

import pytest
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from core.installation_config import RECOVERY_SIGNING_SEED
from core.installation_key_rotation import RotationError, inspect_envelopes
from core.recovery_key_identity import signer_identity, verify_signing_seed


def custody():
    key = Ed25519PrivateKey.generate()
    raw = key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    installation = str(uuid4())
    return (
        key,
        base64.b64encode(raw),
        installation,
        json.dumps(signer_identity(key, installation)),
    )


def inventory(seed, marker):
    cursor = Mock()
    cursor.fetchall.side_effect = [
        [],
        [seed] if seed else [],
        [marker] if marker else [],
    ]
    cursor.fetchone.return_value = (True,)
    return cursor


def test_stored_signer_rewraps_without_replacing_public_trust():
    private, seed, installation, marker = custody()
    old, new = Fernet(Fernet.generate_key()), Fernet(Fernet.generate_key())
    secret = (
        RECOVERY_SIGNING_SEED,
        "(0,7)",
        old.encrypt(seed).decode(),
        "installation",
        None,
    )
    public = (marker, "json", "installation")
    state, counts, digest, updates = inspect_envelopes(
        inventory(secret, public), old, new, True, installation
    )
    assert state == "old" and counts == {"stored_secrets": 1, "local_keks": 0}
    pointer, token = updates["stored_secrets"][0].strip().split("\t")
    reopened = verify_signing_seed(new.decrypt(token.encode()), marker, installation)
    assert reopened.sign(b"point bytes") == private.sign(b"point bytes")
    retry = (RECOVERY_SIGNING_SEED, pointer, token, "installation", None)
    assert inspect_envelopes(
        inventory(retry, public), old, new, True, installation
    ) == (
        "new",
        counts,
        digest,
        {"stored_secrets": [], "local_keks": []},
    )


@pytest.mark.parametrize(
    "defect",
    [
        "missing_mark",
        "missing_seed",
        "wrong_key",
        "wrong_site",
        "source",
        "missing_both",
    ],
)
def test_damaged_signer_aborts_before_writing(defect):
    _, seed, installation, marker = custody()
    old, new = Fernet(Fernet.generate_key()), Fernet(Fernet.generate_key())
    secret = (
        None
        if defect in {"missing_seed", "missing_both"}
        else (
            RECOVERY_SIGNING_SEED,
            "(0,7)",
            old.encrypt(seed).decode(),
            "ui" if defect == "source" else "installation",
            None,
        )
    )
    if defect == "wrong_key":
        marker = custody()[3]
    public = (
        None
        if defect in {"missing_mark", "missing_both"}
        else (marker, "json", "installation")
    )
    with pytest.raises(RotationError):
        inspect_envelopes(
            inventory(secret, public),
            old,
            new,
            True,
            str(uuid4()) if defect == "wrong_site" else installation,
        )
