"""Select non-secret KEK identity under the source transaction's tenant locks.

DEK generation/wrapping and secure delivery belong to the admitted producer phase.
No key material is loaded here or included in a transaction envelope.
"""

import os
import re

from models import EncryptionKey
from core.s3_ownership import StorageOwnershipError

FORMAT = "vnbu1-aes256gcm-chunk5242880"


def select_encryption(db, backup, *, read_only=False):
    if os.getenv("ENABLE_ENCRYPTION", "false").lower() != "true":
        if backup.encryption_key_id is not None:
            raise StorageOwnershipError(
                "Recorded encryption selection cannot be disabled"
            )
        return dict(format="none", key_ref=None)
    # Select scalar identity fields only, not encrypted_material. Multiple active
    # keys are an ambiguity, never an ordering rule for choosing one of them.
    keys = (
        db.query(
            EncryptionKey.id,
            EncryptionKey.key_hash,
            EncryptionKey.algorithm,
            EncryptionKey.provider,
            EncryptionKey.provider_key_ref,
            EncryptionKey.encrypted_material.isnot(None).label("has_material"),
        )
        .filter(
            EncryptionKey.org_id == backup.org_id,
            EncryptionKey.status == "active",
        )
        .with_for_update()
        .limit(2)
        .all()
    )
    if len(keys) != 1:
        raise StorageOwnershipError(
            "Transaction encryption key selection is unavailable or ambiguous"
        )
    key = keys[0]
    if (
        key.algorithm != "aes-256-gcm"
        or key.provider != "local"
        or key.provider_key_ref is not None
        or not key.has_material
        or re.fullmatch(r"(?:[0-9a-f]{16}|[0-9a-f]{64})", key.key_hash or "") is None
    ):
        raise StorageOwnershipError("Unsupported transaction encryption key identity")
    if backup.encryption_key_id not in (None, key.id):
        raise StorageOwnershipError("Transaction encryption key selection changed")
    if read_only:
        if backup.encryption_key_id != key.id:
            raise StorageOwnershipError("Encryption identity was not committed")
    else:
        backup.encryption_key_id = key.id
    return dict(format=FORMAT, key_ref=f"kek:{key.id}:{key.key_hash}")
