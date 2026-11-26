"""
Local KMS provider — KEKs stored in DB, encrypted with VESTA_ENCRYPTION_KEY (Fernet).

This is the default/OSS provider. Key material never leaves the database boundary.
For external KMS (Vault, AWS), key material stays in the external service.
"""

import base64
import hashlib
import json
import logging
import os
import uuid
from datetime import datetime
from typing import Optional, List
from sqlalchemy.exc import IntegrityError

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.keywrap import aes_key_wrap, aes_key_unwrap
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

from core.vesta_environment import vesta_encryption_key
from core.kms.base import KMSProvider, KeyMetadata
from database import SessionLocal

logger = logging.getLogger(__name__)


def _get_fernet() -> Fernet:
    """Get Fernet instance from VESTA_ENCRYPTION_KEY env var."""
    key = vesta_encryption_key()
    if not key:
        raise ValueError(
            "VESTA_ENCRYPTION_KEY not set — required for local KMS provider"
        )
    return Fernet(key.encode() if isinstance(key, str) else key)


def _derive_export_key(password: str, salt: bytes) -> bytes:
    """Derive a Fernet key from a user password via PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=600_000,
    )
    raw = kdf.derive(password.encode())
    return base64.urlsafe_b64encode(raw)


class StaleKeyRotation(ValueError):
    """A predecessor can acquire only one successor."""


class LocalKMSProvider(KMSProvider):
    """
    Local DB-backed KMS provider.

    KEK lifecycle:
    - create_key: generate random 256-bit key, encrypt with Fernet, store in DB
    - wrap_dek: decrypt KEK from DB, AES-wrap the DEK
    - unwrap_dek: decrypt KEK from DB, AES-unwrap the DEK
    - rotate_key: create new key, mark old as "rotated"
    - revoke_key: mark as "revoked" (cannot wrap/unwrap)
    """

    def __init__(self):
        self._fernet = _get_fernet()

    def _session(self):
        from core.tenant_context import identity

        _, _, platform = identity()
        if platform:
            raise ValueError("KMS operations require explicit tenant scope")
        return SessionLocal()

    def _encrypt_material(self, raw_key: bytes) -> str:
        """Encrypt raw key material with Fernet for DB storage."""
        return self._fernet.encrypt(raw_key).decode()

    def _decrypt_material(self, encrypted: str) -> bytes:
        """Decrypt key material from DB."""
        return self._fernet.decrypt(encrypted.encode())

    def _row_to_metadata(self, row) -> KeyMetadata:
        """Convert DB row to KeyMetadata."""
        return KeyMetadata(
            id=row.id,
            name=row.name,
            algorithm=row.algorithm,
            key_hash=row.key_hash,
            status=row.status,
            provider=row.provider,
            provider_key_ref=row.provider_key_ref,
            created_at=row.created_at,
            created_by=row.created_by,
            rotated_at=row.rotated_at,
            replaced_by_id=row.replaced_by_id,
            backed_up=row.backed_up,
            backed_up_at=row.backed_up_at,
            backed_up_locations=row.backed_up_locations or [],
        )

    def _lock_generation(self, db):
        from core.tenant_context import identity
        from models import Organization, OrganizationDefault

        org_id, _, platform = identity()
        if platform:
            raise ValueError("KMS operations require explicit tenant scope")
        if org_id in (None, "default"):
            assignment = db.get(OrganizationDefault, "oss")
            if assignment is None:
                raise ValueError("Organization assignment unavailable")
            org_id = assignment.org_id
        org = (
            db.query(Organization).filter_by(id=org_id).with_for_update().one_or_none()
        )
        if org is None or org.enabled is not True:
            raise ValueError("Active key organization unavailable")
        return org_id

    def create_key_flush(self, db, name, algorithm="aes-256-gcm", created_by=None):
        """Compose key material, predecessor transition and receipt in one commit."""
        from models import EncryptionKey

        org_id = self._lock_generation(db)
        if algorithm != "aes-256-gcm":
            raise ValueError("Unsupported key algorithm")
        active = (
            db.query(EncryptionKey)
            .filter_by(
                org_id=org_id,
                status="active",
                provider="local",
            )
            .with_for_update()
            .all()
        )
        raw_key = os.urandom(32)
        row = EncryptionKey(
            id=str(uuid.uuid4()),
            org_id=org_id,
            name=name,
            algorithm=algorithm,
            key_hash=hashlib.sha256(raw_key).hexdigest()[:16],
            encrypted_material=self._encrypt_material(raw_key),
            status="active",
            provider="local",
            created_by=created_by,
        )
        db.add(row)
        db.flush()
        for old in active:
            old.status = "rotated"
            old.rotated_at = datetime.utcnow()
            old.replaced_by_id = row.id
        db.flush()
        return self._row_to_metadata(row)

    def rotate_key_flush(self, db, old_key_id, new_name, created_by=None):
        from models import EncryptionKey

        org_id = self._lock_generation(db)
        old = (
            db.query(EncryptionKey)
            .filter_by(
                id=old_key_id,
                org_id=org_id,
                provider="local",
            )
            .with_for_update()
            .one_or_none()
        )
        if old is None:
            raise ValueError("Encryption key not found")
        if old.status != "active" or old.replaced_by_id is not None:
            raise StaleKeyRotation("Cannot rotate a revoked or already rotated key")
        return self.create_key_flush(db, new_name, old.algorithm, created_by)

    async def create_key(
        self,
        name: str,
        algorithm: str = "aes-256-gcm",
        created_by: Optional[str] = None,
    ) -> KeyMetadata:
        with self._session() as db:
            result = self.create_key_flush(db, name, algorithm, created_by)
            db.commit()
            return result

    async def get_key(self, key_id: str) -> KeyMetadata:
        from models import EncryptionKey

        db = self._session()
        try:
            row = db.query(EncryptionKey).filter(EncryptionKey.id == key_id).first()
            if not row:
                raise ValueError(f"Key {key_id} not found")
            return self._row_to_metadata(row)
        finally:
            db.close()

    async def list_keys(self) -> List[KeyMetadata]:
        from models import EncryptionKey

        db = self._session()
        try:
            rows = (
                db.query(EncryptionKey)
                .filter(EncryptionKey.provider == "local")
                .order_by(EncryptionKey.created_at.desc())
                .all()
            )
            return [self._row_to_metadata(r) for r in rows]
        finally:
            db.close()

    async def get_active_key(self) -> Optional[KeyMetadata]:
        from models import EncryptionKey

        db = self._session()
        try:
            row = (
                db.query(EncryptionKey)
                .filter(
                    EncryptionKey.status == "active", EncryptionKey.provider == "local"
                )
                .first()
            )
            return self._row_to_metadata(row) if row else None
        finally:
            db.close()

    async def rotate_key(
        self,
        old_key_id: str,
        new_name: str,
        created_by: Optional[str] = None,
    ) -> KeyMetadata:
        with self._session() as db:
            result = self.rotate_key_flush(db, old_key_id, new_name, created_by)
            db.commit()
            return result

    async def revoke_key(self, key_id: str) -> None:
        from models import EncryptionKey, Backup

        db = self._session()
        try:
            row = db.query(EncryptionKey).filter(EncryptionKey.id == key_id).first()
            if not row:
                raise ValueError(f"Key {key_id} not found")
            if row.status == "revoked":
                return

            # Check if any active backups still use this key
            backup_count = (
                db.query(Backup)
                .filter(
                    Backup.encryption_key_id == key_id,
                    Backup.status.in_(["completed", "running", "pending"]),
                )
                .count()
            )
            if backup_count > 0:
                raise ValueError(
                    f"Cannot revoke key: {backup_count} backup(s) still reference it. "
                    "Re-encrypt those backups with a new key first."
                )

            row.status = "revoked"
            db.commit()
            logger.info(f"Revoked KEK {key_id}")
        finally:
            db.close()

    async def wrap_dek(self, dek: bytes, kek_id: str) -> bytes:
        from models import EncryptionKey

        if len(dek) != 32:
            raise ValueError("DEK must be 32 bytes (AES-256)")

        db = self._session()
        try:
            row = db.query(EncryptionKey).filter(EncryptionKey.id == kek_id).first()
            if not row:
                raise ValueError(f"KEK {kek_id} not found")
            if row.status == "revoked":
                raise ValueError(f"KEK {kek_id} is revoked")

            raw_kek = self._decrypt_material(row.encrypted_material)
            wrapped = aes_key_wrap(raw_kek, dek)
            return wrapped
        finally:
            db.close()

    async def unwrap_dek(self, wrapped_dek: bytes, kek_id: str) -> bytes:
        from models import EncryptionKey

        db = self._session()
        try:
            row = db.query(EncryptionKey).filter(EncryptionKey.id == kek_id).first()
            if not row:
                raise ValueError(f"KEK {kek_id} not found")
            if row.status == "revoked":
                raise ValueError(f"KEK {kek_id} is revoked — cannot unwrap DEK")

            raw_kek = self._decrypt_material(row.encrypted_material)
            dek = aes_key_unwrap(raw_kek, wrapped_dek)
            return dek
        finally:
            db.close()

    async def export_keys(self, key_ids: List[str], password: str) -> bytes:
        from models import EncryptionKey

        if not password or len(password) < 8:
            raise ValueError("Export password must be at least 8 characters")

        db = self._session()
        try:
            rows = (
                db.query(EncryptionKey)
                .filter(
                    EncryptionKey.id.in_(key_ids), EncryptionKey.provider == "local"
                )
                .all()
            )

            if not rows:
                raise ValueError("No keys found to export")
            if {row.id for row in rows} != set(key_ids):
                raise ValueError(
                    "One or more requested keys are unavailable in this organization"
                )

            keys_data = []
            for row in rows:
                raw = self._decrypt_material(row.encrypted_material)
                keys_data.append(
                    {
                        "id": row.id,
                        "name": row.name,
                        "algorithm": row.algorithm,
                        "key_material": base64.b64encode(raw).decode(),
                        "key_hash": row.key_hash,
                        "created_at": row.created_at.isoformat(),
                    }
                )

            payload = json.dumps(
                {
                    "version": 1,
                    "format": "vnbui-key-export",
                    "exported_at": datetime.utcnow().isoformat(),
                    "keys": keys_data,
                }
            ).encode()

            # Encrypt with password-derived key
            salt = os.urandom(16)
            fernet_key = _derive_export_key(password, salt)
            f = Fernet(fernet_key)
            encrypted = f.encrypt(payload)

            # Prepend salt for decryption
            result = salt + encrypted
        finally:
            db.close()

        return result

    async def confirm_export_custody(
        self, data: bytes, password: str, location: str
    ) -> List[str]:
        """Attest possession of a saved, decryptable export for current keys.

        The administrator supplies the file again after storing it. This proves
        possession and exact key contents, while the named external location is
        an audited operator attestation, not a server-observed durability fact.
        """
        from models import EncryptionKey

        location = location.strip()
        if not location or len(location) > 128:
            raise ValueError("Custody location must contain 1 to 128 characters")
        if len(password) < 8 or len(data) < 17 or len(data) > 4 * 1024 * 1024:
            raise ValueError("Invalid export file or password")
        try:
            payload = Fernet(_derive_export_key(password, data[:16])).decrypt(data[16:])
            archive = json.loads(payload.decode())
        except (InvalidToken, UnicodeError, ValueError, TypeError):
            raise ValueError("Invalid password or corrupted export file") from None
        if (
            not isinstance(archive, dict)
            or archive.get("format") != "vnbui-key-export"
            or archive.get("version") != 1
        ):
            raise ValueError("Unsupported key export format")
        entries = archive.get("keys")
        if not isinstance(entries, list) or not entries:
            raise ValueError("Export contains no keys")
        ids = [entry.get("id") for entry in entries if isinstance(entry, dict)]
        if (
            len(ids) != len(entries)
            or any(not isinstance(key_id, str) or not key_id for key_id in ids)
            or len(set(ids)) != len(ids)
        ):
            raise ValueError("Export contains invalid or duplicate key identities")

        db = self._session()
        try:
            rows = (
                db.query(EncryptionKey)
                .filter(EncryptionKey.id.in_(ids), EncryptionKey.provider == "local")
                .with_for_update()
                .all()
            )
            by_id = {row.id: row for row in rows}
            if set(by_id) != set(ids):
                raise ValueError("Export keys are unavailable in this organization")
            for entry in entries:
                row = by_id[entry["id"]]
                try:
                    raw = base64.b64decode(entry["key_material"], validate=True)
                except (KeyError, TypeError, ValueError):
                    raise ValueError("Export contains invalid key material") from None
                if row.key_hash != entry.get(
                    "key_hash"
                ) or raw != self._decrypt_material(row.encrypted_material):
                    raise ValueError(
                        "Export key does not match the current key identity"
                    )

            receipt = (
                "verified-file:" + hashlib.sha256(data).hexdigest() + ":" + location
            )
            now = datetime.utcnow()
            for row in rows:
                locations = [
                    value
                    for value in (row.backed_up_locations or [])
                    if value != "file-export"
                ]
                if receipt not in locations:
                    locations.append(receipt)
                    row.backed_up_at = now
                row.backed_up_locations = locations
                row.backed_up = True
            db.commit()
            return ids
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    async def import_keys(self, data: bytes, password: str) -> List[str]:
        from models import EncryptionKey

        if len(data) < 17:
            raise ValueError("Invalid export data")

        # Extract salt and decrypt
        salt = data[:16]
        encrypted = data[16:]
        fernet_key = _derive_export_key(password, salt)
        f = Fernet(fernet_key)

        try:
            payload = f.decrypt(encrypted)
        except InvalidToken:
            raise ValueError("Invalid password or corrupted export file")

        export_data = json.loads(payload.decode())
        if export_data.get("format") != "vnbui-key-export":
            raise ValueError("Invalid export format")

        imported_ids = []
        db = self._session()
        try:
            for key_entry in export_data.get("keys", []):
                raw_material = base64.b64decode(key_entry["key_material"])
                computed_hash = hashlib.sha256(raw_material).hexdigest()[:16]

                if computed_hash != key_entry["key_hash"]:
                    logger.warning(f"Hash mismatch for key {key_entry['id']}, skipping")
                    continue

                # Skip duplicates
                existing = (
                    db.query(EncryptionKey)
                    .filter(EncryptionKey.key_hash == key_entry["key_hash"])
                    .first()
                )
                if existing:
                    logger.info(
                        f"Key {key_entry['id']} already exists (hash={key_entry['key_hash']}), skipping"
                    )
                    imported_ids.append(existing.id)
                    continue

                encrypted_material = self._encrypt_material(raw_material)
                row = EncryptionKey(
                    id=key_entry["id"],
                    name=key_entry["name"],
                    algorithm=key_entry.get("algorithm", "aes-256-gcm"),
                    key_hash=key_entry["key_hash"],
                    encrypted_material=encrypted_material,
                    status="rotated",  # Imported keys are not active by default
                    provider="local",
                    # Import proves the file was presented once, not that a
                    # recoverable copy remains outside this installation.
                    backed_up=False,
                    backed_up_locations=[],
                )
                db.add(row)
                imported_ids.append(row.id)

            db.commit()
            logger.info(f"Imported {len(imported_ids)} key(s)")
            return imported_ids
        except IntegrityError:
            db.rollback()
            raise ValueError("Key import conflicts with an existing identity") from None
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    @property
    def supports_export(self) -> bool:
        return True

    async def mark_backed_up(self, key_id: str, location: str) -> None:
        from models import EncryptionKey

        db = self._session()
        try:
            row = db.query(EncryptionKey).filter(EncryptionKey.id == key_id).first()
            if not row:
                raise ValueError(f"Key {key_id} not found")

            row.backed_up = True
            row.backed_up_at = datetime.utcnow()
            locations = list(row.backed_up_locations or [])
            if location not in locations:
                locations.append(location)
            row.backed_up_locations = locations
            db.commit()
        finally:
            db.close()

    async def get_backup_count(self, key_id: str) -> int:
        from models import Backup

        db = self._session()
        try:
            return db.query(Backup).filter(Backup.encryption_key_id == key_id).count()
        finally:
            db.close()
