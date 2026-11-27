"""
Full-cycle tests for KMS encryption key management.

Tests every flow without needing a real backup agent:
1. KMS provider interface + local provider
2. Key lifecycle: create → rotate → revoke
3. Envelope encryption: wrap/unwrap DEK
4. Key export/import round-trip
5. Legacy fallback paths
6. API router endpoints
7. Backup/restore executor encryption logic
"""

import base64
import hashlib
import io
import json
import os
import unicodedata
import uuid
from types import SimpleNamespace

import pytest
from fastapi import HTTPException, UploadFile
from sqlalchemy.orm import sessionmaker

NEW_EXPORT_PASSPHRASE = "r5Mq12Jd8B-XwTn6cYaP2_zL97vF"

# Fixtures (db_engine, session_factory, db_session, patch_session_local,
# set_encryption_env, _clean_db) provided by conftest.py


@pytest.fixture
def kms_provider(patch_session_local, db_session, monkeypatch):
    """Create a LocalKMSProvider using the test DB."""
    from core.kms.registry import reset_provider

    reset_provider()
    from core.kms.local import LocalKMSProvider

    from models import StorageConfigurationClock

    provider = LocalKMSProvider()
    monkeypatch.setattr("core.settings_service._fernet", provider._fernet)
    db_session.add(
        StorageConfigurationClock(slot=1, installation_id=str(uuid.uuid4()), revision=1)
    )
    db_session.commit()
    return provider


# ═══════════════════════════════════════════════════════════════════════════════
# 1. LOCAL KMS PROVIDER — KEY LIFECYCLE
# ═══════════════════════════════════════════════════════════════════════════════


class TestKeyLifecycle:
    """Test create → list → get → rotate → revoke."""

    @pytest.mark.asyncio
    async def test_create_key(self, kms_provider):
        key = await kms_provider.create_key("test-key-1", created_by=None)
        assert key.name == "test-key-1"
        assert key.algorithm == "aes-256-gcm"
        assert key.status == "active"
        assert key.provider == "local"
        assert len(key.key_hash) == 16
        assert key.id is not None
        assert key.backed_up is False

    @pytest.mark.asyncio
    async def test_create_key_deactivates_previous(self, kms_provider):
        key1 = await kms_provider.create_key("key-1")
        assert key1.status == "active"

        key2 = await kms_provider.create_key("key-2")
        assert key2.status == "active"

        # key1 should now be rotated
        key1_refreshed = await kms_provider.get_key(key1.id)
        assert key1_refreshed.status == "rotated"
        assert key1_refreshed.replaced_by_id == key2.id

    @pytest.mark.asyncio
    async def test_get_active_key(self, kms_provider):
        # No keys → None
        active = await kms_provider.get_active_key()
        assert active is None

        key = await kms_provider.create_key("active-key")
        active = await kms_provider.get_active_key()
        assert active is not None
        assert active.id == key.id

    @pytest.mark.asyncio
    async def test_list_keys(self, kms_provider):
        await kms_provider.create_key("k1")
        await kms_provider.create_key("k2")
        await kms_provider.create_key("k3")

        keys = await kms_provider.list_keys()
        assert len(keys) == 3
        # Most recent first
        assert keys[0].name == "k3"
        assert keys[0].status == "active"
        assert keys[1].status == "rotated"
        assert keys[2].status == "rotated"

    @pytest.mark.asyncio
    async def test_get_key_not_found(self, kms_provider):
        with pytest.raises(ValueError, match="not found"):
            await kms_provider.get_key("nonexistent-id")

    @pytest.mark.asyncio
    async def test_rotate_key(self, kms_provider):
        original = await kms_provider.create_key("original")
        rotated_to = await kms_provider.rotate_key(original.id, "rotated-key")

        assert rotated_to.status == "active"
        assert rotated_to.name == "rotated-key"

        # Original should be rotated
        orig_refreshed = await kms_provider.get_key(original.id)
        assert orig_refreshed.status == "rotated"

    @pytest.mark.asyncio
    async def test_rotate_nonexistent_key(self, kms_provider):
        with pytest.raises(ValueError, match="not found"):
            await kms_provider.rotate_key("nonexistent", "new")

    @pytest.mark.asyncio
    async def test_rotate_revoked_key(self, kms_provider):
        key = await kms_provider.create_key("to-revoke")
        await kms_provider.revoke_key(key.id)
        with pytest.raises(ValueError, match="Cannot rotate a revoked"):
            await kms_provider.rotate_key(key.id, "new")

    @pytest.mark.asyncio
    async def test_revoke_key(self, kms_provider):
        key = await kms_provider.create_key("to-revoke")
        await kms_provider.revoke_key(key.id)
        revoked = await kms_provider.get_key(key.id)
        assert revoked.status == "revoked"

    @pytest.mark.asyncio
    async def test_revoke_already_revoked_is_noop(self, kms_provider):
        key = await kms_provider.create_key("to-revoke")
        await kms_provider.revoke_key(key.id)
        await kms_provider.revoke_key(key.id)  # Should not raise

    @pytest.mark.asyncio
    async def test_revoke_key_with_backups_fails(self, kms_provider, db_session):
        """Cannot revoke a key that has backups referencing it."""
        from models import Backup, VM, Agent

        key = await kms_provider.create_key("has-backups")

        # Create minimal agent → vm → backup chain
        agent = Agent(id=str(uuid.uuid4()), hostname="test-agent", status="online")
        db_session.add(agent)
        db_session.commit()

        vm = VM(id=str(uuid.uuid4()), name="test-vm", agent_id=agent.id)
        db_session.add(vm)
        db_session.commit()

        backup = Backup(
            id=str(uuid.uuid4()),
            vm_id=vm.id,
            status="completed",
            encryption_key_id=key.id,
        )
        db_session.add(backup)
        db_session.commit()

        with pytest.raises(ValueError, match="backup.*still reference"):
            await kms_provider.revoke_key(key.id)


# ═══════════════════════════════════════════════════════════════════════════════
# 2. ENVELOPE ENCRYPTION — WRAP / UNWRAP DEK
# ═══════════════════════════════════════════════════════════════════════════════


class TestEnvelopeEncryption:
    """Test DEK wrap/unwrap round-trip."""

    @pytest.mark.asyncio
    async def test_wrap_unwrap_roundtrip(self, kms_provider):
        key = await kms_provider.create_key("wrap-test")
        dek = os.urandom(32)

        wrapped = await kms_provider.wrap_dek(dek, key.id)
        assert wrapped != dek  # Must be different
        assert len(wrapped) > 0

        unwrapped = await kms_provider.unwrap_dek(wrapped, key.id)
        assert unwrapped == dek

    @pytest.mark.asyncio
    async def test_wrap_with_wrong_key_fails_unwrap(self, kms_provider):
        """Wrapping with key A, unwrapping with key B should fail."""
        key_a = await kms_provider.create_key("key-a")
        key_b = await kms_provider.create_key("key-b")

        dek = os.urandom(32)
        wrapped = await kms_provider.wrap_dek(dek, key_a.id)

        with pytest.raises(Exception):  # InvalidUnwrap or similar
            await kms_provider.unwrap_dek(wrapped, key_b.id)

    @pytest.mark.asyncio
    async def test_wrap_dek_wrong_size(self, kms_provider):
        key = await kms_provider.create_key("size-test")
        with pytest.raises(ValueError, match="32 bytes"):
            await kms_provider.wrap_dek(os.urandom(16), key.id)

    @pytest.mark.asyncio
    async def test_wrap_with_revoked_key_fails(self, kms_provider):
        key = await kms_provider.create_key("revoke-test")
        await kms_provider.revoke_key(key.id)

        with pytest.raises(ValueError, match="revoked"):
            await kms_provider.wrap_dek(os.urandom(32), key.id)

    @pytest.mark.asyncio
    async def test_unwrap_with_revoked_key_fails(self, kms_provider):
        key = await kms_provider.create_key("revoke-unwrap")
        dek = os.urandom(32)
        wrapped = await kms_provider.wrap_dek(dek, key.id)

        await kms_provider.revoke_key(key.id)
        with pytest.raises(ValueError, match="revoked"):
            await kms_provider.unwrap_dek(wrapped, key.id)

    @pytest.mark.asyncio
    async def test_wrap_with_nonexistent_key_fails(self, kms_provider):
        with pytest.raises(ValueError, match="not found"):
            await kms_provider.wrap_dek(os.urandom(32), "no-such-key")

    @pytest.mark.asyncio
    async def test_rotated_key_still_unwraps(self, kms_provider):
        """After rotation, old key can still unwrap existing DEKs."""
        old_key = await kms_provider.create_key("old")
        dek = os.urandom(32)
        wrapped = await kms_provider.wrap_dek(dek, old_key.id)

        # Rotate
        _new_key = await kms_provider.create_key("new")  # noqa: F841
        old_refreshed = await kms_provider.get_key(old_key.id)
        assert old_refreshed.status == "rotated"

        # Old key can still unwrap
        unwrapped = await kms_provider.unwrap_dek(wrapped, old_key.id)
        assert unwrapped == dek


# ═══════════════════════════════════════════════════════════════════════════════
# 3. KEY EXPORT / IMPORT ROUND-TRIP
# ═══════════════════════════════════════════════════════════════════════════════


class TestExportImport:
    """Test export → wipe → import → unwrap still works."""

    @pytest.mark.asyncio
    async def test_export_import_roundtrip(self, kms_provider):
        key = await kms_provider.create_key("exportable")
        dek = os.urandom(32)
        _wrapped = await kms_provider.wrap_dek(dek, key.id)  # noqa: F841

        # Export
        export_data = await kms_provider.export_keys([key.id], NEW_EXPORT_PASSPHRASE)
        assert len(export_data) > 16  # salt + encrypted payload

        from cryptography.fernet import Fernet
        from core.kms.local import _derive_export_key

        archive = json.loads(
            Fernet(_derive_export_key(NEW_EXPORT_PASSPHRASE, export_data[:16])).decrypt(
                export_data[16:]
            )
        )
        trust = archive["recovery_trust"]
        assert trust["schema"] == "vesta-recovery-trust/1"
        assert len(trust["public_key"]) == 43
        assert len(trust["key_id"]) == 64

        # Generating bytes cannot prove that the caller saved them.
        key_refreshed = await kms_provider.get_key(key.id)
        assert key_refreshed.backed_up is False
        assert key_refreshed.backed_up_locations == []

        confirmed = await kms_provider.confirm_export_custody(
            export_data, NEW_EXPORT_PASSPHRASE, "offline-test-vault"
        )
        assert confirmed == [key.id]
        key_refreshed = await kms_provider.get_key(key.id)
        assert key_refreshed.backed_up is True
        assert len(key_refreshed.backed_up_locations) == 1
        assert key_refreshed.backed_up_locations[0].startswith("verified-file:")
        assert key_refreshed.backed_up_locations[0].endswith(":offline-test-vault")

        # Repeating the same confirmation must not append a second receipt.
        assert await kms_provider.confirm_export_custody(
            export_data, NEW_EXPORT_PASSPHRASE, "offline-test-vault"
        ) == [key.id]
        assert len((await kms_provider.get_key(key.id)).backed_up_locations) == 1

    @pytest.mark.asyncio
    async def test_export_custody_rejects_wrong_file_or_password(self, kms_provider):
        first = await kms_provider.create_key("first")
        exported = await kms_provider.export_keys([first.id], NEW_EXPORT_PASSPHRASE)
        # Mutate authenticated bytes, not a base64 character that might already
        # be "x" or change only unused padding bits.
        corrupted_token = bytearray(base64.urlsafe_b64decode(exported[16:]))
        corrupted_token[-1] ^= 1
        corrupted = exported[:16] + base64.urlsafe_b64encode(corrupted_token)
        assert corrupted != exported
        for data, password, location in (
            (exported, "wrong-pass-123", "offline-test-vault"),
            (corrupted, NEW_EXPORT_PASSPHRASE, "offline-test-vault"),
            (exported, NEW_EXPORT_PASSPHRASE, "  "),
        ):
            with pytest.raises(ValueError):
                await kms_provider.confirm_export_custody(data, password, location)
        assert (await kms_provider.get_key(first.id)).backed_up is False

    @pytest.mark.asyncio
    async def test_export_custody_rejects_changed_key_identity(self, kms_provider):
        first = await kms_provider.create_key("first")
        exported = await kms_provider.export_keys([first.id], NEW_EXPORT_PASSPHRASE)
        from models import EncryptionKey

        db = kms_provider._session()
        try:
            row = db.query(EncryptionKey).filter(EncryptionKey.id == first.id).one()
            row.encrypted_material = kms_provider._encrypt_material(os.urandom(32))
            db.commit()
        finally:
            db.close()
        with pytest.raises(ValueError, match="does not match"):
            await kms_provider.confirm_export_custody(
                exported, NEW_EXPORT_PASSPHRASE, "offline-test-vault"
            )
        assert (await kms_provider.get_key(first.id)).backed_up is False

    @pytest.mark.asyncio
    async def test_confirm_export_route_requires_admin_and_a_valid_file(
        self, kms_provider, monkeypatch
    ):
        from routers import encryption

        key = await kms_provider.create_key("route-key")
        data = await kms_provider.export_keys([key.id], NEW_EXPORT_PASSPHRASE)
        events = []
        monkeypatch.setattr(encryption, "get_kms_provider", lambda: kms_provider)
        monkeypatch.setattr(
            encryption, "log_activity", lambda *args, **kwargs: events.append(args)
        )
        reader = SimpleNamespace(id="reader", role="viewer")
        admin = SimpleNamespace(id="admin", role="admin")

        with pytest.raises(HTTPException) as denied:
            await encryption.confirm_export_custody(
                file=UploadFile(file=io.BytesIO(data), filename="keys.bin"),
                password=NEW_EXPORT_PASSPHRASE,
                location="external-vault",
                current_user=reader,
                db=None,
            )
        assert denied.value.status_code == 403
        assert (await kms_provider.get_key(key.id)).backed_up is False

        with pytest.raises(HTTPException) as invalid:
            await encryption.confirm_export_custody(
                file=UploadFile(file=io.BytesIO(data), filename="keys.bin"),
                password="bad-password",
                location="external-vault",
                current_user=admin,
                db=None,
            )
        assert invalid.value.status_code == 400
        assert (await kms_provider.get_key(key.id)).backed_up is False

        result = await encryption.confirm_export_custody(
            file=UploadFile(file=io.BytesIO(data), filename="keys.bin"),
            password=NEW_EXPORT_PASSPHRASE,
            location="external-vault",
            current_user=admin,
            db=None,
        )
        assert result == {
            "key_ids": [key.id],
            "sha256": hashlib.sha256(data).hexdigest(),
            "location": "external-vault",
        }
        assert events and events[0][2] == "encryption_export_custody_confirmed"
        assert (await kms_provider.get_key(key.id)).backed_up is True

    @pytest.mark.asyncio
    async def test_export_import_restores_keys(self, kms_provider, db_engine):
        """Full cycle: create key, export, nuke DB, reimport, unwrap works."""
        key = await kms_provider.create_key("full-cycle")
        dek = os.urandom(32)
        wrapped = await kms_provider.wrap_dek(dek, key.id)

        # Export
        password = NEW_EXPORT_PASSPHRASE
        export_data = await kms_provider.export_keys([key.id], password)

        # "Nuke" — delete the key from DB
        from models import EncryptionKey

        Session = sessionmaker(bind=db_engine)
        s = Session()
        s.query(EncryptionKey).filter(EncryptionKey.id == key.id).delete()
        s.commit()
        s.close()

        # Verify key is gone
        with pytest.raises(ValueError, match="not found"):
            await kms_provider.get_key(key.id)

        # Import
        imported_ids = await kms_provider.import_keys(export_data, password)
        assert key.id in imported_ids
        assert (await kms_provider.get_key(key.id)).backed_up is False

        # Unwrap with reimported key
        unwrapped = await kms_provider.unwrap_dek(wrapped, key.id)
        assert unwrapped == dek

    @pytest.mark.asyncio
    async def test_legacy_eight_character_export_can_be_confirmed_and_imported(
        self, kms_provider
    ):
        from cryptography.fernet import Fernet
        from models import EncryptionKey

        key = await kms_provider.create_key("legacy")
        with kms_provider._session() as db:
            row = db.get(EncryptionKey, key.id)
            raw = kms_provider._decrypt_material(row.encrypted_material)
        passphrase = "legacy80"
        salt = bytes(range(16))
        kdf_key = hashlib.pbkdf2_hmac("sha256", passphrase.encode(), salt, 600_000)
        payload = {
            "version": 1,
            "format": "vnbui-key-export",
            "keys": [
                {
                    "id": key.id,
                    "name": key.name,
                    "algorithm": key.algorithm,
                    "key_material": base64.b64encode(raw).decode(),
                    "key_hash": key.key_hash,
                }
            ],
        }
        archived = salt + Fernet(base64.urlsafe_b64encode(kdf_key)).encrypt(
            json.dumps(payload).encode()
        )

        assert await kms_provider.confirm_export_custody(
            archived, passphrase, "offline-vault"
        ) == [key.id]
        with kms_provider._session() as db:
            db.delete(db.get(EncryptionKey, key.id))
            db.commit()
        assert await kms_provider.import_keys(archived, passphrase) == [key.id]

    @pytest.mark.asyncio
    async def test_new_export_uses_original_unicode_passphrase_bytes(
        self, kms_provider
    ):
        key = await kms_provider.create_key("unicode-export")
        passphrase = "  ﬃﬄ①②③㍿ⅫⅦΑΒΓΔ中文  "
        normalized = unicodedata.normalize("NFKC", passphrase)
        assert normalized != passphrase

        archive = await kms_provider.export_keys([key.id], passphrase)
        with pytest.raises(ValueError, match="Invalid password"):
            await kms_provider.import_keys(archive, normalized)
        assert await kms_provider.import_keys(archive, passphrase) == [key.id]

    @pytest.mark.asyncio
    async def test_export_wrong_password_fails_import(self, kms_provider):
        key = await kms_provider.create_key("password-test")
        export_data = await kms_provider.export_keys([key.id], NEW_EXPORT_PASSPHRASE)

        with pytest.raises(ValueError, match="Invalid password"):
            await kms_provider.import_keys(export_data, "wrong-password")

    @pytest.mark.asyncio
    async def test_export_short_password_fails(self, kms_provider):
        key = await kms_provider.create_key("short-pw")
        with pytest.raises(ValueError, match="at least 20"):
            await kms_provider.export_keys([key.id], "short")

    @pytest.mark.asyncio
    async def test_import_skips_duplicates(self, kms_provider):
        key = await kms_provider.create_key("dup-test")
        export_data = await kms_provider.export_keys([key.id], NEW_EXPORT_PASSPHRASE)

        # Import again — should skip (key still exists)
        imported_ids = await kms_provider.import_keys(
            export_data, NEW_EXPORT_PASSPHRASE
        )
        assert len(imported_ids) == 1

        # Should still be only 1 key with this hash
        keys = await kms_provider.list_keys()
        hashes = [k.key_hash for k in keys]
        assert hashes.count(key.key_hash) == 1

    @pytest.mark.asyncio
    async def test_import_corrupt_data(self, kms_provider):
        with pytest.raises(ValueError):
            await kms_provider.import_keys(b"corrupt data here", NEW_EXPORT_PASSPHRASE)

    @pytest.mark.asyncio
    async def test_export_no_keys_fails(self, kms_provider):
        with pytest.raises(ValueError, match="No keys found"):
            await kms_provider.export_keys(["nonexistent-id"], NEW_EXPORT_PASSPHRASE)

    @pytest.mark.asyncio
    async def test_supports_export(self, kms_provider):
        assert kms_provider.supports_export is True


# ═══════════════════════════════════════════════════════════════════════════════
# 4. BACKUP COUNT + MARK BACKED UP
# ═══════════════════════════════════════════════════════════════════════════════


class TestBackupCountAndMarkup:
    @pytest.mark.asyncio
    async def test_backup_count_zero(self, kms_provider):
        key = await kms_provider.create_key("count-test")
        count = await kms_provider.get_backup_count(key.id)
        assert count == 0

    @pytest.mark.asyncio
    async def test_backup_count_with_backups(self, kms_provider, db_session):
        from models import Backup, VM, Agent

        key = await kms_provider.create_key("counted")

        agent = Agent(id=str(uuid.uuid4()), hostname="a1", status="online")
        db_session.add(agent)
        db_session.commit()

        vm = VM(id=str(uuid.uuid4()), name="v1", agent_id=agent.id)
        db_session.add(vm)
        db_session.commit()

        for _ in range(3):
            b = Backup(
                id=str(uuid.uuid4()),
                vm_id=vm.id,
                status="completed",
                encryption_key_id=key.id,
            )
            db_session.add(b)
        db_session.commit()

        count = await kms_provider.get_backup_count(key.id)
        assert count == 3

    @pytest.mark.asyncio
    async def test_mark_backed_up(self, kms_provider):
        key = await kms_provider.create_key("backup-mark")
        assert key.backed_up is False

        await kms_provider.mark_backed_up(key.id, "vault")
        refreshed = await kms_provider.get_key(key.id)
        assert refreshed.backed_up is True
        assert "vault" in refreshed.backed_up_locations

    @pytest.mark.asyncio
    async def test_mark_backed_up_multiple_locations(self, kms_provider):
        key = await kms_provider.create_key("multi-loc")
        await kms_provider.mark_backed_up(key.id, "s3")
        await kms_provider.mark_backed_up(key.id, "vault")
        await kms_provider.mark_backed_up(
            key.id, "s3"
        )  # Duplicate — should not add again

        refreshed = await kms_provider.get_key(key.id)
        assert refreshed.backed_up_locations == ["s3", "vault"]


# ═══════════════════════════════════════════════════════════════════════════════
# 5. REGISTRY
# ═══════════════════════════════════════════════════════════════════════════════


class TestRegistry:
    def test_get_kms_provider_returns_local(self, patch_session_local):
        from core.kms.registry import get_kms_provider, reset_provider
        from core.kms.local import LocalKMSProvider

        reset_provider()
        provider = get_kms_provider()
        assert isinstance(provider, LocalKMSProvider)

    def test_get_kms_provider_caches(self, patch_session_local):
        from core.kms.registry import get_kms_provider, reset_provider

        reset_provider()
        p1 = get_kms_provider()
        p2 = get_kms_provider()
        assert p1 is p2

    def test_reset_provider(self, patch_session_local):
        from core.kms.registry import get_kms_provider, reset_provider

        reset_provider()
        p1 = get_kms_provider()
        reset_provider()
        p2 = get_kms_provider()
        assert p1 is not p2


# ═══════════════════════════════════════════════════════════════════════════════
# 6. MODEL FIELDS
# ═══════════════════════════════════════════════════════════════════════════════


class TestModels:
    def test_encryption_key_model(self, db_session):
        from models import EncryptionKey

        key = EncryptionKey(
            id=str(uuid.uuid4()),
            name="model-test",
            algorithm="aes-256-gcm",
            key_hash="abc123",
            encrypted_material="fernet-encrypted-blob",
            status="active",
            provider="local",
        )
        db_session.add(key)
        db_session.commit()

        fetched = (
            db_session.query(EncryptionKey).filter(EncryptionKey.id == key.id).first()
        )
        assert fetched.name == "model-test"
        assert fetched.status == "active"
        assert fetched.backed_up is False

    def test_backup_encryption_fields(self, db_session):
        from models import Backup, VM, Agent, EncryptionKey

        agent = Agent(id=str(uuid.uuid4()), hostname="a1", status="online")
        db_session.add(agent)
        db_session.commit()

        vm = VM(id=str(uuid.uuid4()), name="v1", agent_id=agent.id)
        db_session.add(vm)
        db_session.commit()

        key = EncryptionKey(
            id=str(uuid.uuid4()),
            name="bk",
            key_hash="abc",
            encrypted_material="x",
            status="active",
            provider="local",
        )
        db_session.add(key)
        db_session.commit()

        backup = Backup(
            id=str(uuid.uuid4()),
            vm_id=vm.id,
            status="completed",
            encryption_key_id=key.id,
            wrapped_dek=base64.b64encode(b"wrapped-data").decode(),
        )
        db_session.add(backup)
        db_session.commit()

        fetched = db_session.query(Backup).filter(Backup.id == backup.id).first()
        assert fetched.encryption_key_id == key.id
        assert fetched.wrapped_dek == base64.b64encode(b"wrapped-data").decode()

    def test_backup_encryption_fields_nullable(self, db_session):
        """Pre-KMS backups have NULL encryption fields."""
        from models import Backup, VM, Agent

        agent = Agent(id=str(uuid.uuid4()), hostname="a2", status="online")
        db_session.add(agent)
        db_session.commit()

        vm = VM(id=str(uuid.uuid4()), name="v2", agent_id=agent.id)
        db_session.add(vm)
        db_session.commit()

        backup = Backup(id=str(uuid.uuid4()), vm_id=vm.id, status="completed")
        db_session.add(backup)
        db_session.commit()

        fetched = db_session.query(Backup).filter(Backup.id == backup.id).first()
        assert fetched.encryption_key_id is None
        assert fetched.wrapped_dek is None


# ═══════════════════════════════════════════════════════════════════════════════
# 7. BACKUP EXECUTOR — ENVELOPE ENCRYPTION PATH
# ═══════════════════════════════════════════════════════════════════════════════


class TestBackupExecutorEncryption:
    """Test that backup executor correctly uses KMS envelope encryption."""

    @pytest.mark.asyncio
    async def test_envelope_encryption_sets_fields(
        self, kms_provider, db_session, monkeypatch
    ):
        """When ENABLE_ENCRYPTION=true and KMS has active key, backup should use envelope encryption."""
        from models import Backup, VM, Agent

        monkeypatch.setenv("ENABLE_ENCRYPTION", "true")

        # Create active key
        active_key = await kms_provider.create_key("backup-test-key")

        # Create test data
        agent = Agent(
            id=str(uuid.uuid4()),
            hostname="test-host",
            status="online",
            ip_address="127.0.0.1",
            port=8090,
        )
        db_session.add(agent)
        db_session.commit()

        vm = VM(id=str(uuid.uuid4()), name="test-vm", agent_id=agent.id)
        db_session.add(vm)
        db_session.commit()

        backup = Backup(
            id=str(uuid.uuid4()),
            vm_id=vm.id,
            status="pending",
            backup_type="full",
            storage_path=f"file:///tmp/test/{str(uuid.uuid4())}",
            tags={},
        )
        db_session.add(backup)
        db_session.commit()

        # Simulate the encryption section of execute_backup
        # (extracting the logic to test without full agent communication)
        from core.kms import get_kms_provider

        kms = get_kms_provider()
        active = await kms.get_active_key()

        assert active is not None
        assert active.id == active_key.id

        dek = os.urandom(32)
        wrapped_dek = await kms.wrap_dek(dek, active.id)

        # Set fields like backup_executor does
        backup.encryption_key_id = active.id
        backup.wrapped_dek = base64.b64encode(wrapped_dek).decode()
        backup.tags = {
            **backup.tags,
            "encryption_type": "aes-256-gcm",
            "encrypted": True,
            "encryption_key_hash": active.key_hash,
        }
        db_session.commit()

        # Verify
        db_session.refresh(backup)
        assert backup.encryption_key_id == active_key.id
        assert backup.wrapped_dek is not None
        assert backup.tags["encrypted"] is True

        # Verify DEK can be unwrapped
        unwrapped = await kms.unwrap_dek(
            base64.b64decode(backup.wrapped_dek), backup.encryption_key_id
        )
        assert unwrapped == dek


# ═══════════════════════════════════════════════════════════════════════════════
# 8. RESTORE EXECUTOR — ENVELOPE DECRYPTION PATH
# ═══════════════════════════════════════════════════════════════════════════════


class TestRestoreExecutorDecryption:
    """Test that restore executor correctly unwraps DEK from backup."""

    @pytest.mark.asyncio
    async def test_envelope_restore_unwraps_dek(self, kms_provider, db_session):
        """Simulate: backup was envelope-encrypted → restore unwraps DEK correctly."""
        from models import Backup, VM, Agent

        key = await kms_provider.create_key("restore-key")
        original_dek = os.urandom(32)
        wrapped = await kms_provider.wrap_dek(original_dek, key.id)

        agent = Agent(id=str(uuid.uuid4()), hostname="r-host", status="online")
        db_session.add(agent)
        db_session.commit()

        vm = VM(id=str(uuid.uuid4()), name="r-vm", agent_id=agent.id)
        db_session.add(vm)
        db_session.commit()

        backup = Backup(
            id=str(uuid.uuid4()),
            vm_id=vm.id,
            status="completed",
            encryption_key_id=key.id,
            wrapped_dek=base64.b64encode(wrapped).decode(),
            tags={
                "encrypted": True,
                "encryption_type": "aes-256-gcm",
                "encryption_key_hash": key.key_hash,
            },
        )
        db_session.add(backup)
        db_session.commit()

        # Simulate restore executor logic
        from core.kms import get_kms_provider

        kms = get_kms_provider()
        wrapped_dek_bytes = base64.b64decode(backup.wrapped_dek)
        dek = await kms.unwrap_dek(wrapped_dek_bytes, backup.encryption_key_id)

        assert dek == original_dek

    @pytest.mark.asyncio
    async def test_legacy_backup_no_kms_fields(
        self, db_session, monkeypatch, patch_session_local
    ):
        """Legacy backup (pre-envelope) has no encryption_key_id — uses env var fallback."""
        from models import Backup, VM, Agent

        legacy_key = "my-legacy-encryption-key"
        monkeypatch.setenv("ENCRYPTION_KEY", legacy_key)

        agent = Agent(id=str(uuid.uuid4()), hostname="l-host", status="online")
        db_session.add(agent)
        db_session.commit()

        vm = VM(id=str(uuid.uuid4()), name="l-vm", agent_id=agent.id)
        db_session.add(vm)
        db_session.commit()

        key_hash = hashlib.sha256(legacy_key.encode()).hexdigest()[:16]
        backup = Backup(
            id=str(uuid.uuid4()),
            vm_id=vm.id,
            status="completed",
            encryption_key_id=None,  # Legacy — no KMS
            wrapped_dek=None,
            tags={
                "encrypted": True,
                "encryption_type": "fernet",
                "encryption_key_hash": key_hash,
            },
        )
        db_session.add(backup)
        db_session.commit()

        # Simulate restore executor fallback logic
        assert backup.encryption_key_id is None
        assert backup.wrapped_dek is None

        # Would fall through to env var path
        encryption_key = os.getenv("ENCRYPTION_KEY", "")
        assert encryption_key == legacy_key
        actual_hash = hashlib.sha256(encryption_key.encode()).hexdigest()[:16]
        assert actual_hash == key_hash  # Hash matches


# ═══════════════════════════════════════════════════════════════════════════════
# 9. FULL END-TO-END CYCLE
# ═══════════════════════════════════════════════════════════════════════════════


class TestFullCycle:
    """
    Full cycle without backup files:
    create key → backup uses envelope → rotate → old backup still restorable
    → new backup uses new key → export → import on fresh provider → unwrap works
    """

    @pytest.mark.asyncio
    async def test_full_lifecycle(self, kms_provider, db_session):
        from models import Backup, VM, Agent

        # Setup
        agent = Agent(id=str(uuid.uuid4()), hostname="cycle-host", status="online")
        db_session.add(agent)
        db_session.commit()
        vm = VM(id=str(uuid.uuid4()), name="cycle-vm", agent_id=agent.id)
        db_session.add(vm)
        db_session.commit()

        # Step 1: Create key
        key1 = await kms_provider.create_key("key-v1")
        assert key1.status == "active"

        # Step 2: Simulate backup with key1
        dek1 = os.urandom(32)
        wrapped1 = await kms_provider.wrap_dek(dek1, key1.id)
        b1 = Backup(
            id=str(uuid.uuid4()),
            vm_id=vm.id,
            status="completed",
            encryption_key_id=key1.id,
            wrapped_dek=base64.b64encode(wrapped1).decode(),
            tags={"encrypted": True, "encryption_type": "aes-256-gcm"},
        )
        db_session.add(b1)
        db_session.commit()

        # Step 3: Rotate key
        key2 = await kms_provider.rotate_key(key1.id, "key-v2")
        assert key2.status == "active"
        key1_ref = await kms_provider.get_key(key1.id)
        assert key1_ref.status == "rotated"

        # Step 4: Old backup still restorable (old key still unwraps)
        unwrapped1 = await kms_provider.unwrap_dek(
            base64.b64decode(b1.wrapped_dek), b1.encryption_key_id
        )
        assert unwrapped1 == dek1

        # Step 5: New backup uses key2
        dek2 = os.urandom(32)
        wrapped2 = await kms_provider.wrap_dek(dek2, key2.id)
        b2 = Backup(
            id=str(uuid.uuid4()),
            vm_id=vm.id,
            status="completed",
            encryption_key_id=key2.id,
            wrapped_dek=base64.b64encode(wrapped2).decode(),
            tags={"encrypted": True, "encryption_type": "aes-256-gcm"},
        )
        db_session.add(b2)
        db_session.commit()

        # Step 6: Export both keys
        export_data = await kms_provider.export_keys(
            [key1.id, key2.id], NEW_EXPORT_PASSPHRASE
        )

        # Step 7: Verify backup counts
        assert await kms_provider.get_backup_count(key1.id) == 1
        assert await kms_provider.get_backup_count(key2.id) == 1

        # Step 8: Import on same provider (dedup)
        imported = await kms_provider.import_keys(export_data, NEW_EXPORT_PASSPHRASE)
        assert len(imported) == 2  # Both returned (existing = deduplicated)

        # Step 9: Both backups still restorable
        assert (
            await kms_provider.unwrap_dek(
                base64.b64decode(b1.wrapped_dek), b1.encryption_key_id
            )
            == dek1
        )
        assert (
            await kms_provider.unwrap_dek(
                base64.b64decode(b2.wrapped_dek), b2.encryption_key_id
            )
            == dek2
        )


# ═══════════════════════════════════════════════════════════════════════════════
# 10. KMS UNAVAILABLE FALLBACK
# ═══════════════════════════════════════════════════════════════════════════════


class TestKMSUnavailable:
    """Verify that the local KMS refuses to start without an encryption key."""

    def test_local_provider_fails_without_env(self, monkeypatch):
        monkeypatch.delenv("VESTA_ENCRYPTION_KEY", raising=False)
        monkeypatch.delenv("VNBUI_ENCRYPTION_KEY", raising=False)
        from core.kms.local import LocalKMSProvider

        with pytest.raises(ValueError, match="VESTA_ENCRYPTION_KEY not set"):
            LocalKMSProvider()
