"""
Tests for S3 backup discovery and import (greenfield DR).

Covers:
1. Discovery — classify chains as available/imported/partial/conflict/kek_missing
2. Import — idempotent creation of backup + VM records
3. Sentinel agent — creation and reuse
4. Conflict detection — backup ID exists under different chain
5. KEK validation — encrypted chains need matching keys
"""

import importlib.util
import json
import os
import uuid
from unittest.mock import MagicMock

# Fixtures (db_engine, session_factory, db_session, set_encryption_env,
# _clean_db) provided by conftest.py


def _load_s3_import():
    """Load s3_import module directly, bypassing routers/__init__.py."""
    backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    spec = importlib.util.spec_from_file_location(
        "s3_import",
        os.path.join(backend_dir, "routers", "s3_import.py"),
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_s3_mod = _load_s3_import()
_classify_chain = _s3_mod._classify_chain
_download_manifests = _s3_mod._download_manifests
_get_or_create_sentinel_agent = _s3_mod._get_or_create_sentinel_agent
_find_or_create_vm = _s3_mod._find_or_create_vm


# --- Helper: create a manifest dict ---


def make_manifest(
    vm_name="test-vm", chain_id=None, num_backups=3, encrypted=False, kek_id=None
):
    chain_id = chain_id or str(uuid.uuid4())
    backups = []
    for i in range(num_backups):
        bid = str(uuid.uuid4())
        entry = {
            "backup_id": bid,
            "backup_type": "full" if i == 0 else "incremental",
            "chain_position": i,
            "size_bytes": 1000000 * (i + 1),
            "created_at": f"2026-03-0{i+1}T10:00:00Z",
            "completed_at": f"2026-03-0{i+1}T10:30:00Z",
            "s3_prefix": f"backups/{vm_name}/{bid}",
            "retention_days": 30,
        }
        if encrypted and kek_id:
            entry["encryption_key_id"] = kek_id
            entry["wrapped_dek"] = "base64encodedwrappeddek=="
        backups.append(entry)

    return {
        "chain_id": chain_id,
        "vm_name": vm_name,
        "backups": backups,
    }


# ═══════════════════════════════════════════════════════════════════════════════
# 1. CHAIN CLASSIFICATION
# ═══════════════════════════════════════════════════════════════════════════════


class TestClassifyChain:

    def test_available_chain(self, db_session):
        manifest = make_manifest("vpn01")
        result = _classify_chain(manifest, db_session)

        assert result["status"] == "available"
        assert result["vm_name"] == "vpn01"
        assert result["backup_count"] == 3
        assert result["imported_count"] == 0
        assert result["total_size_bytes"] == 6000000
        assert result["encrypted"] is False
        assert result["conflicts"] == []

    def test_imported_chain(self, db_session):
        from models import Backup, VM, Agent

        manifest = make_manifest("vpn01")
        chain_id = manifest["chain_id"]

        # Pre-create all backups in DB
        agent = Agent(id=str(uuid.uuid4()), hostname="test-agent", status="online")
        db_session.add(agent)
        db_session.flush()

        vm = VM(id=str(uuid.uuid4()), name="vpn01", agent_id=agent.id)
        db_session.add(vm)
        db_session.flush()

        for entry in manifest["backups"]:
            b = Backup(
                id=entry["backup_id"],
                vm_id=vm.id,
                status="completed",
                chain_id=chain_id,
            )
            db_session.add(b)
        db_session.commit()

        result = _classify_chain(manifest, db_session)
        assert result["status"] == "imported"
        assert result["imported_count"] == 3

    def test_partial_chain(self, db_session):
        from models import Backup, VM, Agent

        manifest = make_manifest("vpn01")
        chain_id = manifest["chain_id"]

        agent = Agent(id=str(uuid.uuid4()), hostname="test-agent", status="online")
        db_session.add(agent)
        db_session.flush()

        vm = VM(id=str(uuid.uuid4()), name="vpn01", agent_id=agent.id)
        db_session.add(vm)
        db_session.flush()

        # Only import first 2 of 3
        for entry in manifest["backups"][:2]:
            b = Backup(
                id=entry["backup_id"],
                vm_id=vm.id,
                status="completed",
                chain_id=chain_id,
            )
            db_session.add(b)
        db_session.commit()

        result = _classify_chain(manifest, db_session)
        assert result["status"] == "partial"
        assert result["imported_count"] == 2
        assert result["backup_count"] == 3

    def test_conflict_different_chain(self, db_session):
        from models import Backup, VM, Agent

        manifest = make_manifest("vpn01")
        different_chain = str(uuid.uuid4())

        agent = Agent(id=str(uuid.uuid4()), hostname="test-agent", status="online")
        db_session.add(agent)
        db_session.flush()

        vm = VM(id=str(uuid.uuid4()), name="vpn01", agent_id=agent.id)
        db_session.add(vm)
        db_session.flush()

        # Create backup with same ID but different chain
        b = Backup(
            id=manifest["backups"][0]["backup_id"],
            vm_id=vm.id,
            status="completed",
            chain_id=different_chain,
        )
        db_session.add(b)
        db_session.commit()

        result = _classify_chain(manifest, db_session)
        assert result["status"] == "conflict"
        assert len(result["conflicts"]) == 1
        assert result["conflicts"][0]["reason"] == "exists_different_chain"

    def test_kek_missing(self, db_session):
        kek_id = str(uuid.uuid4())
        manifest = make_manifest("vpn01", encrypted=True, kek_id=kek_id)

        result = _classify_chain(manifest, db_session)
        assert result["status"] == "kek_missing"
        assert result["encrypted"] is True
        assert result["kek_available"] is False
        assert kek_id in result["kek_ids"]

    def test_encrypted_with_kek(self, db_session):
        from models import EncryptionKey

        kek_id = str(uuid.uuid4())
        kek = EncryptionKey(
            id=kek_id,
            name="test-kek",
            key_hash="abcd1234",
            status="active",
        )
        db_session.add(kek)
        db_session.commit()

        manifest = make_manifest("vpn01", encrypted=True, kek_id=kek_id)
        result = _classify_chain(manifest, db_session)
        assert result["status"] == "available"
        assert result["encrypted"] is True
        assert result["kek_available"] is True


# ═══════════════════════════════════════════════════════════════════════════════
# 2. SENTINEL AGENT + VM CREATION
# ═══════════════════════════════════════════════════════════════════════════════


class TestSentinelAgent:

    def test_creates_sentinel_agent(self, db_session):
        agent = _get_or_create_sentinel_agent(db_session)
        db_session.commit()

        assert agent.hostname == "__s3_import__"
        assert agent.display_name == "S3 Import (placeholder)"
        assert agent.status == "offline"

        # Second call reuses
        agent2 = _get_or_create_sentinel_agent(db_session)
        assert agent2.id == agent.id

    def test_creates_placeholder_vm(self, db_session):
        vm, created = _find_or_create_vm(db_session, "new-vm-01", "chain-new")
        db_session.commit()

        assert created is True
        assert vm.name == "new-vm-01"
        assert vm.state == "unknown"
        assert vm.vm_metadata.get("imported_from_s3") is True
        assert vm.vm_metadata.get("placeholder") is True

    def test_never_attaches_legacy_chain_by_name(self, db_session):
        from models import VM, Agent

        agent = Agent(id=str(uuid.uuid4()), hostname="real-agent", status="online")
        db_session.add(agent)
        db_session.flush()

        existing_vm = VM(id=str(uuid.uuid4()), name="existing-vm", agent_id=agent.id)
        db_session.add(existing_vm)
        db_session.commit()

        vm, created = _find_or_create_vm(db_session, "existing-vm", "old-chain")
        assert created is True
        assert vm.id != existing_vm.id
        assert vm.inventory_present is False
        repeated, created = _find_or_create_vm(db_session, "existing-vm", "old-chain")
        assert repeated.id == vm.id and created is False
        different, _ = _find_or_create_vm(db_session, "existing-vm", "other-chain")
        assert different.id != vm.id

    def test_reuses_only_exact_source_identity(self, db_session):
        from models import VM, Agent

        agent = Agent(hostname="identity-agent", status="online")
        db_session.add(agent)
        db_session.flush()
        vm = VM(
            name="same",
            agent_id=agent.id,
            provider="kubevirt",
            namespace="one",
            vm_uid="old-uid",
            inventory_present=False,
        )
        replacement = VM(
            name="same",
            agent_id=agent.id,
            provider="kubevirt",
            namespace="one",
            vm_uid="new-uid",
        )
        db_session.add_all([vm, replacement])
        db_session.commit()
        identity = dict(
            agent_id=agent.id, provider="kubevirt", namespace="one", vm_uid="old-uid"
        )
        imported, created = _find_or_create_vm(
            db_session, "same", "old-chain", identity
        )
        assert imported.id == vm.id and created is False
        identity["namespace"] = "different"
        isolated, created = _find_or_create_vm(
            db_session, "same", "foreign-chain", identity
        )
        assert isolated.id not in (vm.id, replacement.id) and created is True


# ═══════════════════════════════════════════════════════════════════════════════
# 3. IMPORT LOGIC (unit-level)
# ═══════════════════════════════════════════════════════════════════════════════


class TestImportLogic:

    def test_import_creates_backups(self, db_session):
        from models import Backup

        manifest = make_manifest("import-vm")
        vm, _ = _find_or_create_vm(db_session, "import-vm", manifest["chain_id"])
        chain_id = manifest["chain_id"]

        prev_id = None
        for entry in sorted(manifest["backups"], key=lambda b: b["chain_position"]):
            backup = Backup(
                id=entry["backup_id"],
                vm_id=vm.id,
                status="completed",
                progress=100,
                size_bytes=entry["size_bytes"],
                backup_type=entry["backup_type"],
                storage_path=f"s3://bucket/{entry['s3_prefix']}",
                tags={"imported_from_s3": True},
                chain_position=entry["chain_position"],
            )
            if entry["chain_position"] == 0:
                db_session.add(backup)
                db_session.flush()
                backup.chain_id = backup.id
            else:
                backup.chain_id = chain_id
                backup.parent_backup_id = prev_id
                db_session.add(backup)

            prev_id = entry["backup_id"]

        db_session.commit()

        backups = db_session.query(Backup).filter(Backup.vm_id == vm.id).all()
        assert len(backups) == 3

        full = [b for b in backups if b.chain_position == 0][0]
        assert full.chain_id == full.id
        assert full.parent_backup_id is None

        inc1 = [b for b in backups if b.chain_position == 1][0]
        assert inc1.chain_id == chain_id
        assert inc1.parent_backup_id == full.id

    def test_import_idempotent_skip(self, db_session):
        """Importing a backup that already exists should be skipped."""
        from models import Backup, VM, Agent

        manifest = make_manifest("skip-vm")
        chain_id = manifest["chain_id"]

        agent = Agent(id=str(uuid.uuid4()), hostname="ag1", status="online")
        db_session.add(agent)
        db_session.flush()

        vm = VM(id=str(uuid.uuid4()), name="skip-vm", agent_id=agent.id)
        db_session.add(vm)
        db_session.flush()

        # Pre-import all backups
        for entry in manifest["backups"]:
            b = Backup(
                id=entry["backup_id"],
                vm_id=vm.id,
                status="completed",
                chain_id=chain_id,
            )
            db_session.add(b)
        db_session.commit()

        # Simulating import logic: check existing
        backup_ids = [b["backup_id"] for b in manifest["backups"]]
        existing = db_session.query(Backup).filter(Backup.id.in_(backup_ids)).all()
        existing_map = {b.id: b for b in existing}

        imported = 0
        skipped = 0
        for entry in manifest["backups"]:
            if entry["backup_id"] in existing_map:
                skipped += 1
            else:
                imported += 1

        assert imported == 0
        assert skipped == 3

    def test_import_partial_only_missing(self, db_session):
        """Partial import should only create missing backups."""
        from models import Backup, VM, Agent

        manifest = make_manifest("partial-vm")
        chain_id = manifest["chain_id"]

        agent = Agent(id=str(uuid.uuid4()), hostname="ag2", status="online")
        db_session.add(agent)
        db_session.flush()

        vm = VM(id=str(uuid.uuid4()), name="partial-vm", agent_id=agent.id)
        db_session.add(vm)
        db_session.flush()

        # Pre-import first 2 backups only
        for entry in manifest["backups"][:2]:
            b = Backup(
                id=entry["backup_id"],
                vm_id=vm.id,
                status="completed",
                chain_id=chain_id,
            )
            db_session.add(b)
        db_session.commit()

        # Simulate import: only 3rd should be created
        backup_ids = [b["backup_id"] for b in manifest["backups"]]
        existing = db_session.query(Backup).filter(Backup.id.in_(backup_ids)).all()
        existing_map = {b.id: b for b in existing}

        imported = 0
        skipped = 0
        for entry in manifest["backups"]:
            if entry["backup_id"] in existing_map:
                skipped += 1
            else:
                imported += 1

        assert skipped == 2
        assert imported == 1


# ═══════════════════════════════════════════════════════════════════════════════
# 4. MANIFEST DOWNLOAD + PARSING
# ═══════════════════════════════════════════════════════════════════════════════


class TestDownloadManifests:

    def test_download_manifests_parses_correctly(self):
        import io

        manifest = make_manifest("vm1")
        manifest_json = json.dumps(manifest).encode("utf-8")

        mock_s3 = MagicMock()
        mock_paginator = MagicMock()
        mock_s3.get_paginator.return_value = mock_paginator
        mock_paginator.paginate.return_value = [
            {
                "Contents": [
                    {"Key": "backups/manifests/vm1/chain-abc.json"},
                    {"Key": "backups/manifests/vm1/not-json.txt"},  # ignored
                ]
            }
        ]
        mock_s3.get_object.return_value = {"Body": io.BytesIO(manifest_json)}

        results = _download_manifests(mock_s3, "test-bucket", "backups")
        assert len(results) == 1
        assert results[0]["vm_name"] == "vm1"

    def test_download_manifests_skips_invalid_paths(self):
        mock_s3 = MagicMock()
        mock_paginator = MagicMock()
        mock_s3.get_paginator.return_value = mock_paginator
        mock_paginator.paginate.return_value = [
            {
                "Contents": [
                    {"Key": "backups/manifests/nested/deep/chain.json"},  # 2+ levels
                    {"Key": "backups/manifests/chain.json"},  # no vm_name level
                ]
            }
        ]

        results = _download_manifests(mock_s3, "test-bucket", "backups")
        assert len(results) == 0

    def test_download_manifests_handles_empty_bucket(self):
        mock_s3 = MagicMock()
        mock_paginator = MagicMock()
        mock_s3.get_paginator.return_value = mock_paginator
        mock_paginator.paginate.return_value = [{}]  # No Contents

        results = _download_manifests(mock_s3, "test-bucket", "backups")
        assert results == []
