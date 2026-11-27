"""The retired unsigned catalog endpoints leave storage and catalog untouched."""

from types import SimpleNamespace

from fastapi import FastAPI
from fastapi.testclient import TestClient
import pytest

from database import get_db
from deps import get_current_user
from routers.s3_import import router


@pytest.mark.parametrize("role,expected", [("admin", 410), ("viewer", 403)])
def test_unsigned_catalog_retirement_has_no_io(monkeypatch, role, expected):
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_current_user] = lambda: SimpleNamespace(role=role)

    def forbidden(*args, **kwargs):
        pytest.fail("retired catalog endpoint reached a storage or write dependency")

    app.dependency_overrides[get_db] = forbidden
    monkeypatch.setattr(
        "core.settings_service.SettingsService.get_s3_config", forbidden
    )
    monkeypatch.setattr("boto3.client", forbidden)
    with TestClient(app) as client:
        response = client.post("/api/v1/s3/import")
    assert response.status_code == expected
    if role == "admin":
        assert response.json()["detail"]["code"] == "unsigned_s3_import_retired"
        assert "Recover from S3" in response.json()["detail"]["message"]


def test_unverified_rows_cannot_supply_restore_a_delete_plan_or_parentage(
    db_session, monkeypatch
):
    import asyncio
    from uuid import uuid4

    from fastapi import HTTPException, BackgroundTasks

    from core.backup_deletion import BackupDependencyError, backup_deletion_service
    from core.backup_service import BackupService
    from core.legacy_recovery import recorded_legacy_local_path
    from models import Backup, User
    from routers.restores import RestoreCreateRequest, create_restore
    from .conftest import make_agent, make_backup, make_vm

    agent = make_agent(db_session)
    vm = make_vm(db_session, agent)
    actor = User(username="catalog-reviewer", password_hash="test-only", role="admin")
    db_session.add(actor)
    db_session.commit()
    trusted_local = make_backup(
        db_session, vm, status="completed", storage_path="file:///backups/recorded"
    )
    legacy = make_backup(
        db_session,
        vm,
        status="completed",
        storage_path="s3://retained-bucket/unverified-history",
        tags={},
        unverified_legacy_s3=True,
    )
    legacy.chain_id = legacy.id
    db_session.commit()

    def no_io(*args, **kwargs):
        pytest.fail("quarantined catalog reached storage or key resolution")

    monkeypatch.setattr("core.settings_service.SettingsService.get_s3_config", no_io)
    monkeypatch.setattr("core.kms.get_kms_provider", no_io)
    with pytest.raises(HTTPException) as refusal:
        create_restore(
            RestoreCreateRequest(backup_id=legacy.id),
            BackgroundTasks(),
            current_user=actor,
            db=db_session,
            request_id=None,
        )
    assert refusal.value.status_code == 409
    db_session.rollback()
    with pytest.raises(BackupDependencyError, match="accepted catalog lineage"):
        asyncio.run(backup_deletion_service.delete_payload(db_session, legacy))

    child = make_backup(
        db_session,
        vm,
        status="completed",
        storage_path="file:///backups/retained-child",
        chain_id=legacy.id,
        parent_backup_id=legacy.id,
        backup_type="incremental",
    )
    candidate = Backup(
        id=str(uuid4()), vm_id=vm.id, backup_type="incremental", org_id=actor.org_id
    )
    service = BackupService(db_session)
    service._resolve_chain(candidate, vm.id)
    assert service.get_chain(legacy.id) == []
    assert recorded_legacy_local_path(child) is None
    assert candidate.parent_backup_id is None
    assert candidate.backup_type == "full"
    assert recorded_legacy_local_path(trusted_local) == "/backups/recorded"
    assert recorded_legacy_local_path(legacy) is None


def test_missing_locator_or_key_material_does_not_select_legacy_local_restore():
    from core.legacy_recovery import recorded_legacy_local_path

    for row in (
        SimpleNamespace(storage_path=None),
        SimpleNamespace(storage_path="s3://retained-bucket/history"),
        SimpleNamespace(
            storage_path="file:///backups/recorded",
            encryption_key_id="retained-key",
        ),
        SimpleNamespace(
            storage_path="file:///backups/recorded",
            tags={"encrypted": True},
        ),
    ):
        assert recorded_legacy_local_path(row) is None
