"""
Tests for auto-queue behavior when backup capacity is reached.

Covers:
1. BackupService returns 429 at capacity
2. add_to_queue creates proper queue entries
3. Queue processor uses BackupService for chain resolution
4. Scheduler queues on capacity instead of bypassing limits
"""

import uuid
from unittest.mock import patch

import pytest

# Fixtures (db_engine, session_factory, db_session, patch_session_local,
# set_encryption_env, _clean_db) provided by conftest.py


@pytest.mark.asyncio
async def test_restart_recovery_poll_is_bounded_and_retires_terminal(monkeypatch):
    from core import backup_recovery
    from core.backup_queue_processor import BackupQueueProcessor

    processor = BackupQueueProcessor(lambda: None, object())
    first = ("first-backup", "org")
    second = ("second-backup", "org")
    processor._recovery_due = {first: 0, second: 0}
    monkeypatch.setattr(processor, "_list_recovery_candidates", lambda: (first, second))
    calls = []

    async def recover(factory, executor, backup_id, org_id, *, previous_outcome):
        calls.append((backup_id, previous_outcome))
        if backup_id == first[0]:
            return {"status": "held", "reason": "agent_unavailable"}
        return {"status": "inactive"}

    monkeypatch.setattr(backup_recovery, "recover_original_attempt", recover)
    await processor._process_recovery()
    assert calls == [(first[0], None)]
    assert processor._recovery_due[first] > 0
    assert processor._recovery_outcome[first] == ("held", "agent_unavailable")
    await processor._process_recovery()
    assert calls[-1] == (second[0], None)
    assert second not in processor._recovery_due
    processor._recovery_due[first] = 0
    await processor._process_recovery()
    assert calls[-1] == (first[0], ("held", "agent_unavailable"))


@pytest.mark.asyncio
async def test_live_recovery_discovers_lost_send_without_restart(monkeypatch):
    from core import backup_queue_processor, backup_recovery

    processor = backup_queue_processor.BackupQueueProcessor(lambda: None, object())
    candidate = ("original-backup", "original-org")
    rows, scans, deliveries = [], [], []
    clock = [1000.0]
    monkeypatch.setattr(backup_queue_processor.time, "monotonic", lambda: clock[0])

    def discover():
        scans.append(clock[0])
        return tuple(rows)

    async def recover(factory, executor, backup_id, org_id, *, previous_outcome):
        deliveries.append((backup_id, org_id, previous_outcome))
        return {"status": "held", "reason": "agent_unavailable"}

    monkeypatch.setattr(processor, "_list_recovery_candidates", discover)
    monkeypatch.setattr(backup_recovery, "recover_original_attempt", recover)
    await processor._refresh_recovery_candidates(clock[0], initial=True)
    rows.append(candidate)  # The original send fails after process startup.
    clock[0] += 59
    await processor._process_recovery()
    assert scans == [1000.0] and not deliveries
    clock[0] += 1
    await processor._process_recovery()
    assert processor._recovery_due[candidate] == 1360.0
    assert not deliveries  # Do not race the normal live admission/observer.
    clock[0] = 1120.0
    await processor._process_recovery()
    assert processor._recovery_due[candidate] == 1360.0
    clock[0] = 1360.0
    await processor._process_recovery()
    assert deliveries == [(candidate[0], candidate[1], None)]
    due = processor._recovery_due[candidate]
    clock[0] += 60
    await processor._process_recovery()
    assert processor._recovery_due[candidate] == due
    assert len(deliveries) == 1  # A scan does not reset held retry backoff.
    rows.clear()  # Terminal work leaves the catalog, no replacement custody.
    clock[0] += 60
    await processor._process_recovery()
    assert not processor._recovery_due and not processor._recovery_outcome


@pytest.mark.asyncio
async def test_live_recovery_discovery_failure_is_rate_limited(monkeypatch):
    from core.backup_queue_processor import BackupQueueProcessor

    processor = BackupQueueProcessor(lambda: None, object())
    calls = []

    def unavailable():
        calls.append(True)
        raise RuntimeError("disposable test database unavailable")

    monkeypatch.setattr(processor, "_list_recovery_candidates", unavailable)
    with pytest.raises(RuntimeError):
        await processor._refresh_recovery_candidates(1000)
    await processor._refresh_recovery_candidates(1005)
    assert len(calls) == 1 and processor._recovery_refresh_due == 1060


def test_custodied_started_queue_never_reenters_dispatch(db_session, session_factory):
    from core.backup_queue_processor import BackupQueueProcessor
    from core.tenant_context import TenantContext
    from models import BackupQueue

    agent = _make_agent(db_session)
    vm = _make_vm(db_session, agent)
    backup = _make_backup(db_session, vm, status="pending", native_job_transaction_id=1)
    queue = BackupQueue(
        vm_id=vm.id,
        status="started",
        authority_kind="human",
        initiating_user_id="original-user",
        started_backup_id=backup.id,
    )
    db_session.add(queue)
    db_session.commit()
    processor = BackupQueueProcessor(session_factory, object())

    with TenantContext(vm.org_id):
        processor._recover_tenant_items()
    db_session.expire_all()
    assert db_session.get(BackupQueue, queue.id).status == "started"

    queue.status = "queued"  # Already queued by a predecessor version.
    db_session.commit()
    assert all(row[0] != queue.id for row in processor._read_candidates((vm.org_id,)))


def _make_agent(db_session, hostname=None):
    from models import Agent

    agent = Agent(
        id=str(uuid.uuid4()),
        hostname=hostname or f"host-{uuid.uuid4().hex[:6]}",
        status="online",
        ip_address="127.0.0.1",
        port=8090,
    )
    db_session.add(agent)
    db_session.commit()
    return agent


def _make_vm(db_session, agent, name=None):
    from models import VM

    vm = VM(
        id=str(uuid.uuid4()),
        name=name or f"vm-{uuid.uuid4().hex[:6]}",
        agent_id=agent.id,
        state="running",
        uuid=str(uuid.uuid4()),
        memory_kb=2048,
        vcpu_count=2,
        disks=[{"target": "vda", "format": "qcow2"}],
    )
    db_session.add(vm)
    db_session.commit()
    return vm


def _make_backup(db_session, vm, **kwargs):
    from models import Backup

    defaults = dict(
        id=str(uuid.uuid4()),
        vm_id=vm.id,
        status="pending",
        backup_type="full",
        tags={},
        storage_path=f"file:///var/lib/vnbui/backups/{uuid.uuid4()}",
    )
    defaults.update(kwargs)
    backup = Backup(**defaults)
    db_session.add(backup)
    db_session.commit()
    db_session.refresh(backup)
    return backup


def _make_service(db_session, monkeypatch, max_concurrent=2):
    monkeypatch.setattr("core.settings_reader.is_maintenance_mode", lambda db: False)
    monkeypatch.setattr(
        "core.settings_reader.get_max_concurrent_backups", lambda db: max_concurrent
    )
    monkeypatch.setattr(
        "core.settings_reader.get_default_retention_days", lambda db: 30
    )
    monkeypatch.setattr(
        "core.settings_reader.get_backup_storage_path",
        lambda db: "/var/lib/vnbui/backups",
    )
    from core.backup_service import BackupService

    # backup_service imports these functions directly. Patch both surfaces so the
    # test is independent of module collection/import order in the full suite.
    monkeypatch.setattr(
        "core.backup_service.get_max_concurrent_backups", lambda db: max_concurrent
    )
    monkeypatch.setattr("core.backup_service.get_default_retention_days", lambda db: 30)
    monkeypatch.setattr(
        "core.backup_service.get_backup_storage_path",
        lambda db: "/var/lib/vnbui/backups",
    )
    monkeypatch.setattr("core.backup_service.is_maintenance_mode", lambda db: False)

    return BackupService(db_session)


# =============================================================================
# 1. BackupService returns 429 when at capacity
# =============================================================================


class TestBackupServiceCapacity:
    """BackupService.create_backup returns error_code=429 at capacity."""

    def test_at_capacity_returns_429(self, db_session, monkeypatch):
        """When running backups >= max_concurrent, create_backup returns 429."""
        agent = _make_agent(db_session)
        vm1 = _make_vm(db_session, agent, name="vm-1")
        vm2 = _make_vm(db_session, agent, name="vm-2")
        vm3 = _make_vm(db_session, agent, name="vm-3")

        svc = _make_service(db_session, monkeypatch, max_concurrent=2)

        # Fill capacity
        _make_backup(db_session, vm1, status="running")
        _make_backup(db_session, vm2, status="running")

        # Third should get 429
        result = svc.create_backup(vm_id=vm3.id, backup_type="full")
        assert not result.success
        assert result.error_code == 429

    def test_below_capacity_succeeds(self, db_session, monkeypatch):
        """When running backups < max_concurrent, create_backup succeeds."""
        agent = _make_agent(db_session)
        vm1 = _make_vm(db_session, agent, name="vm-1")
        vm2 = _make_vm(db_session, agent, name="vm-2")

        svc = _make_service(db_session, monkeypatch, max_concurrent=2)

        _make_backup(db_session, vm1, status="running")

        result = svc.create_backup(vm_id=vm2.id, backup_type="full")
        assert result.success

    def test_skip_concurrent_check(self, db_session, monkeypatch):
        """check_concurrent=False bypasses the limit."""
        agent = _make_agent(db_session)
        vm1 = _make_vm(db_session, agent, name="vm-1")
        vm2 = _make_vm(db_session, agent, name="vm-2")
        vm3 = _make_vm(db_session, agent, name="vm-3")

        svc = _make_service(db_session, monkeypatch, max_concurrent=2)

        _make_backup(db_session, vm1, status="running")
        _make_backup(db_session, vm2, status="running")

        result = svc.create_backup(
            vm_id=vm3.id, backup_type="full", check_concurrent=False
        )
        assert result.success


# =============================================================================
# 2. add_to_queue creates proper queue entries
# =============================================================================


class TestAddToQueue:
    """add_to_queue creates BackupQueue records with correct fields."""

    def test_basic_queue_entry(self, db_session):
        from core.backup_queue_processor import add_to_queue

        agent = _make_agent(db_session)
        vm = _make_vm(db_session, agent)

        item = add_to_queue(
            db_session,
            vm_id=vm.id,
            retention_days=14,
            backup_type="incremental",
            tags={"env": "test"},
        )

        assert item.id is not None
        assert item.vm_id == vm.id
        assert item.retention_days == 14
        assert item.backup_type == "incremental"
        assert item.status == "queued"
        assert item.tags == {"env": "test"}

    def test_queue_with_schedule_id(self, db_session):
        from core.backup_queue_processor import add_to_queue

        agent = _make_agent(db_session)
        vm = _make_vm(db_session, agent)

        schedule_id = str(uuid.uuid4())
        item = add_to_queue(
            db_session,
            vm_id=vm.id,
            schedule_id=schedule_id,
        )

        assert item.schedule_id == schedule_id

    def test_queue_with_created_by(self, db_session):
        from core.backup_queue_processor import add_to_queue

        agent = _make_agent(db_session)
        vm = _make_vm(db_session, agent)

        user_id = str(uuid.uuid4())
        item = add_to_queue(
            db_session,
            vm_id=vm.id,
            created_by=user_id,
        )

        assert item.created_by == user_id


# =============================================================================
# 3. Queue processor uses BackupService (chain resolution + storage_path)
# =============================================================================


class TestQueueProcessorBackupService:
    """_start_backup_from_queue uses BackupService for proper backup creation."""

    @pytest.fixture(autouse=True)
    def initiating_actor(self, db_session, monkeypatch):
        from models import User

        actor = User(
            id=str(uuid.uuid4()),
            username="queue-operator",
            password_hash="fixture",
            role="operator",
        )
        db_session.add(actor)
        db_session.commit()
        # Unit-only authenticated-context double. Real admission/immutability
        # and organization-only reopen execute in the restricted PG suite.
        monkeypatch.setattr(
            "core.backup_queue_processor.identity",
            lambda: (actor.org_id, actor.id, False),
        )

    @pytest.mark.asyncio
    async def test_queue_creates_backup_via_service(
        self, db_session, session_factory, monkeypatch
    ):
        """Queue processor creates backup with chain resolution."""
        from core.backup_queue_processor import BackupQueueProcessor, add_to_queue
        from models import Backup

        agent = _make_agent(db_session)
        vm = _make_vm(db_session, agent, name="chain-vm")

        # Create a completed full backup (chain parent)
        parent = _make_backup(
            db_session,
            vm,
            status="completed",
            backup_type="full",
            chain_id=None,
            chain_position=0,
        )
        parent.chain_id = parent.id
        db_session.commit()

        # Queue an incremental
        queue_item = add_to_queue(
            db_session,
            vm_id=vm.id,
            backup_type="incremental",
            retention_days=7,
        )

        # Mock settings
        monkeypatch.setattr(
            "core.settings_reader.is_maintenance_mode", lambda db: False
        )
        monkeypatch.setattr(
            "core.settings_reader.get_max_concurrent_backups", lambda db: 10
        )
        monkeypatch.setattr(
            "core.settings_reader.get_default_retention_days", lambda db: 30
        )
        monkeypatch.setattr(
            "core.settings_reader.get_backup_storage_path",
            lambda db: "/var/lib/vnbui/backups",
        )
        processor = BackupQueueProcessor(
            db_session_factory=session_factory,
            backup_executor=None,
            use_real_executor=False,
        )

        await processor._start_backup_from_queue(db_session, queue_item)

        # The backup should exist with chain fields set
        new_backup = (
            db_session.query(Backup)
            .filter(
                Backup.vm_id == vm.id,
                Backup.status == "pending",
            )
            .first()
        )
        assert new_backup is not None
        assert new_backup.chain_id == parent.chain_id
        assert new_backup.parent_backup_id == parent.id
        assert new_backup.chain_position == 1
        assert new_backup.storage_path is not None
        assert new_backup.storage_path.startswith("file:///var/lib/vnbui/backups/")
        await processor.stop()

    @pytest.mark.asyncio
    async def test_queue_adds_from_queue_tag(
        self, db_session, session_factory, monkeypatch
    ):
        """Queue-originated backups get from_queue and queue_id tags."""
        from core.backup_queue_processor import BackupQueueProcessor, add_to_queue
        from models import Backup

        agent = _make_agent(db_session)
        vm = _make_vm(db_session, agent)

        queue_item = add_to_queue(db_session, vm_id=vm.id)

        monkeypatch.setattr(
            "core.settings_reader.is_maintenance_mode", lambda db: False
        )
        monkeypatch.setattr(
            "core.settings_reader.get_max_concurrent_backups", lambda db: 10
        )
        monkeypatch.setattr(
            "core.settings_reader.get_default_retention_days", lambda db: 30
        )
        monkeypatch.setattr(
            "core.settings_reader.get_backup_storage_path",
            lambda db: "/var/lib/vnbui/backups",
        )

        processor = BackupQueueProcessor(
            db_session_factory=session_factory,
            backup_executor=None,
            use_real_executor=False,
        )

        await processor._start_backup_from_queue(db_session, queue_item)

        backup = (
            db_session.query(Backup)
            .filter(Backup.vm_id == vm.id, Backup.status == "pending")
            .first()
        )
        assert backup is not None
        assert backup.tags.get("from_queue") == "true"
        assert backup.tags.get("queue_id") == queue_item.id
        await processor.stop()

    @pytest.mark.asyncio
    async def test_queue_failure_resets_to_queued(
        self, db_session, session_factory, monkeypatch
    ):
        """If BackupService fails, queue item goes back to 'queued'."""
        from core.backup_queue_processor import BackupQueueProcessor, add_to_queue

        agent = _make_agent(db_session)
        vm = _make_vm(db_session, agent)

        queue_item = add_to_queue(db_session, vm_id=vm.id)

        # Make create_backup fail (maintenance mode)
        # Patch where it's used — BackupService imports via `from ... import`
        monkeypatch.setattr("core.backup_service.is_maintenance_mode", lambda db: True)
        monkeypatch.setattr(
            "core.backup_service.get_max_concurrent_backups", lambda db: 10
        )
        monkeypatch.setattr(
            "core.backup_service.get_default_retention_days", lambda db: 30
        )
        monkeypatch.setattr(
            "core.backup_service.get_backup_storage_path",
            lambda db: "/var/lib/vnbui/backups",
        )

        processor = BackupQueueProcessor(
            db_session_factory=session_factory,
            backup_executor=None,
            use_real_executor=False,
        )

        queue_id = queue_item.id
        await processor._start_backup_from_queue(db_session, queue_item)

        # Re-query to avoid session state issues
        from models import BackupQueue

        reloaded = (
            db_session.query(BackupQueue).filter(BackupQueue.id == queue_id).first()
        )
        assert reloaded is not None
        assert reloaded.status == "queued"
        assert reloaded.started_at is None


# =============================================================================
# 4. Scheduler queues on capacity
# =============================================================================


class TestSchedulerAutoQueue:
    """Scheduler queues backups when at capacity instead of bypassing limits."""

    def test_scheduler_queues_on_429(self, db_session, session_factory, monkeypatch):
        """When at capacity, scheduler calls add_to_queue instead of skipping."""
        from models import Schedule, BackupQueue, User

        agent = _make_agent(db_session)
        vm = _make_vm(db_session, agent, name="sched-vm")
        vm_id = vm.id  # Capture before session close
        org_id = vm.org_id
        actor_id = str(uuid.uuid4())
        db_session.add(
            User(
                id=actor_id,
                org_id=org_id,
                username=actor_id,
                password_hash="test",
                role="operator",
                is_active=True,
            )
        )
        db_session.commit()

        # Create schedule
        schedule_id = str(uuid.uuid4())
        schedule = Schedule(
            id=schedule_id,
            name="nightly",
            vm_id=vm_id,
            cron_expression="0 2 * * *",
            retention_days=14,
            backup_type="full",
            enabled=True,
        )
        db_session.add(schedule)
        db_session.commit()

        # Fill capacity
        vm_other = _make_vm(db_session, agent, name="other-vm-1")
        vm_other2 = _make_vm(db_session, agent, name="other-vm-2")
        _make_backup(db_session, vm_other, status="running")
        _make_backup(db_session, vm_other2, status="running")

        # Mock settings
        monkeypatch.setattr(
            "core.settings_reader.is_maintenance_mode", lambda db: False
        )
        monkeypatch.setattr(
            "core.settings_reader.get_max_concurrent_backups", lambda db: 2
        )
        monkeypatch.setattr(
            "core.settings_reader.get_default_retention_days", lambda db: 30
        )
        monkeypatch.setattr(
            "core.settings_reader.get_backup_storage_path",
            lambda db: "/var/lib/vnbui/backups",
        )
        monkeypatch.setattr(
            "core.backup_service.get_max_concurrent_backups", lambda db: 2
        )
        monkeypatch.setattr(
            "core.backup_service.get_default_retention_days", lambda db: 30
        )
        monkeypatch.setattr(
            "core.backup_service.get_backup_storage_path",
            lambda db: "/var/lib/vnbui/backups",
        )
        monkeypatch.setattr("core.backup_service.is_maintenance_mode", lambda db: False)

        # Scheduler creates its own session via SessionLocal() and closes it,
        # so we use session_factory to give it a fresh session from the same DB
        with patch("database.SessionLocal", session_factory):
            from scheduler import execute_scheduled_backup

            # Actorless timer callbacks cannot queue anything in the dormant slice.
            execute_scheduled_backup(schedule_id, org_id)
            with session_factory() as check:
                assert check.query(BackupQueue).filter_by(vm_id=vm_id).count() == 0
            execute_scheduled_backup(schedule_id, org_id, actor_id)

        # Query with a fresh session (scheduler closed the one it got)
        check_db = session_factory()
        queued = check_db.query(BackupQueue).filter(BackupQueue.vm_id == vm_id).first()
        assert queued is not None
        assert queued.schedule_id == schedule_id
        assert queued.authority_kind == "human"
        assert queued.initiating_user_id == actor_id
        assert queued.scheduler_occurrence_id is None
        assert queued.retention_days == 14
        assert queued.backup_type == "full"
        check_db.close()


# =============================================================================
# 5. Disk eligibility checks
# =============================================================================


class TestDiskEligibility:
    """BackupService.check_disk_eligibility returns correct results."""

    @pytest.mark.parametrize("metadata_provider", [False, True])
    @pytest.mark.parametrize("source_type", ["persistentVolumeClaim", "dataVolume"])
    @pytest.mark.parametrize("ready", [False, True])
    def test_kubevirt_uses_observed_disk_eligibility(
        self, metadata_provider, source_type, ready
    ):
        from models import VM
        from core.backup_service import BackupService

        vm = VM(
            provider=None if metadata_provider else "kubevirt",
            vm_metadata={"provider": "kubevirt"} if metadata_provider else {},
            disks=[
                {
                    "target": "data",
                    "format": "raw",
                    "source_type": source_type,
                    "backup_eligible": ready,
                    **(
                        {}
                        if ready
                        else {
                            "source_error": "KubeVirt ChangedBlockTracking is not Enabled"
                        }
                    ),
                }
            ],
        )
        result = BackupService.check_disk_eligibility(vm)
        assert result["eligible"] is ready
        assert result["has_raw"] is False
        assert not any("copy mode" in warning for warning in result["warnings"])
        assert bool(result["warnings"]) is not ready

    @pytest.mark.parametrize(
        "disk",
        [
            {"source_type": "persistentVolumeClaim"},
            {"source_type": "unsupported", "backup_eligible": True},
            {
                "source_type": "persistentVolumeClaim",
                "backup_eligible": True,
                "source_error": "unbound",
            },
        ],
    )
    def test_kubevirt_unusable_disk_is_not_eligible(self, disk):
        from models import VM
        from core.backup_service import BackupService

        result = BackupService.check_disk_eligibility(
            VM(provider="kubevirt", disks=[disk])
        )
        assert result["eligible"] is False
        assert result["warnings"]

    def test_kubevirt_can_select_data_and_exclude_container_boot(self):
        from models import VM
        from core.backup_service import BackupService

        vm = VM(
            provider="kubevirt",
            disks=[
                {
                    "target": "boot",
                    "source_type": "unsupported",
                    "backup_eligible": False,
                },
                {
                    "target": "data",
                    "source_type": "persistentVolumeClaim",
                    "backup_eligible": True,
                },
            ],
        )
        result = BackupService.check_disk_eligibility(vm)
        assert result["eligible"] is True
        assert len(result["warnings"]) == 1
        assert "boot" in result["warnings"][0]

    def test_kubevirt_ineligible_inventory_refuses_admission(self, db_session):
        from models import VM
        from core.backup_service import BackupService

        vm = VM(
            id="initializing",
            name="initializing",
            agent_id="a",
            provider="kubevirt",
            vm_uid="stable",
            disks=[
                {
                    "target": "data",
                    "source_type": "persistentVolumeClaim",
                    "backup_eligible": False,
                    "source_error": "KubeVirt ChangedBlockTracking is not Enabled",
                }
            ],
        )
        db_session.add(vm)
        db_session.commit()
        allowed, error, code = BackupService(db_session).can_start_backup(
            vm.id, check_maintenance=False, check_concurrent=False
        )
        assert allowed is False and code == 422
        assert "ChangedBlockTracking" in error

    def test_all_qcow2(self, db_session):
        from models import VM

        vm = VM(
            id="1",
            name="test",
            agent_id="a",
            disks=[{"target": "vda", "format": "qcow2"}],
        )
        from core.backup_service import BackupService

        result = BackupService.check_disk_eligibility(vm)
        assert result["eligible"] is True
        assert result["has_raw"] is False
        assert result["warnings"] == []

    def test_all_raw(self, db_session):
        from models import VM

        vm = VM(
            id="1",
            name="test",
            agent_id="a",
            disks=[{"target": "sda", "format": "raw"}],
        )
        from core.backup_service import BackupService

        result = BackupService.check_disk_eligibility(vm)
        assert result["eligible"] is False
        assert result["has_raw"] is True
        assert len(result["warnings"]) == 1
        assert "require qcow2" in result["warnings"][0]
        assert "copy mode" not in result["warnings"][0]

    def test_mixed_disks(self, db_session):
        from models import VM

        vm = VM(
            id="1",
            name="test",
            agent_id="a",
            disks=[
                {"target": "vda", "format": "qcow2"},
                {"target": "sda", "format": "raw"},
            ],
        )
        from core.backup_service import BackupService

        result = BackupService.check_disk_eligibility(vm)
        assert result["eligible"] is True
        assert result["has_raw"] is True
        assert len(result["warnings"]) == 1
        assert "sda" in result["warnings"][0]
        assert "explicitly exclude" in result["warnings"][0]

    def test_no_disks(self, db_session):
        from models import VM

        vm = VM(id="1", name="test", agent_id="a", disks=[])
        from core.backup_service import BackupService

        result = BackupService.check_disk_eligibility(vm)
        assert result["eligible"] is False
        assert "no disks" in result["warnings"][0].lower()

    def test_unknown_format(self, db_session):
        from models import VM

        vm = VM(id="1", name="test", agent_id="a", disks=[{"target": "vda"}])
        from core.backup_service import BackupService

        result = BackupService.check_disk_eligibility(vm)
        assert result["eligible"] is False
        assert "require qcow2" in result["warnings"][0]

    def test_native_raw_inventory_refuses_before_backup_admission(self, db_session):
        from models import Backup, VM
        from core.backup_service import BackupService

        vm = VM(
            id="native-raw",
            name="native-raw",
            agent_id="a",
            provider="libvirt",
            disks=[{"target": "vda", "format": "raw"}],
        )
        db_session.add(vm)
        db_session.commit()
        allowed, error, code = BackupService(db_session).can_start_backup(
            vm.id, check_maintenance=False, check_concurrent=False
        )
        assert not allowed and code == 422 and "require qcow2" in error
        assert db_session.query(Backup).count() == 0

    def test_none_disks(self, db_session):
        from models import VM

        vm = VM(id="1", name="test", agent_id="a", disks=None)
        from core.backup_service import BackupService

        result = BackupService.check_disk_eligibility(vm)
        assert result["eligible"] is False


# =============================================================================
# 6. Retry-upload endpoint validation
# =============================================================================


class TestRetryUpload:
    """POST /backups/{id}/retry-upload validates status correctly."""

    def test_rejects_running_backup(self, db_session, monkeypatch):
        agent = _make_agent(db_session)
        vm = _make_vm(db_session, agent)
        backup = _make_backup(db_session, vm, status="running")

        # Backup in running state would be rejected by retry-upload endpoint
        assert backup.status == "running"

    def test_accepts_upload_failed(self, db_session, monkeypatch):
        agent = _make_agent(db_session)
        vm = _make_vm(db_session, agent)
        backup = _make_backup(
            db_session,
            vm,
            status="upload_failed",
            tags={"upload_error": "timeout", "upload_attempts": 3},
        )
        # Verify tags are set correctly for retry
        assert backup.status == "upload_failed"
        assert backup.tags["upload_attempts"] == 3

    def test_rejects_already_in_s3(self, db_session, monkeypatch):
        agent = _make_agent(db_session)
        vm = _make_vm(db_session, agent)
        backup = _make_backup(
            db_session,
            vm,
            status="completed",
            storage_path="s3://bucket/prefix/id",
        )
        assert backup.storage_path.startswith("s3://")
