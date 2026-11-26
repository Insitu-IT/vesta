"""
Backup Service - Centralized backup creation and management

Consolidates backup creation logic from multiple entry points:
- API endpoint (POST /api/v1/backups)
- Bulk operations (POST /api/v1/backups/bulk-create)
- Scheduled backups (APScheduler)
"""

from typing import Optional, Dict, Any, List, Tuple
from copy import deepcopy
from sqlalchemy.orm import Session
import logging

from models import Agent, Backup, BackupQueue, VM
from core.settings_reader import (
    get_max_concurrent_backups,
    get_default_retention_days,
    get_backup_storage_path,
    is_maintenance_mode,
)
from sqlalchemy import desc
from core.tenant_context import identity

logger = logging.getLogger(__name__)


class BackupCreateResult:
    """Result of backup creation attempt"""

    def __init__(
        self,
        success: bool,
        backup: Optional[Backup] = None,
        error: Optional[str | Dict[str, str]] = None,
        error_code: Optional[int] = None,
    ):
        self.success = success
        self.backup = backup
        self.error = error
        self.error_code = error_code  # HTTP status code for error


class BackupService:
    """Service for backup creation and management"""

    def __init__(self, db: Session):
        self.db = db

    @staticmethod
    def check_disk_eligibility(vm) -> dict:
        """Check provider-specific disk eligibility from observed inventory.

        Returns dict with: eligible, warnings, has_raw
        """
        if getattr(vm, "inventory_present", True) is False:
            return {
                "eligible": False,
                "has_raw": False,
                "warnings": ["VM is absent; historical backups remain available"],
            }
        disks = vm.disks or []
        if not disks:
            return {
                "eligible": False,
                "has_raw": False,
                "warnings": ["VM has no disks"],
            }

        if (
            getattr(vm, "provider", None)
            or (getattr(vm, "vm_metadata", None) or {}).get("provider")
        ) == "kubevirt":
            eligible = False
            warnings = []
            for disk in disks:
                usable = (
                    disk.get("source_type") in {"persistentVolumeClaim", "dataVolume"}
                    and disk.get("backup_eligible") is True
                    and not disk.get("source_error")
                )
                eligible = eligible or usable
                if not usable:
                    warnings.append(
                        f"Disk {disk.get('target', 'unknown')}: "
                        f"{disk.get('source_error') or 'not eligible; explicitly exclude this disk'}"
                    )
            # At least one persistent disk must be usable. Selection validates
            # every non-excluded disk separately; container boot media need not
            # prevent backing up an explicitly selected persistent data disk.
            return {"eligible": eligible, "has_raw": False, "warnings": warnings}

        has_qcow2 = False
        raw_disks = []
        warnings = []
        for d in disks:
            fmt = d.get("format")
            target = d.get("target", "unknown")
            if fmt == "qcow2":
                has_qcow2 = True
            elif fmt == "raw":
                raw_disks.append(target)
            if fmt != "qcow2":
                warnings.append(
                    f"Disk {target}: protected native libvirt disks require qcow2; "
                    "explicitly exclude this disk"
                )

        return {
            "eligible": has_qcow2,
            "has_raw": bool(raw_disks),
            "warnings": warnings,
        }

    def can_start_backup(
        self, vm_id: str, check_maintenance: bool = True, check_concurrent: bool = True
    ) -> Tuple[bool, Optional[str | Dict[str, str]], Optional[int]]:
        """
        Check if a backup can be started for a VM.

        Args:
            vm_id: ID of the VM to backup
            check_maintenance: Whether to check maintenance mode
            check_concurrent: Whether to check max concurrent limit

        Returns:
            Tuple of (can_start, error_detail, HTTP_status).
            Admission errors include a stable code and a human-readable message.
        """
        # Check maintenance mode
        if check_maintenance and is_maintenance_mode(self.db):
            return (
                False,
                "System is in maintenance mode. New backups are disabled.",
                503,
            )

        # Validate VM exists
        vm = self.db.query(VM).filter(VM.id == vm_id).first()
        if not vm:
            return False, "VM not found", 404
        from core.backup_admission_pause import new_backup_admission_paused

        try:
            paused = new_backup_admission_paused(self.db)
        except ValueError:
            return (
                False,
                {
                    "code": "backup_admission_policy_unavailable",
                    "message": "The installation's backup admission policy needs review.",
                },
                409,
            )
        if paused:
            return (
                False,
                {
                    "code": "backup_admission_paused",
                    "message": "New backup admissions are paused. Already reserved backups may continue.",
                },
                409,
            )
        if vm.inventory_present is False:
            return (
                False,
                "VM is absent from inventory; historical backups remain available",
                409,
            )
        if (
            vm.provider or (vm.vm_metadata or {}).get("provider")
        ) == "kubevirt" and not vm.vm_uid:
            return (
                False,
                "KubeVirt VM identity is unresolved; refresh inventory before backup",
                409,
            )

        # Check disk eligibility
        eligibility = self.check_disk_eligibility(vm)
        if not eligibility["eligible"]:
            return (
                False,
                f"VM {vm.name} cannot be backed up: {'; '.join(eligibility['warnings'])}",
                422,
            )

        if (vm.provider or (vm.vm_metadata or {}).get("provider")) == "kubevirt":
            from core.agent_scope import source_allowed

            agent = self.db.get(Agent, vm.agent_id)
            if agent is None or not source_allowed(agent, vm.namespace):
                return (
                    False,
                    "Source namespace is outside the applied agent selection; "
                    "upgrade agent scope configuration if unavailable",
                    409,
                )

        # Check for existing running/pending backup
        existing_backup = (
            self.db.query(Backup)
            .filter(Backup.vm_id == vm_id, Backup.status.in_(["running", "pending"]))
            .first()
        )

        if existing_backup:
            return (
                False,
                f"Backup already {existing_backup.status} for VM {vm.name}",
                409,
            )

        # Check max concurrent backups
        if check_concurrent:
            max_concurrent = get_max_concurrent_backups(self.db)
            running_count = (
                self.db.query(Backup).filter(Backup.status == "running").count()
            )
            if running_count >= max_concurrent:
                return (
                    False,
                    f"Maximum concurrent backups ({max_concurrent}) reached. Please wait for a backup to complete.",
                    429,
                )

        return True, None, None

    def create_backup(
        self,
        vm_id: str,
        retention_days: Optional[int] = None,
        backup_type: str = "full",
        tags: Optional[Dict[str, Any]] = None,
        exclude_disks: Optional[List[str]] = None,
        workers: Optional[int] = None,
        schedule_id: Optional[str] = None,
        schedule_name: Optional[str] = None,
        is_bulk_operation: bool = False,
        check_maintenance: bool = True,
        check_concurrent: bool = True,
        queue_item=None,
    ) -> BackupCreateResult:
        """Manual entry point owns commit; composition uses the flush-only helper."""
        result = self._create_backup_flush(
            vm_id,
            retention_days,
            backup_type,
            tags,
            exclude_disks,
            workers,
            schedule_id,
            schedule_name,
            is_bulk_operation,
            check_maintenance,
            check_concurrent,
            queue_item,
        )
        if result.success:
            self.db.commit()
            self.db.refresh(result.backup)
        return result

    def _create_backup_flush(
        self,
        vm_id: str,
        retention_days: Optional[int] = None,
        backup_type: str = "full",
        tags: Optional[Dict[str, Any]] = None,
        exclude_disks: Optional[List[str]] = None,
        workers: Optional[int] = None,
        schedule_id: Optional[str] = None,
        schedule_name: Optional[str] = None,
        is_bulk_operation: bool = False,
        check_maintenance: bool = True,
        check_concurrent: bool = True,
        queue_item=None,
    ) -> BackupCreateResult:
        """
        Create a new backup record.

        Args:
            vm_id: ID of the VM to backup
            retention_days: Days to retain backup (uses default if not specified)
            backup_type: Type of backup ("full" or "incremental")
            tags: Tags to apply to backup
            exclude_disks: List of disks to exclude
            workers: Number of concurrent workers
            schedule_id: ID of schedule (if scheduled backup)
            schedule_name: Name of schedule (if scheduled backup)
            is_bulk_operation: Whether this is part of bulk operation
            check_maintenance: Whether to check maintenance mode
            check_concurrent: Whether to check max concurrent limit

        Returns:
            BackupCreateResult with success status and backup or error
        """
        if queue_item is not None:
            queue_item = (
                self.db.query(BackupQueue)
                .filter(BackupQueue.id == queue_item.id, BackupQueue.vm_id == vm_id)
                .populate_existing()
                .with_for_update()
                .one_or_none()
            )
            if (
                queue_item is None
                or not queue_item.initiating_user_id
                or queue_item.authority_kind != "human"
                or queue_item.scheduler_occurrence_id is not None
            ):
                return BackupCreateResult(
                    success=False,
                    error="Legacy queue authority is held",
                    error_code=423,
                )
            from core.backup_authority import human_authority

            human_authority(queue_item)
            if queue_item.started_backup_id:
                prior = self.db.get(
                    Backup, queue_item.started_backup_id, populate_existing=True
                )
                if (
                    prior is None
                    or prior.vm_id != vm_id
                    or prior.initiating_user_id != queue_item.initiating_user_id
                ):
                    return BackupCreateResult(
                        success=False,
                        error="Queue backup authority is held",
                        error_code=409,
                    )
                return BackupCreateResult(success=True, backup=prior)
        # Check if we can start the backup
        can_start, error, error_code = self.can_start_backup(
            vm_id,
            check_maintenance=check_maintenance,
            check_concurrent=check_concurrent,
        )
        if not can_start:
            return BackupCreateResult(success=False, error=error, error_code=error_code)

        # Get VM for storage path
        vm = self.db.query(VM).filter(VM.id == vm_id).first()

        # Use default retention if not specified
        if retention_days is None or retention_days == 0:
            retention_days = get_default_retention_days(self.db)

        # Build tags
        backup_tags = tags.copy() if tags else {}
        if schedule_id:
            backup_tags["scheduled"] = "true"
            backup_tags["schedule_id"] = schedule_id
            if schedule_name:
                backup_tags["schedule_name"] = schedule_name
        if is_bulk_operation:
            backup_tags["bulk_operation"] = "true"

        return self._insert_backup_flush(
            vm,
            retention_days,
            backup_type,
            backup_tags,
            exclude_disks,
            workers,
            "human",
            queue_item.initiating_user_id if queue_item else identity()[1],
            None,
            queue_item,
        )

    def _insert_backup_flush(
        self,
        vm,
        retention_days,
        backup_type,
        tags,
        exclude_disks,
        workers,
        authority_kind,
        user_id,
        occurrence_id,
        queue_item=None,
        *,
        scheduler_decision=None,
    ):
        """Shared record construction after caller validation; never commits."""
        backup = Backup(
            authority_kind=authority_kind,
            scheduler_occurrence_id=occurrence_id,
            vm_id=vm.id,
            initiating_user_id=user_id,
            status="pending",
            progress=0,
            retention_days=retention_days,
            backup_type=backup_type,
            tags=tags,
            exclude_disks=exclude_disks or [],
            workers=workers,
        )
        self.db.add(backup)
        self.db.flush()

        # Set storage path after we have the backup ID
        storage_base = get_backup_storage_path(self.db)
        backup.storage_path = f"file://{storage_base}/{backup.id}"

        # Resolve incremental chain
        self._resolve_chain(backup, vm.id)

        if queue_item is not None:
            if scheduler_decision is not None:
                if authority_kind != "scheduler":
                    raise ValueError("Automatic decisions require scheduler authority")
                # Do not dirty the queue before the first Backup flush. Its
                # one-time input transition must include the permanent claim.
                queue_item.backup_type = backup_type
                queue_item.backup_decision = deepcopy(scheduler_decision)
            queue_item.started_backup_id = backup.id
            if authority_kind == "scheduler":
                queue_item.status = "claimed"
        self.db.flush()

        logger.info(f"Created backup {backup.id} for VM {vm.name}")

        return BackupCreateResult(success=True, backup=backup)

    def _resolve_chain(self, backup: Backup, vm_id: str) -> None:
        """Set chain_id, parent_backup_id, chain_position on a new backup."""
        if backup.backup_type == "full":
            backup.chain_id = backup.id
            backup.chain_position = 0
            return

        vm = self.db.get(VM, vm_id)
        if vm is not None and vm.provider in {"kubevirt", "libvirt"}:
            # Preserve requested incremental intent. Legacy completed-row/name
            # selection cannot supply transaction/1 lineage or downgrade it.
            # Provider dispatch selects only its current accepted generation;
            # a missing/changed baseline refuses rather than silently going full.
            return

        # Incremental: find latest completed backup for same VM
        parent = (
            self.db.query(Backup)
            .filter(
                Backup.vm_id == vm_id,
                Backup.status == "completed",
                Backup.chain_id.isnot(None),
            )
            .order_by(desc(Backup.created_at))
            .first()
        )

        if parent and (parent.storage_path or "").startswith("s3://"):
            from core.s3_ownership import (
                owned_chain_target,
                storage_identity,
                StorageOwnershipError,
            )
            from core.settings_service import SettingsService

            target = owned_chain_target(self.db, parent)
            reason = None
            if target is None:
                reason = "legacy_uncommitted_or_split_s3_lineage"
            else:
                try:
                    settings_service = SettingsService(self.db)
                    proposed = storage_identity(
                        {
                            "endpoint": settings_service.get("storage.s3.endpoint"),
                            "bucket": settings_service.get("storage.s3.bucket"),
                        }
                    )
                except (StorageOwnershipError, ValueError):
                    proposed = None
                if target != proposed:
                    reason = "s3_target_changed_or_unavailable"
            if reason:
                backup.tags = dict(
                    backup.tags or {},
                    full_required_reason=reason,
                )
                logger.warning(
                    "Backup %s requires a fresh full: %s; existing chain remains read-only",
                    backup.id,
                    reason,
                )
                parent = None

        if parent:
            backup.parent_backup_id = parent.id
            backup.chain_id = parent.chain_id
            backup.chain_position = (parent.chain_position or 0) + 1
        else:
            # No parent found — auto-promote to full
            logger.warning(
                f"No completed chain parent for VM {vm_id}, "
                f"promoting incremental backup {backup.id} to full"
            )
            backup.backup_type = "full"
            backup.chain_id = backup.id
            backup.parent_backup_id = None
            backup.chain_position = 0

    def get_chain(self, chain_id: str) -> List[Backup]:
        """All completed backups in a chain, ordered by chain_position ASC."""
        return (
            self.db.query(Backup)
            .filter(
                Backup.chain_id == chain_id,
                Backup.status == "completed",
            )
            .order_by(Backup.chain_position.asc())
            .all()
        )

    def get_vm_name(self, vm_id: str) -> Optional[str]:
        """Get VM name by ID"""
        vm = self.db.query(VM).filter(VM.id == vm_id).first()
        return vm.name if vm else None
