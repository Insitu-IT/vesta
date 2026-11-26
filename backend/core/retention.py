"""
Backup retention policy enforcement
Automatically cleanup old backups based on retention settings
"""

import logging
from datetime import datetime, timedelta
from sqlalchemy.orm import Session

from database import SessionLocal
from models import Backup
from .settings_reader import get_setting
from .backup_deletion import BackupDeletionError, backup_deletion_service

logger = logging.getLogger(__name__)


class RetentionPolicyEnforcer:
    """
    Enforces backup retention policies
    Runs as scheduled job to clean up expired backups
    """

    def __init__(self):
        self.dry_run = False  # Set to True for testing

    async def enforce_all(self, *, dry_run=None):
        """
        Enforce retention policies for all backups.
        Chain-aware: a full backup (chain_position=0) is protected as long as
        any non-expired incremental in its chain still exists.
        Called by scheduler (e.g., daily at 3 AM).
        """
        db = SessionLocal()
        effective_dry_run = self.dry_run if dry_run is None else dry_run
        try:
            # Check if auto_cleanup is enabled. Default OFF (#29): retention prune is
            # destructive, so it is opt-in — an unset/absent value must NOT delete.
            auto_cleanup = get_setting("backup", "auto_cleanup", False, "boolean", db)
            if not auto_cleanup:
                logger.info("Auto cleanup is disabled, skipping retention enforcement")
                return {
                    "deleted_count": 0,
                    "deleted_bytes": 0,
                    "dry_run": effective_dry_run,
                    "skipped": True,
                    "reason": "auto_cleanup disabled",
                }

            logger.info("Starting retention policy enforcement")

            # An interrupted exact-receipt deletion keeps its catalog custody.
            # Resume it on the next enabled retention pass, even if its original
            # retention setting has since changed.
            backups = (
                db.query(Backup)
                .filter(Backup.status.in_(("completed", "deleting")))
                .all()
            )
            # Delete chain suffixes before their parents so dependency protection
            # can release a fully-expired chain in one enforcement pass.
            backups.sort(key=lambda item: item.chain_position or 0, reverse=True)

            # Build set of chain_ids that have non-expired members
            protected_chains = set()
            for backup in backups:
                if (
                    backup.status != "deleting"
                    and not self._is_expired(backup)
                    and backup.chain_id
                ):
                    protected_chains.add(backup.chain_id)

            expired_count = 0
            deleted_bytes = 0
            skipped_chain_roots = 0

            for backup in backups:
                if backup.status == "deleting" or self._is_expired(backup):
                    # Protect full backups whose chain has non-expired incrementals
                    if (
                        backup.chain_position == 0
                        and backup.chain_id in protected_chains
                    ):
                        skipped_chain_roots += 1
                        logger.debug(
                            f"Skipping chain root {backup.id} — "
                            f"chain {backup.chain_id} has non-expired members"
                        )
                        continue

                    backup_id = backup.id
                    try:
                        deleted_size = await self._delete_backup(
                            db, backup, dry_run=dry_run
                        )
                        expired_count += 1
                        deleted_bytes += deleted_size

                        logger.info(
                            f"Deleted expired backup {backup.id} "
                            f"(age: {self._get_age_days(backup)} days, "
                            f"retention: {backup.retention_days} days)"
                        )

                    except Exception as e:
                        db.rollback()
                        logger.error(f"Failed to delete backup {backup_id}: {e}")
                        continue

            # Inventory is not deletion authority for a shared-prefix object.
            await self._cleanup_orphaned_manifests(db, protected_chains)

            if skipped_chain_roots:
                logger.info(
                    f"Protected {skipped_chain_roots} chain root backups "
                    f"(non-expired incrementals depend on them)"
                )

            logger.info(
                f"Retention enforcement complete: "
                f"deleted {expired_count} backups, "
                f"freed {deleted_bytes / (1024**3):.2f} GB"
            )

            return {
                "deleted_count": expired_count,
                "deleted_bytes": deleted_bytes,
                "dry_run": effective_dry_run,
            }

        except Exception as e:
            logger.exception(f"Retention enforcement failed: {e}")
            raise
        finally:
            db.close()

    def _is_expired(self, backup: Backup) -> bool:
        """
        Check if backup has exceeded its retention period
        """
        if not backup.retention_days:
            return False  # No retention policy = keep forever

        if not backup.completed_at:
            return False  # Only delete completed backups

        return datetime.utcnow() - backup.completed_at >= timedelta(
            days=backup.retention_days
        )

    def _get_age_days(self, backup: Backup) -> int:
        """Calculate backup age in days"""
        if not backup.completed_at:
            return 0

        age = datetime.utcnow() - backup.completed_at
        return age.days

    async def _delete_backup(self, db: Session, backup: Backup, *, dry_run=None) -> int:
        """Delete exact payload first; retain modern accepted catalog tombstones."""
        if self.dry_run if dry_run is None else dry_run:
            logger.info(f"[DRY RUN] Would delete backup {backup.id}")
            return backup.size_bytes or 0

        deleted_size = await backup_deletion_service.delete_payload(db, backup)
        if backup.status != "deleted":
            raise BackupDeletionError(
                "Deletion did not preserve a deleted catalog tombstone"
            )
        db.commit()
        return deleted_size

    async def _cleanup_orphaned_manifests(self, db, protected_chains: set):
        """Report candidates only; an absent row carries no ownership evidence.

        A tenant-scoped query cannot distinguish its orphan from another
        organization's live chain, disabled organization, or historical data.
        Durable object attribution is required before automated reclamation.
        """
        try:
            from core.settings_service import SettingsService

            svc = SettingsService(db)
            s3_config = svc.get_s3_config()
            if not s3_config:
                return

            prefix = s3_config.get("prefix", "backups").strip("/")
            bucket = s3_config["bucket"]
            manifest_prefix = f"{prefix}/manifests/"

            import boto3

            s3 = boto3.client(
                "s3",
                endpoint_url=s3_config.get("endpoint") or None,
                aws_access_key_id=s3_config.get("access_key"),
                aws_secret_access_key=s3_config.get("secret_key"),
                region_name=s3_config.get("region", "us-east-1"),
            )

            # List all manifests
            paginator = s3.get_paginator("list_objects_v2")
            for page in paginator.paginate(Bucket=bucket, Prefix=manifest_prefix):
                for obj in page.get("Contents", []):
                    key = obj["Key"]
                    # Extract chain_id from key: prefix/manifests/vm_name/chain_id.json
                    filename = key.rsplit("/", 1)[-1]
                    if not filename.endswith(".json"):
                        continue
                    chain_id = filename[:-5]  # Remove .json

                    # Check if any backup still references this chain
                    remaining = (
                        db.query(Backup)
                        .filter(
                            Backup.chain_id == chain_id,
                            Backup.status == "completed",
                        )
                        .count()
                    )

                    if remaining == 0:
                        logger.warning(
                            "Unattributed manifest retained; database absence is not "
                            "deletion authority: s3://%s/%s",
                            bucket,
                            key,
                        )

        except ImportError:
            pass  # boto3 not installed
        except Exception as e:
            logger.warning(f"Failed to cleanup orphaned manifests: {e}")

    async def enforce_for_vm(self, vm_id: str) -> dict:
        """
        Enforce retention for a specific VM.
        Chain-aware: protects full backups while non-expired incrementals exist.
        """
        db = SessionLocal()
        try:
            backups = (
                db.query(Backup)
                .filter(
                    Backup.vm_id == vm_id, Backup.status.in_(("completed", "deleting"))
                )
                .all()
            )
            backups.sort(key=lambda item: item.chain_position or 0, reverse=True)

            # Chain protection: same logic as enforce_all
            protected_chains = set()
            for backup in backups:
                if (
                    backup.status != "deleting"
                    and not self._is_expired(backup)
                    and backup.chain_id
                ):
                    protected_chains.add(backup.chain_id)

            deleted_count = 0
            deleted_bytes = 0

            for backup in backups:
                if backup.status != "deleting" and not self._is_expired(backup):
                    continue
                if backup.chain_position == 0 and backup.chain_id in protected_chains:
                    continue

                backup_id = backup.id
                try:
                    deleted_size = await self._delete_backup(db, backup)
                    deleted_count += 1
                    deleted_bytes += deleted_size
                except Exception as e:
                    db.rollback()
                    logger.error(f"Failed to delete backup {backup_id}: {e}")

            return {
                "vm_id": vm_id,
                "deleted_count": deleted_count,
                "deleted_bytes": deleted_bytes,
            }

        finally:
            db.close()

    async def get_retention_report(self) -> dict:
        """
        Generate report of backups approaching expiration
        """
        db = SessionLocal()
        try:
            backups = db.query(Backup).filter(Backup.status == "completed").all()

            upcoming_expiration = []  # Within 7 days
            expired = []

            for backup in backups:
                if self._is_expired(backup):
                    expired.append(
                        {
                            "backup_id": backup.id,
                            "vm_id": backup.vm_id,
                            "age_days": self._get_age_days(backup),
                            "retention_days": backup.retention_days,
                            "size_bytes": backup.size_bytes,
                        }
                    )
                elif backup.retention_days:
                    days_until_expiration = backup.retention_days - self._get_age_days(
                        backup
                    )
                    if 0 < days_until_expiration <= 7:
                        upcoming_expiration.append(
                            {
                                "backup_id": backup.id,
                                "vm_id": backup.vm_id,
                                "days_until_expiration": days_until_expiration,
                                "size_bytes": backup.size_bytes,
                            }
                        )

            return {
                "expired_backups": expired,
                "upcoming_expiration": upcoming_expiration,
                "total_expired_bytes": sum(b["size_bytes"] or 0 for b in expired),
            }

        finally:
            db.close()


# Global instance
retention_enforcer = RetentionPolicyEnforcer()
