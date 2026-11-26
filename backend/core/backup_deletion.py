"""Exact-receipt deletion; paths and catalog absence never establish ownership."""

from datetime import datetime

from models import Backup


class BackupDeletionError(RuntimeError):
    """Payload deletion failed while its attributable catalog row was retained."""


class BackupDependencyError(RuntimeError):
    """Deletion lacks accepted authority or would invalidate retained work."""


class BackupDeletionService:
    async def delete_payload(self, db, backup: Backup) -> int:
        """Use immutable accepted receipts or refuse before any provider effect."""
        if backup.capacity_state == "legacy_held":
            raise BackupDeletionError(
                "Historical backup custody requires explicit reconciliation; retention cannot infer deletion authority"
            )
        from core.storage_deletion import (
            is_transaction_backup,
            delete_transaction_payload,
        )

        if not is_transaction_backup(db, backup):
            raise BackupDependencyError(
                "Backup has no accepted ownership receipts; "
                "path-based deletion is unsupported and its catalog is retained"
            )
        try:
            return delete_transaction_payload(db, backup.id)
        except BackupDependencyError:
            db.rollback()
            raise
        except Exception as exc:
            db.rollback()
            self._record_error(db, backup, str(exc))
            raise BackupDeletionError(str(exc)) from exc

    @staticmethod
    def _record_error(db, backup: Backup, detail: str) -> None:
        backup.tags = dict(backup.tags or {})
        backup.tags["deletion_error"] = detail[:1000]
        backup.tags["deletion_failed_at"] = datetime.utcnow().isoformat() + "Z"
        db.commit()


backup_deletion_service = BackupDeletionService()
