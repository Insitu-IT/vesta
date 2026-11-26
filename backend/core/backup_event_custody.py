"""Generic VM/job events cannot supply transactional backup authority."""

from models import Backup


def generic_event_backups(db):
    """Lock only predecessor rows with no modern authority or producer custody.

    Filter and lock are one statement. SKIP LOCKED avoids waiting on admission
    or publication from the heartbeat loop; a skipped observation can never
    authorize an update. The lock remains until the heartbeat transaction ends.
    Modern human/scheduler rows are excluded even before capacity admission.
    Native holds need their own exact-attempt reporting, not this event path.
    """
    return (
        db.query(Backup)
        .filter(
            Backup.authority_kind.is_(None),
            Backup.capacity_state == "unreserved",
            Backup.native_job_intent.is_(None),
            Backup.native_inventory.is_(None),
        )
        .populate_existing()
        .with_for_update(skip_locked=True)
    )
