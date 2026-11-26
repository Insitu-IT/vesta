"""
Statistics endpoint for dashboard.
"""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from database import get_db
from models import VM, Backup
from deps import get_current_user

router = APIRouter(prefix="/api/v1", tags=["stats"])


@router.get("/stats")
async def get_stats(
    db: Session = Depends(get_db), current_user=Depends(get_current_user)
):
    """Get system statistics for dashboard"""
    total_vms = db.query(VM).filter(VM.inventory_present.is_(True)).count()
    total_backups = db.query(Backup).count()
    running_backups = db.query(Backup).filter(Backup.status == "running").count()
    completed_backups = db.query(Backup).filter(Backup.status == "completed").count()
    failed_backups = db.query(Backup).filter(Backup.status == "failed").count()

    # Calculate total backup size
    total_size = (
        db.query(Backup)
        .filter(Backup.status == "completed", Backup.size_bytes.isnot(None))
        .all()
    )
    total_size_bytes = sum(b.size_bytes for b in total_size if b.size_bytes)

    return {
        "vms": {"total": total_vms},
        "backups": {
            "total": total_backups,
            "running": running_backups,
            "completed": completed_backups,
            "failed": failed_backups,
        },
        "storage": {
            "total_bytes": total_size_bytes,
            "total_gb": round(total_size_bytes / (1024**3), 2),
        },
    }
