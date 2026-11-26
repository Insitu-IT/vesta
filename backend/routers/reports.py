"""
Reports & Export endpoints: create, list, get, update, delete, generate, download.
"""

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response, FileResponse
from sqlalchemy.orm import Session
from datetime import datetime
from typing import Optional, List
import os
import logging

from database import get_db
from models import Report, ReportExecution, User
from deps import get_current_user, get_operator_or_admin, log_activity, iso_utc
from schemas import ReportCreate
from core.report_generator import generate_report as generate_report_content

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1", tags=["reports"])

# Valid report types and formats
VALID_REPORT_TYPES = [
    "backup_summary",
    "compliance",
    "health",
    "activity",
    "vm_inventory",
    "schedule_status",
    "failed_backups",
    "storage_usage",
    "agent_health",
    "custom",
]
VALID_FORMATS = ["pdf", "csv", "json", "html"]


@router.post("/reports")
def create_report(
    report_data: ReportCreate,
    current_user: User = Depends(get_operator_or_admin),
    db: Session = Depends(get_db),
):
    """Create a new report configuration"""
    # Validate report type
    if report_data.report_type not in VALID_REPORT_TYPES:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid report type. Must be one of: {', '.join(VALID_REPORT_TYPES)}",
        )

    # Validate format
    if report_data.format not in VALID_FORMATS:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid format. Must be one of: {', '.join(VALID_FORMATS)}",
        )

    report = Report(
        name=report_data.name,
        report_type=report_data.report_type,
        schedule=report_data.schedule,
        format=report_data.format,
        recipients=report_data.recipients or [],
        filters=report_data.filters or {},
        enabled=report_data.enabled,
        created_by=current_user.id,
        created_at=datetime.utcnow(),
    )

    db.add(report)
    db.commit()
    db.refresh(report)

    # Log activity
    log_activity(
        db,
        current_user,
        action="report_created",
        resource_type="report",
        resource_id=report.id,
        details={"name": report_data.name, "report_type": report_data.report_type},
    )

    return {
        "id": report.id,
        "name": report.name,
        "report_type": report.report_type,
        "schedule": report.schedule,
        "format": report.format,
        "recipients": report.recipients,
        "filters": report.filters,
        "enabled": report.enabled,
        "created_at": iso_utc(report.created_at),
    }


@router.get("/reports")
def list_reports(
    report_type: Optional[str] = Query(None),
    enabled: Optional[bool] = Query(None),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """List all reports"""
    query = db.query(Report)

    if report_type:
        query = query.filter(Report.report_type == report_type)
    if enabled is not None:
        query = query.filter(Report.enabled == enabled)

    reports = query.order_by(Report.created_at.desc()).all()

    result = []
    for r in reports:
        user = db.query(User).filter(User.id == r.created_by).first()
        result.append(
            {
                "id": r.id,
                "name": r.name,
                "report_type": r.report_type,
                "schedule": r.schedule,
                "format": r.format,
                "recipients": r.recipients,
                "filters": r.filters,
                "enabled": r.enabled,
                "last_run_at": iso_utc(r.last_run_at),
                "next_run_at": iso_utc(r.next_run_at),
                "created_by_user": (
                    {"id": user.id, "username": user.username} if user else None
                ),
                "created_at": iso_utc(r.created_at),
            }
        )

    return {"reports": result, "total": len(result)}


@router.get("/reports/{report_id}")
def get_report(
    report_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Get a specific report configuration"""
    report = db.query(Report).filter(Report.id == report_id).first()

    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    user = db.query(User).filter(User.id == report.created_by).first()

    # Get most recent completed execution for download
    last_execution = (
        db.query(ReportExecution)
        .filter(
            ReportExecution.report_id == report_id,
            ReportExecution.status == "completed",
        )
        .order_by(ReportExecution.created_at.desc())
        .first()
    )

    return {
        "id": report.id,
        "name": report.name,
        "report_type": report.report_type,
        "schedule": report.schedule,
        "format": report.format,
        "recipients": report.recipients,
        "filters": report.filters,
        "enabled": report.enabled,
        "last_run_at": iso_utc(report.last_run_at),
        "next_run_at": iso_utc(report.next_run_at),
        "last_execution": last_execution.id if last_execution else None,
        "created_by_user": (
            {"id": user.id, "username": user.username, "role": user.role}
            if user
            else None
        ),
        "created_at": iso_utc(report.created_at),
        "updated_at": iso_utc(report.updated_at),
    }


@router.put("/reports/{report_id}")
def update_report(
    report_id: str,
    name: Optional[str] = None,
    schedule: Optional[str] = None,
    format: Optional[str] = None,
    recipients: Optional[List[str]] = None,
    filters: Optional[dict] = None,
    enabled: Optional[bool] = None,
    current_user: User = Depends(get_operator_or_admin),
    db: Session = Depends(get_db),
):
    """Update a report configuration"""
    report = db.query(Report).filter(Report.id == report_id).first()

    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    # Update fields
    if name is not None:
        report.name = name
    if schedule is not None:
        report.schedule = schedule
    if format is not None:
        if format not in ["pdf", "csv", "json", "html"]:
            raise HTTPException(status_code=400, detail="Invalid format")
        report.format = format
    if recipients is not None:
        report.recipients = recipients
    if filters is not None:
        report.filters = filters
    if enabled is not None:
        report.enabled = enabled

    report.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(report)

    # Log activity
    log_activity(
        db,
        current_user,
        action="report_updated",
        resource_type="report",
        resource_id=report_id,
        details={"name": report.name},
    )

    return {
        "id": report.id,
        "name": report.name,
        "report_type": report.report_type,
        "schedule": report.schedule,
        "format": report.format,
        "recipients": report.recipients,
        "filters": report.filters,
        "enabled": report.enabled,
        "updated_at": iso_utc(report.updated_at),
    }


@router.delete("/reports/{report_id}")
def delete_report(
    report_id: str,
    current_user: User = Depends(get_operator_or_admin),
    db: Session = Depends(get_db),
):
    """Delete a report configuration"""
    report = db.query(Report).filter(Report.id == report_id).first()

    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    report_name = report.name

    # Delete associated report executions first
    db.query(ReportExecution).filter(ReportExecution.report_id == report_id).delete()

    db.delete(report)
    db.commit()

    # Log activity
    log_activity(
        db,
        current_user,
        action="report_deleted",
        resource_type="report",
        resource_id=report_id,
        details={"name": report_name},
    )

    return {"message": "Report deleted successfully"}


@router.post("/reports/{report_id}/generate")
def generate_report(
    report_id: str,
    current_user: User = Depends(get_operator_or_admin),
    db: Session = Depends(get_db),
):
    """Generate a report immediately"""
    report = db.query(Report).filter(Report.id == report_id).first()

    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    # Create execution record
    execution = ReportExecution(
        report_id=report_id, status="pending", created_at=datetime.utcnow()
    )
    db.add(execution)
    db.commit()
    db.refresh(execution)

    # Start report generation
    execution.status = "running"
    execution.started_at = datetime.utcnow()
    db.commit()

    try:
        # Generate report using report generator
        content, filename = generate_report_content(report, db)

        # Determine content type
        content_types = {
            "pdf": "application/pdf",
            "csv": "text/csv",
            "json": "application/json",
            "html": "text/html",
        }
        content_type = content_types.get(report.format, "application/octet-stream")

        # Store in database (preferred over filesystem for K8s)
        execution.status = "completed"
        execution.completed_at = datetime.utcnow()
        execution.file_content = content
        execution.file_name = filename
        execution.content_type = content_type
        execution.file_size_bytes = len(content)

    except ValueError as e:
        # Unsupported report type
        execution.status = "failed"
        execution.completed_at = datetime.utcnow()
        execution.error_message = str(e)
        logger.warning(f"Report generation failed: {e}")

    except Exception as e:
        # Other errors
        execution.status = "failed"
        execution.completed_at = datetime.utcnow()
        execution.error_message = f"Report generation error: {str(e)}"
        logger.exception(f"Report generation error for {report_id}: {e}")

    db.commit()
    db.refresh(execution)

    # Update report's last_run_at
    report.last_run_at = datetime.utcnow()
    db.commit()

    # Log activity
    log_activity(
        db,
        current_user,
        action="report_generated",
        resource_type="report",
        resource_id=report_id,
        details={"execution_id": execution.id, "format": report.format},
    )

    result = {
        "execution_id": execution.id,
        "report_id": report_id,
        "status": execution.status,
        "file_path": execution.file_path,
        "started_at": iso_utc(execution.started_at),
        "completed_at": iso_utc(execution.completed_at),
    }

    if execution.file_size_bytes:
        result["file_size_bytes"] = execution.file_size_bytes
        result["file_size_mb"] = round(execution.file_size_bytes / (1024 * 1024), 2)

    if execution.error_message:
        result["error"] = execution.error_message

    return result


@router.get("/reports/{report_id}/executions")
def list_report_executions(
    report_id: str,
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """List execution history for a report"""
    # Verify report exists
    report = db.query(Report).filter(Report.id == report_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    # Get executions
    total = (
        db.query(ReportExecution).filter(ReportExecution.report_id == report_id).count()
    )
    executions = (
        db.query(ReportExecution)
        .filter(ReportExecution.report_id == report_id)
        .order_by(ReportExecution.created_at.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )

    return {
        "report_id": report_id,
        "report_name": report.name,
        "executions": [
            {
                "id": e.id,
                "status": e.status,
                "file_path": e.file_path,
                "file_size_bytes": e.file_size_bytes,
                "file_size_mb": (
                    round(e.file_size_bytes / (1024 * 1024), 2)
                    if e.file_size_bytes
                    else 0
                ),
                "error_message": e.error_message,
                "started_at": iso_utc(e.started_at),
                "completed_at": iso_utc(e.completed_at),
                "created_at": iso_utc(e.created_at),
            }
            for e in executions
        ],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.get("/report-executions/{execution_id}")
def get_report_execution(
    execution_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Get details of a specific report execution"""
    execution = (
        db.query(ReportExecution).filter(ReportExecution.id == execution_id).first()
    )

    if not execution:
        raise HTTPException(status_code=404, detail="Report execution not found")

    report = db.query(Report).filter(Report.id == execution.report_id).first()

    return {
        "id": execution.id,
        "report_id": execution.report_id,
        "report_name": report.name if report else "Unknown",
        "status": execution.status,
        "file_path": execution.file_path,
        "file_size_bytes": execution.file_size_bytes,
        "file_size_mb": (
            round(execution.file_size_bytes / (1024 * 1024), 2)
            if execution.file_size_bytes
            else 0
        ),
        "error_message": execution.error_message,
        "started_at": iso_utc(execution.started_at),
        "completed_at": iso_utc(execution.completed_at),
        "created_at": iso_utc(execution.created_at),
    }


@router.get("/report-executions/{execution_id}/download")
def download_report(
    execution_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Download a generated report file"""
    execution = (
        db.query(ReportExecution).filter(ReportExecution.id == execution_id).first()
    )

    if not execution:
        raise HTTPException(status_code=404, detail="Report execution not found")

    if execution.status != "completed":
        raise HTTPException(
            status_code=400, detail=f"Report is not ready (status: {execution.status})"
        )

    # Prefer database storage, fall back to file path for legacy
    if execution.file_content:
        # Serve from database
        filename = execution.file_name or f"report_{execution_id}"
        content_type = execution.content_type or "application/octet-stream"
        return Response(
            content=execution.file_content,
            media_type=content_type,
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )
    elif execution.file_path and os.path.exists(execution.file_path):
        # Legacy: serve from file system
        report = db.query(Report).filter(Report.id == execution.report_id).first()
        filename = os.path.basename(execution.file_path)
        media_types = {
            "pdf": "application/pdf",
            "csv": "text/csv",
            "json": "application/json",
            "html": "text/html",
        }
        report_format = report.format if report else "pdf"
        media_type = media_types.get(report_format, "application/octet-stream")
        return FileResponse(
            path=execution.file_path, filename=filename, media_type=media_type
        )
    else:
        raise HTTPException(status_code=404, detail="Report file not found")
