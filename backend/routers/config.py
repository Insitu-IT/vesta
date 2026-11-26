"""
Configuration and settings endpoints.
"""

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session
from datetime import datetime
from typing import Optional
import json
import logging

from models import SystemSettings, User
from deps import get_installation_admin, get_installation_db, log_activity, iso_utc
from core.settings_reader import get_setting, invalidate_cache
from core.settings_service import SettingsService, is_encryption_configured

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1", tags=["config"])


@router.get("/settings")
async def get_settings(
    category: Optional[str] = None,
    current_user=Depends(get_installation_admin),
    db: Session = Depends(get_installation_db),
):
    """Get system settings"""

    query = db.query(SystemSettings)
    if category:
        query = query.filter(SystemSettings.category == category)

    settings = query.all()

    result = {}
    for setting in settings:
        parsed_value = setting.value
        if setting.value_type == "integer" and setting.value:
            parsed_value = int(setting.value)
        elif setting.value_type == "boolean" and setting.value:
            parsed_value = setting.value.lower() == "true"
        elif setting.value_type == "json" and setting.value:
            parsed_value = json.loads(setting.value)

        result[setting.key] = parsed_value

    return {"settings": result}


@router.put("/settings")
async def update_settings_bulk(
    settings_data: dict,
    current_user=Depends(get_installation_admin),
    db: Session = Depends(get_installation_db),
):
    """Update multiple system settings at once"""

    KEY_CATEGORY_MAP = {
        "maintenance_mode": "general",
        "log_level": "general",
        "default_retention_days": "backup",
        "max_concurrent_backups": "backup",
        "compression_level": "backup",
        "verify_backups": "backup",
        "auto_cleanup": "backup",
        "retention_hour": "backup",
        "sustained_failure_threshold": "backup",
        "storage_backend": "storage",
        "storage_path": "storage",
        "backup_storage_path": "storage",
        "min_free_space_gb": "storage",
        "email_notifications": "notifications",
        "email_enabled": "notifications",
        "smtp_server": "notifications",
        "smtp_port": "notifications",
        "smtp_username": "notifications",
        "smtp_password": "notifications",
        "smtp_from": "notifications",
        "smtp_use_tls": "notifications",
        "notification_emails": "notifications",
        "notification_recipients": "notifications",
        "notify_on_success": "notifications",
        "notify_on_failure": "notifications",
        "notify_agent_offline": "notifications",
        "session_timeout_minutes": "security",
        "password_min_length": "security",
        "require_password_complexity": "security",
        "force_password_change": "security",
        "max_login_attempts": "security",
        "audit_logging": "security",
        "rate_limit_per_minute": "api",
        "cors_origins": "api",
        "api_docs_enabled": "api",
    }

    updated_count = 0
    for key, value in settings_data.items():
        setting = db.query(SystemSettings).filter(SystemSettings.key == key).first()

        if not setting:
            category = KEY_CATEGORY_MAP.get(key, "general")
            value_type = "string"

            if isinstance(value, bool):
                value_type = "boolean"
            elif isinstance(value, int):
                value_type = "integer"

            setting = SystemSettings(
                category=category,
                key=key,
                value=(
                    str(value)
                    if not isinstance(value, bool)
                    else ("true" if value else "false")
                ),
                value_type=value_type,
                updated_by=current_user.id,
            )
            db.add(setting)
        else:
            if isinstance(value, bool):
                setting.value = "true" if value else "false"
            elif isinstance(value, int):
                setting.value = str(value)
            else:
                setting.value = str(value)

            setting.updated_by = current_user.id
            setting.updated_at = datetime.utcnow()

        updated_count += 1

    db.commit()
    invalidate_cache()

    # If the retention run-hour changed, reschedule the daily job in place so the
    # change takes effect without a backend restart (#29). Lazy import breaks the
    # app<->router import cycle; the enable-toggle (auto_cleanup) needs no reschedule
    # since the job always runs daily and enforce_all() checks the toggle at run time.
    if "retention_hour" in settings_data:
        try:
            from app import reschedule_retention_job

            reschedule_retention_job(
                get_setting("backup", "retention_hour", 3, "integer", db)
            )
        except Exception:
            logger.exception("Failed to reschedule retention job after settings change")

    log_activity(
        db,
        current_user,
        action="settings_updated",
        resource_type="settings",
        resource_id=None,
        details={"count": updated_count, "keys": list(settings_data.keys())},
    )

    return {
        "message": f"Updated {updated_count} settings",
        "updated_count": updated_count,
    }


# V3 SETTINGS ENDPOINTS (S3 + OIDC)
# NOTE: These must be defined BEFORE /settings/{setting_id} to avoid route conflict


@router.get("/settings/v3")
async def get_settings_v3(
    current_user=Depends(get_installation_admin),
    db: Session = Depends(get_installation_db),
):
    """Get v3 settings (storage and OIDC config) with secret status."""

    svc = SettingsService(db)

    return {
        "settings": svc.get_all(),
        "secrets": svc.get_secret_status(),
        "encryption_configured": is_encryption_configured(),
    }


async def settings_patch_body(
    request: Request, current_user=Depends(get_installation_admin)
):
    """Resolve installation authority before decoding potentially sensitive input."""
    try:
        value = await request.json()
    except (ValueError, TypeError):
        raise HTTPException(400, "Invalid settings configuration") from None
    if type(value) is not dict:
        raise HTTPException(400, "Invalid settings configuration")
    return value


@router.put("/settings/v3")
async def update_settings_v3(
    settings_data: dict = Depends(settings_patch_body),
    current_user=Depends(get_installation_admin),
    db: Session = Depends(get_installation_db),
):
    """Update v3 settings (storage and OIDC config)."""

    svc = SettingsService(db)
    updated_settings = []
    updated_secrets = []

    # All writes here are database-backed, including locally encrypted secrets.
    # Helpers flush only; this endpoint owns the single final commit with audit.
    try:
        try:
            settings_data = svc.validate_update(settings_data)
        except (ValueError, TypeError):
            raise HTTPException(400, "Invalid settings configuration") from None
        # Audit's user FK must precede the configuration statement lock. A
        # backup admission may hold this user while waiting for configuration.
        db.query(User.id).filter(User.id == current_user.id).with_for_update(
            read=True, key_share=True
        ).one()
        for key, value in settings_data.items():
            if key in SettingsService.DEFINITIONS:
                svc.set(key, value, updated_by=current_user.username, commit=False)
                updated_settings.append(key)
            elif key in SettingsService.SECRET_DEFINITIONS:
                if value:
                    if not is_encryption_configured():
                        raise HTTPException(
                            status_code=400,
                            detail="Configure the installation encryption key before saving credentials",
                        )
                    svc.set_secret(key, value, commit=False)
                    updated_secrets.append(key)

        log_activity(
            db,
            current_user,
            action="v3_settings_updated",
            resource_type="settings_v3",
            resource_id=None,
            details={"settings": updated_settings, "secrets": updated_secrets},
            commit=False,
        )
        db.commit()
    except HTTPException:
        db.rollback()
        raise
    except Exception:
        db.rollback()
        raise HTTPException(500, "Settings update failed") from None

    return {
        "status": "ok",
        "updated_settings": updated_settings,
        "updated_secrets": updated_secrets,
    }


@router.post("/settings/test-s3")
async def test_s3_connection(
    current_user=Depends(get_installation_admin),
    db: Session = Depends(get_installation_db),
):
    """Test S3 connection with current settings."""

    svc = SettingsService(db)
    s3_config = svc.get_s3_config()

    if not s3_config:
        raise HTTPException(
            status_code=400,
            detail="S3 not configured. Set storage.type to 's3' and configure endpoint, bucket, and credentials.",
        )

    try:
        import boto3
        from botocore.exceptions import ClientError, NoCredentialsError  # noqa: F401

        s3 = boto3.client(
            "s3",
            endpoint_url=s3_config["endpoint"],
            aws_access_key_id=s3_config["access_key"],
            aws_secret_access_key=s3_config["secret_key"],
            region_name=s3_config["region"],
        )

        bucket = s3_config["bucket"]
        s3.head_bucket(Bucket=bucket)
        s3.list_objects_v2(Bucket=bucket, MaxKeys=1)

        log_activity(
            db,
            current_user,
            action="s3_connection_test",
            resource_type="settings_v3",
            resource_id="s3",
            details={
                "bucket": bucket,
                "endpoint": s3_config["endpoint"],
                "status": "success",
            },
        )

        return {
            "status": "ok",
            "message": f"Successfully connected to bucket: {bucket}",
            "bucket": bucket,
            "endpoint": s3_config["endpoint"] or "AWS S3",
        }

    except Exception as e:
        if "NoCredentialsError" in str(type(e)):
            raise HTTPException(
                status_code=400, detail="S3 credentials not configured or invalid"
            )
        raise HTTPException(status_code=400, detail=f"S3 connection failed: {str(e)}")


# Legacy settings endpoint - must be AFTER /settings/v3 to avoid route conflict
@router.put("/settings/{setting_id}")
async def update_setting(
    setting_id: str,
    update_data: dict,
    current_user=Depends(get_installation_admin),
    db: Session = Depends(get_installation_db),
):
    """Update a system setting"""

    setting = db.query(SystemSettings).filter(SystemSettings.id == setting_id).first()
    if not setting:
        raise HTTPException(status_code=404, detail="Setting not found")

    new_value = update_data.get("value")
    if new_value is not None:
        if setting.value_type == "integer":
            setting.value = str(int(new_value))
        elif setting.value_type == "boolean":
            setting.value = "true" if new_value else "false"
        elif setting.value_type == "json":
            setting.value = json.dumps(new_value)
        else:
            setting.value = str(new_value)

    setting.updated_by = current_user.id
    setting.updated_at = datetime.utcnow()
    db.commit()

    log_activity(
        db,
        current_user,
        action="setting_updated",
        resource_type="setting",
        resource_id=setting.id,
        details={
            "category": setting.category,
            "key": setting.key,
        },
    )

    return {
        "message": "Setting updated",
        "setting": {"id": setting.id, "key": setting.key, "value": setting.value},
    }


@router.post("/settings/test-email")
async def test_email_settings(
    test_data: dict,
    current_user=Depends(get_installation_admin),
    db: Session = Depends(get_installation_db),
):
    """Test email settings by sending a test email"""

    recipient = test_data.get("recipient", getattr(current_user, "email", None))
    if not recipient:
        raise HTTPException(status_code=400, detail="Recipient email required")

    try:
        from core.notifications import notification_service

        config = {
            "enabled": get_setting(
                "notifications", "email_enabled", False, "boolean", db
            ),
            "server": get_setting("notifications", "smtp_server", "", "string", db),
            "port": get_setting("notifications", "smtp_port", 587, "integer", db),
            "username": get_setting("notifications", "smtp_username", "", "string", db),
            "password": get_setting("notifications", "smtp_password", "", "string", db),
            "from_email": get_setting("notifications", "smtp_from", "", "string", db),
            "use_tls": get_setting(
                "notifications", "smtp_use_tls", True, "boolean", db
            ),
        }

        if not config["enabled"]:
            raise HTTPException(
                status_code=400, detail="Email notifications are disabled"
            )
        if not config["server"]:
            raise HTTPException(status_code=400, detail="SMTP server not configured")
        if not config["from_email"]:
            raise HTTPException(
                status_code=400, detail="SMTP from address not configured"
            )

        success = await notification_service._send_email(
            subject="vnbui Email Test",
            body=f"Test email from vnbui.\n\nSent by: {current_user.username}\nTimestamp: {iso_utc(datetime.utcnow())}",
            recipients=[recipient],
            config=config,
        )

        if not success:
            raise HTTPException(status_code=500, detail="Failed to send email")

        log_activity(
            db,
            current_user,
            action="email_test_sent",
            resource_type="settings",
            resource_id="email",
            details={"recipient": recipient},
        )

        return {"message": "Test email sent successfully", "recipient": recipient}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Failed to send test email: {str(e)}"
        )
