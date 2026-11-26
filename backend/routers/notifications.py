"""
Email notification rules and testing endpoints.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from datetime import datetime
from typing import Optional

from database import get_db
from models import NotificationRule, NotificationLog
from deps import get_current_user, get_admin_user, check_role, log_activity, iso_utc
from deps import get_installation_admin, get_installation_db

router = APIRouter(prefix="/api/v1", tags=["notifications"])


@router.post("/notifications/rules", status_code=status.HTTP_201_CREATED)
async def create_notification_rule(
    rule_data: dict,
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Create a notification rule"""
    check_role(current_user, ["admin", "operator"])

    rule = NotificationRule(
        name=rule_data.get("name"),
        event_type=rule_data.get("event_type"),
        enabled=rule_data.get("enabled", True),
        notification_type=rule_data.get("notification_type", "email"),
        recipients=rule_data.get("recipients", []),
        conditions=rule_data.get("conditions", {}),
        template=rule_data.get("template"),
        created_by=current_user.id,
    )

    db.add(rule)
    db.commit()
    db.refresh(rule)

    log_activity(
        db,
        current_user,
        action="notification_rule_created",
        resource_type="notification_rule",
        resource_id=rule.id,
        details={"name": rule.name, "event_type": rule.event_type},
    )

    return {
        "id": rule.id,
        "name": rule.name,
        "event_type": rule.event_type,
        "enabled": rule.enabled,
        "recipients": rule.recipients,
        "created_at": iso_utc(rule.created_at),
    }


@router.get("/notifications/rules")
async def list_notification_rules(
    event_type: Optional[str] = None,
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """List notification rules"""
    query = db.query(NotificationRule)
    if event_type:
        query = query.filter(NotificationRule.event_type == event_type)

    rules = query.order_by(NotificationRule.created_at.desc()).all()

    return [
        {
            "id": rule.id,
            "name": rule.name,
            "event_type": rule.event_type,
            "enabled": rule.enabled,
            "notification_type": rule.notification_type,
            "recipients": rule.recipients,
            "created_at": iso_utc(rule.created_at),
        }
        for rule in rules
    ]


@router.get("/notifications/rules/{rule_id}")
async def get_notification_rule(
    rule_id: str, current_user=Depends(get_current_user), db: Session = Depends(get_db)
):
    """Get notification rule details"""
    rule = db.query(NotificationRule).filter(NotificationRule.id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=404, detail="Notification rule not found")

    return {
        "id": rule.id,
        "name": rule.name,
        "event_type": rule.event_type,
        "enabled": rule.enabled,
        "notification_type": rule.notification_type,
        "recipients": rule.recipients,
        "conditions": rule.conditions,
        "template": rule.template,
        "created_at": iso_utc(rule.created_at),
    }


@router.put("/notifications/rules/{rule_id}")
async def update_notification_rule(
    rule_id: str,
    rule_data: dict,
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Update notification rule"""
    check_role(current_user, ["admin", "operator"])

    rule = db.query(NotificationRule).filter(NotificationRule.id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=404, detail="Notification rule not found")

    for key in [
        "name",
        "event_type",
        "enabled",
        "notification_type",
        "recipients",
        "conditions",
        "template",
    ]:
        if key in rule_data:
            setattr(rule, key, rule_data[key])

    rule.updated_at = datetime.utcnow()
    db.commit()

    log_activity(
        db,
        current_user,
        action="notification_rule_updated",
        resource_type="notification_rule",
        resource_id=rule.id,
        details={"name": rule.name},
    )

    return {"message": "Notification rule updated", "id": rule.id}


@router.delete("/notifications/rules/{rule_id}")
async def delete_notification_rule(
    rule_id: str, current_user=Depends(get_current_user), db: Session = Depends(get_db)
):
    """Delete notification rule"""
    check_role(current_user, ["admin", "operator"])

    rule = db.query(NotificationRule).filter(NotificationRule.id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=404, detail="Notification rule not found")

    db.delete(rule)
    db.commit()

    log_activity(
        db,
        current_user,
        action="notification_rule_deleted",
        resource_type="notification_rule",
        resource_id=rule_id,
        details={"name": rule.name},
    )

    return {"message": "Notification rule deleted"}


@router.get("/notifications/logs")
async def list_notification_logs(
    skip: int = 0,
    limit: int = 50,
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """List notification logs"""
    total = db.query(NotificationLog).count()
    logs = (
        db.query(NotificationLog)
        .order_by(NotificationLog.sent_at.desc())
        .offset(skip)
        .limit(limit)
        .all()
    )

    return {
        "items": [
            {
                "id": log.id,
                "rule_id": log.rule_id,
                "event_type": log.event_type,
                "recipient": log.recipient,
                "subject": log.subject,
                "status": log.status,
                "created_at": iso_utc(log.sent_at),
            }
            for log in logs
        ],
        "total": total,
        "skip": skip,
        "limit": limit,
    }


@router.post("/notifications/test")
async def test_notification(
    test_data: dict, admin_user=Depends(get_admin_user), db: Session = Depends(get_db)
):
    """
    Send a test notification email (admin only).

    Validates SMTP configuration by sending a test email to the specified recipient.
    """
    from core.notifications import notification_service
    from core.settings_reader import get_setting

    recipient = test_data.get("recipient")
    if not recipient:
        raise HTTPException(status_code=400, detail="Recipient email required")

    # Get SMTP config
    config = {
        "enabled": get_setting("notifications", "email_enabled", False, "boolean", db),
        "server": get_setting("notifications", "smtp_server", "", "string", db),
        "port": get_setting("notifications", "smtp_port", 587, "integer", db),
        "username": get_setting("notifications", "smtp_username", "", "string", db),
        "password": get_setting("notifications", "smtp_password", "", "string", db),
        "from_email": get_setting("notifications", "smtp_from", "", "string", db),
        "use_tls": get_setting("notifications", "smtp_use_tls", True, "boolean", db),
    }

    if not config["enabled"]:
        raise HTTPException(status_code=400, detail="Email notifications are disabled")
    if not config["server"]:
        raise HTTPException(status_code=400, detail="SMTP server not configured")
    if not config["from_email"]:
        raise HTTPException(status_code=400, detail="SMTP from address not configured")

    try:
        success = await notification_service._send_email(
            subject="vnbui Test Notification",
            body=(
                f"This is a test notification from vnbui backup system.\n\n"
                f"Sent by: {admin_user.username}\n"
                f"Timestamp: {iso_utc(datetime.utcnow())}"
            ),
            recipients=[recipient],
            config=config,
        )

        if not success:
            raise HTTPException(status_code=500, detail="Failed to send notification")

        log_activity(
            db,
            admin_user,
            action="notification_test_sent",
            resource_type="notification",
            resource_id=None,
            details={"recipient": recipient},
        )

        return {
            "message": "Test notification sent successfully",
            "recipient": recipient,
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Failed to send notification: {str(e)}"
        )


# --- User-facing notification inbox endpoints ---
# These power the Notifications page (distinct from admin notification rules)


@router.get("/notifications")
async def list_notifications(
    skip: int = 0,
    limit: int = 50,
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """List notifications for the current user (from notification logs)."""
    total = db.query(NotificationLog).count()
    logs = (
        db.query(NotificationLog)
        .order_by(NotificationLog.sent_at.desc())
        .offset(skip)
        .limit(limit)
        .all()
    )

    return {
        "notifications": [
            {
                "id": log.id,
                "type": log.event_type,
                "title": log.subject,
                "message": log.body,
                "status": log.status,
                "read": log.read,
                "created_at": iso_utc(log.sent_at),
            }
            for log in logs
        ],
        "total": total,
    }


@router.get("/notifications/settings")
async def get_notification_settings(
    current_user=Depends(get_installation_admin),
    db: Session = Depends(get_installation_db),
):
    """Get notification preferences for the current user."""
    from core.settings_reader import get_setting

    return {
        "settings": {
            "email_enabled": get_setting(
                "notifications", "email_enabled", False, "boolean", db
            ),
            "backup_success": get_setting(
                "notifications", "notify_backup_success", False, "boolean", db
            ),
            "backup_failure": get_setting(
                "notifications", "notify_backup_failure", True, "boolean", db
            ),
            "agent_offline": get_setting(
                "notifications", "notify_agent_offline", False, "boolean", db
            ),
            "storage_low": get_setting(
                "notifications", "notify_storage_low", False, "boolean", db
            ),
        }
    }


@router.put("/notifications/settings")
async def update_notification_settings(
    settings_data: dict,
    current_user=Depends(get_installation_admin),
    db: Session = Depends(get_installation_db),
):
    """Update notification preferences."""
    from models import SystemSettings

    field_map = {
        "email_enabled": ("notifications", "email_enabled"),
        "backup_success": ("notifications", "notify_backup_success"),
        "backup_failure": ("notifications", "notify_backup_failure"),
        "agent_offline": ("notifications", "notify_agent_offline"),
        "storage_low": ("notifications", "notify_storage_low"),
    }

    for field, (category, key) in field_map.items():
        if field in settings_data:
            val = "true" if settings_data[field] else "false"
            setting = (
                db.query(SystemSettings)
                .filter(SystemSettings.category == category, SystemSettings.key == key)
                .first()
            )
            if setting:
                setting.value = val
                setting.updated_at = datetime.utcnow()
            else:
                setting = SystemSettings(
                    category=category, key=key, value=val, value_type="boolean"
                )
                db.add(setting)
    db.commit()

    return {"status": "ok"}


@router.put("/notifications/{notification_id}/read")
async def mark_notification_read(
    notification_id: str,
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Mark a notification as read."""
    log = (
        db.query(NotificationLog).filter(NotificationLog.id == notification_id).first()
    )
    if not log:
        raise HTTPException(status_code=404, detail="Notification not found")
    log.read = True
    db.commit()
    return {"status": "ok"}


@router.post("/notifications/mark-all-read")
async def mark_all_notifications_read(
    current_user=Depends(get_current_user), db: Session = Depends(get_db)
):
    """Mark all notifications as read."""
    db.query(NotificationLog).filter(
        NotificationLog.read == False  # noqa: E712
    ).update({"read": True})
    db.commit()
    return {"status": "ok"}


@router.delete("/notifications/{notification_id}")
async def delete_notification(
    notification_id: str,
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Delete a notification."""
    log = (
        db.query(NotificationLog).filter(NotificationLog.id == notification_id).first()
    )
    if not log:
        raise HTTPException(status_code=404, detail="Notification not found")
    db.delete(log)
    db.commit()
    return {"status": "ok"}
