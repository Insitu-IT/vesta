"""
Unified Settings Reader

Provides consistent access to application settings with fallback chain:
1. SystemSettings table (runtime-editable via UI)
2. Environment variables (deployment config)
3. Default values

Usage:
    from core.settings_reader import get_setting

    # Get a string setting
    smtp_server = get_setting("notifications", "smtp_server", "")

    # Get an integer setting
    max_backups = get_setting("backup", "max_concurrent_backups", 3, "integer")

    # Get a boolean setting
    maintenance = get_setting("general", "maintenance_mode", False, "boolean")
"""

import json
import logging
import os
from datetime import datetime, timedelta
from typing import Any, Dict, Optional

from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)

# Cache TTL in seconds
CACHE_TTL = 60

# Cache storage
_settings_cache: Dict[str, Any] = {}
_cache_timestamp: Optional[datetime] = None


# ENV variable mapping: (category, key) -> ENV_VAR_NAME
ENV_MAPPING = {
    # General
    ("general", "maintenance_mode"): "MAINTENANCE_MODE",
    ("general", "log_level"): "LOG_LEVEL",
    # Backup
    ("backup", "max_concurrent_backups"): "MAX_CONCURRENT_BACKUPS",
    ("backup", "default_retention_days"): "BACKUP_RETENTION_DAYS",
    ("backup", "compression_level"): "BACKUP_COMPRESSION_LEVEL",
    ("backup", "verify_backups"): "VERIFY_BACKUPS",
    ("backup", "auto_cleanup"): "AUTO_CLEANUP",
    ("backup", "retention_hour"): "RETENTION_HOUR",
    ("backup", "sustained_failure_threshold"): "SUSTAINED_FAILURE_THRESHOLD",
    # Storage
    ("storage", "backup_storage_path"): "BACKUP_STORAGE_PATH",
    ("storage", "storage_backend"): "STORAGE_BACKEND",
    ("storage", "min_free_space_gb"): "MIN_FREE_SPACE_GB",
    # Notifications
    ("notifications", "email_enabled"): "EMAIL_NOTIFICATIONS_ENABLED",
    ("notifications", "smtp_server"): "SMTP_SERVER",
    ("notifications", "smtp_port"): "SMTP_PORT",
    ("notifications", "smtp_username"): "SMTP_USERNAME",
    ("notifications", "smtp_password"): "SMTP_PASSWORD",
    ("notifications", "smtp_from"): "SMTP_FROM",
    ("notifications", "smtp_use_tls"): "SMTP_USE_TLS",
    ("notifications", "notification_recipients"): "NOTIFICATION_RECIPIENTS",
    ("notifications", "notify_on_success"): "NOTIFY_ON_SUCCESS",
    ("notifications", "notify_on_failure"): "NOTIFY_ON_FAILURE",
    ("notifications", "notify_agent_offline"): "NOTIFY_AGENT_OFFLINE",
    # Security
    ("security", "session_timeout_minutes"): "SESSION_TIMEOUT_MINUTES",
    ("security", "password_min_length"): "PASSWORD_MIN_LENGTH",
    ("security", "require_password_complexity"): "REQUIRE_PASSWORD_COMPLEXITY",
    ("security", "force_password_change"): "FORCE_PASSWORD_CHANGE",
    ("security", "max_login_attempts"): "MAX_LOGIN_ATTEMPTS",
    ("security", "audit_logging"): "AUDIT_LOGGING",
    # API
    ("api", "rate_limit_per_minute"): "RATE_LIMIT_PER_MINUTE",
    ("api", "cors_origins"): "CORS_ORIGINS",
    ("api", "api_docs_enabled"): "API_DOCS_ENABLED",
}

# Default values for all settings
DEFAULTS = {
    # General
    ("general", "maintenance_mode"): False,
    ("general", "log_level"): "INFO",
    # Backup
    ("backup", "max_concurrent_backups"): 20,
    ("backup", "default_retention_days"): 30,
    ("backup", "compression_level"): "balanced",
    ("backup", "verify_backups"): True,
    # auto_cleanup default OFF (#29): retention prune is destructive → opt-in.
    ("backup", "auto_cleanup"): False,
    ("backup", "retention_hour"): 3,
    # Alert after this many consecutive failed backups for a VM (#41); 0 or 1 disables.
    ("backup", "sustained_failure_threshold"): 3,
    # Storage
    ("storage", "backup_storage_path"): "/var/lib/vnbui/backups",
    ("storage", "storage_backend"): "local",
    ("storage", "min_free_space_gb"): 50,
    # Notifications
    ("notifications", "email_enabled"): False,
    ("notifications", "smtp_server"): "",
    ("notifications", "smtp_port"): 587,
    ("notifications", "smtp_username"): "",
    ("notifications", "smtp_password"): "",
    ("notifications", "smtp_from"): "",
    ("notifications", "smtp_use_tls"): True,
    ("notifications", "notification_recipients"): "",
    ("notifications", "notify_on_success"): False,
    ("notifications", "notify_on_failure"): True,
    ("notifications", "notify_agent_offline"): True,
    # Security
    ("security", "session_timeout_minutes"): 60,
    ("security", "password_min_length"): 8,
    ("security", "require_password_complexity"): True,
    ("security", "force_password_change"): False,
    ("security", "max_login_attempts"): 5,
    ("security", "audit_logging"): True,
    # API
    ("api", "rate_limit_per_minute"): 100,
    ("api", "cors_origins"): "http://localhost:3000",
    ("api", "api_docs_enabled"): True,
}


def _is_cache_valid() -> bool:
    """Check if cache is still valid"""
    if _cache_timestamp is None:
        return False
    return datetime.utcnow() - _cache_timestamp < timedelta(seconds=CACHE_TTL)


def _refresh_cache(db: Session) -> None:
    """Refresh settings cache from database"""
    global _settings_cache, _cache_timestamp

    try:
        from models import SystemSettings

        from core.installation_config import read_configuration

        settings = read_configuration(db, SystemSettings)
        _settings_cache = {}

        for setting in settings:
            cache_key = f"{setting.category}:{setting.key}"
            _settings_cache[cache_key] = {
                "value": setting.value,
                "value_type": setting.value_type or "string",
            }

        _cache_timestamp = datetime.utcnow()
        logger.debug(f"Settings cache refreshed with {len(settings)} entries")

    except Exception as e:
        logger.warning(f"Failed to refresh settings cache: {e}")
        _settings_cache = {}
        _cache_timestamp = datetime.utcnow()


def invalidate_cache() -> None:
    """Invalidate the settings cache (call after updating settings)"""
    global _cache_timestamp
    _cache_timestamp = None
    logger.debug("Settings cache invalidated")


def _convert_value(value: str, value_type: str) -> Any:
    """Convert string value to appropriate type"""
    if value is None:
        return None

    if value_type == "boolean":
        if isinstance(value, bool):
            return value
        return str(value).lower() in ("true", "1", "yes", "on")

    elif value_type == "integer":
        try:
            return int(value)
        except (ValueError, TypeError):
            return None

    elif value_type == "json":
        if isinstance(value, (dict, list)):
            return value
        try:
            return json.loads(value)
        except (json.JSONDecodeError, TypeError):
            return None

    else:  # string
        return str(value) if value is not None else ""


def _get_value_type(category: str, key: str, default: Any) -> str:
    """Infer value type from default value"""
    if isinstance(default, bool):
        return "boolean"
    elif isinstance(default, int):
        return "integer"
    elif isinstance(default, (dict, list)):
        return "json"
    return "string"


def get_setting(
    category: str,
    key: str,
    default: Any = None,
    value_type: Optional[str] = None,
    db: Optional[Session] = None,
) -> Any:
    """
    Get a setting value with fallback chain: DB -> ENV -> default

    Args:
        category: Setting category (general, backup, storage, notifications, security, api)
        key: Setting key within category
        default: Default value if not found anywhere
        value_type: Type hint (string, integer, boolean, json) - inferred from default if not provided
        db: Optional database session (creates new one if not provided)

    Returns:
        Setting value converted to appropriate type
    """
    # Infer value type from default if not provided
    if value_type is None:
        value_type = _get_value_type(category, key, default)

    # Use provided default or look up in DEFAULTS
    if default is None:
        default = DEFAULTS.get((category, key))

    cache_key = f"{category}:{key}"

    # Try database first
    if db is not None:
        if not _is_cache_valid():
            _refresh_cache(db)

        if cache_key in _settings_cache:
            cached = _settings_cache[cache_key]
            value = cached["value"]
            if value is not None and value != "":
                return _convert_value(value, value_type)

    # Try environment variable
    env_var = ENV_MAPPING.get((category, key))
    if env_var:
        env_value = os.getenv(env_var)
        if env_value is not None and env_value != "":
            return _convert_value(env_value, value_type)

    # Return default
    return default


def get_setting_with_db(
    category: str, key: str, default: Any = None, value_type: Optional[str] = None
) -> Any:
    """
    Get a setting value, creating a DB session if needed

    Use this for standalone calls outside request context.
    For calls within a request, pass the existing db session to get_setting().
    """
    from database import SessionLocal

    db = SessionLocal()
    try:
        return get_setting(category, key, default, value_type, db)
    finally:
        db.close()


def get_all_settings(db: Session) -> Dict[str, Any]:
    """
    Get all settings as a flat dictionary

    Used by GET /api/v1/settings endpoint
    """
    if not _is_cache_valid():
        _refresh_cache(db)

    result = {}

    # Start with defaults
    for (category, key), default_value in DEFAULTS.items():
        result[key] = default_value

    # Override with ENV values
    for (category, key), env_var in ENV_MAPPING.items():
        env_value = os.getenv(env_var)
        if env_value is not None and env_value != "":
            value_type = _get_value_type(category, key, DEFAULTS.get((category, key)))
            result[key] = _convert_value(env_value, value_type)

    # Override with DB values
    for cache_key, cached in _settings_cache.items():
        _, key = cache_key.split(":", 1)
        if cached["value"] is not None and cached["value"] != "":
            result[key] = _convert_value(
                cached["value"], cached.get("value_type", "string")
            )

    return result


# Convenience functions for commonly used settings


def is_maintenance_mode(db: Optional[Session] = None) -> bool:
    """Check if system is in maintenance mode"""
    if db:
        return get_setting("general", "maintenance_mode", False, "boolean", db)
    return get_setting_with_db("general", "maintenance_mode", False, "boolean")


def get_max_concurrent_backups(db: Optional[Session] = None) -> int:
    """Get maximum concurrent backups allowed"""
    if db:
        return get_setting("backup", "max_concurrent_backups", 3, "integer", db)
    return get_setting_with_db("backup", "max_concurrent_backups", 3, "integer")


def get_default_retention_days(db: Optional[Session] = None) -> int:
    """Get default backup retention period in days"""
    if db:
        return get_setting("backup", "default_retention_days", 30, "integer", db)
    return get_setting_with_db("backup", "default_retention_days", 30, "integer")


def get_sustained_failure_threshold(db: Optional[Session] = None) -> int:
    """Consecutive failed backups for a VM before a backup_failing_sustained alert (#41).

    <= 1 disables the distinct sustained-failure event — a single failure is already
    covered by the per-failure backup_failed event.
    """
    if db:
        return get_setting("backup", "sustained_failure_threshold", 3, "integer", db)
    return get_setting_with_db("backup", "sustained_failure_threshold", 3, "integer")


def get_backup_storage_path(db: Optional[Session] = None) -> str:
    """Get backup storage path.

    Checks v3 settings (storage.path) first, then legacy SystemSettings.
    """
    if db:
        from core.settings_service import SettingsService

        svc = SettingsService(db)
        v3_path = svc.get("storage.path")
        if v3_path:
            return v3_path
    return get_setting(
        "storage", "backup_storage_path", "/var/lib/vnbui/backups", "string", db
    )


def get_compression_level(db: Optional[Session] = None) -> str:
    """Get backup compression level"""
    if db:
        return get_setting("backup", "compression_level", "balanced", "string", db)
    return get_setting_with_db("backup", "compression_level", "balanced", "string")


def is_audit_logging_enabled(db: Optional[Session] = None) -> bool:
    """Check if audit logging is enabled"""
    if db:
        return get_setting("security", "audit_logging", True, "boolean", db)
    return get_setting_with_db("security", "audit_logging", True, "boolean")


def get_session_timeout_minutes(db: Optional[Session] = None) -> int:
    """Get session timeout in minutes"""
    if db:
        return get_setting("security", "session_timeout_minutes", 60, "integer", db)
    return get_setting_with_db("security", "session_timeout_minutes", 60, "integer")
