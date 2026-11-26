"""
Structured logging configuration
"""

import logging
import sys
from pythonjsonlogger import jsonlogger
from datetime import datetime
import traceback

from config import settings


class CustomJsonFormatter(jsonlogger.JsonFormatter):
    """Custom JSON formatter with additional fields"""

    def add_fields(self, log_record, record, message_dict):
        super().add_fields(log_record, record, message_dict)

        # Add timestamp in ISO format
        log_record["timestamp"] = datetime.utcnow().isoformat()

        # Add level name
        log_record["level"] = record.levelname

        # Add logger name
        log_record["logger"] = record.name

        # Add application info
        log_record["app"] = settings.app_name
        log_record["environment"] = settings.environment

        # Add exception info if present
        if record.exc_info:
            log_record["exception"] = self.formatException(record.exc_info)
            log_record["traceback"] = traceback.format_exc()

        # Add custom fields from extra
        for field in [
            "request_id",
            "user_id",
            "path",
            "method",
            "status_code",
            "duration_ms",
        ]:
            if hasattr(record, field):
                log_record[field] = getattr(record, field)


def setup_logging():
    """Configure application logging"""

    # Clear existing handlers
    root_logger = logging.getLogger()
    root_logger.handlers = []

    # Create handler
    handler = logging.StreamHandler(sys.stdout)

    # Set formatter based on configuration
    if settings.log_format == "json":
        formatter = CustomJsonFormatter("%(timestamp)s %(level)s %(name)s %(message)s")
    else:
        # Human-readable format for development
        formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )

    handler.setFormatter(formatter)

    # Configure root logger
    root_logger.addHandler(handler)
    root_logger.setLevel(getattr(logging, settings.log_level.upper()))

    # Configure specific loggers
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("uvicorn.error").setLevel(logging.INFO)
    logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)

    # Log startup
    logger = logging.getLogger(__name__)
    logger.info(
        "Logging configured",
        extra={
            "log_level": settings.log_level,
            "log_format": settings.log_format,
            "environment": settings.environment,
        },
    )

    return root_logger
