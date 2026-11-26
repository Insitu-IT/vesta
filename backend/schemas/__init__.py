"""
Pydantic schemas for API request/response models.
"""

from schemas.models import (
    # Backup schemas
    BackupCreate,
    BackupQueueCreate,
    BackupResponse,
    PaginatedResponse,
    BulkBackupCreate,
    BulkBackupDelete,
    BulkBackupTag,
    # VM Group schemas
    VMGroupCreate,
    VMGroupUpdate,
    VMGroupAddVMs,
    # User schemas
    UserCreate,
    UserUpdate,
    # Schedule schemas
    ScheduleCreate,
    ScheduleUpdate,
    # Report schemas
    ReportCreate,
    # API Key schemas
    OrchestratorAPIKeyCreate,
    OrchestratorAPIKeyUpdate,
    AgentRegistrationKeyCreate,
    AgentRegistrationKeyUpdate,
    AgentAPIKeyRotate,
    # Agent schemas
    AgentUpdateRequest,
    AgentSettingsUpdate,
)

__all__ = [
    "BackupCreate",
    "BackupQueueCreate",
    "BackupResponse",
    "PaginatedResponse",
    "BulkBackupCreate",
    "BulkBackupDelete",
    "BulkBackupTag",
    "VMGroupCreate",
    "VMGroupUpdate",
    "VMGroupAddVMs",
    "UserCreate",
    "UserUpdate",
    "ScheduleCreate",
    "ScheduleUpdate",
    "ReportCreate",
    "OrchestratorAPIKeyCreate",
    "OrchestratorAPIKeyUpdate",
    "AgentRegistrationKeyCreate",
    "AgentRegistrationKeyUpdate",
    "AgentAPIKeyRotate",
    "AgentUpdateRequest",
    "AgentSettingsUpdate",
]
