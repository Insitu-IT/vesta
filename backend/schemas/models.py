"""
Pydantic models for API request/response validation.
"""

from pydantic import BaseModel, Field, ConfigDict, field_validator, model_validator
from typing import Optional, List, Literal
from datetime import datetime
import re

# ============================================================================
# BACKUP SCHEMAS
# ============================================================================


def _unsupported_workers(value):
    if value is not None:
        raise ValueError(
            "Per-backup worker overrides are unsupported; omit workers and use "
            "installation/provider concurrency settings"
        )
    return None


class BackupCloseUnreservedRequest(BaseModel):
    """No caller-supplied proof, force flag or replacement identity is accepted."""

    model_config = ConfigDict(extra="forbid")


class BackupCloseUnreservedResponse(BaseModel):
    backup_id: str
    status: Literal["failed"]
    reason: Literal["pre_dispatch_no_effect"]
    capacity_state: Literal["unreserved"]
    request_id: str


class BackupCreate(BaseModel):
    """Request model for creating backup"""

    vm_id: str
    backup_type: Optional[str] = "full"  # full, incremental, differential
    retention_days: Optional[int] = Field(default=30, ge=1, le=36500)
    tags: Optional[dict] = {}  # Optional tags as key-value pairs
    exclude_disks: Optional[List[str]] = []  # Disks to exclude from backup
    workers: None = Field(
        default=None, description="Per-backup worker overrides are unsupported"
    )
    _validate_workers = field_validator("workers", mode="before")(_unsupported_workers)


class BackupQueueCreate(BaseModel):
    """Request model for adding backup to queue"""

    vm_id: str
    backup_type: Optional[str] = "full"  # full, incremental, differential
    retention_days: int = Field(default=30, ge=1, le=36500)
    tags: Optional[List[str]] = None  # Optional tags
    exclude_disks: Optional[List[str]] = None  # Disks to exclude from backup
    workers: None = Field(
        default=None, description="Per-backup worker overrides are unsupported"
    )
    _validate_workers = field_validator("workers", mode="before")(_unsupported_workers)
    priority: Optional[int] = Field(
        default=0, ge=0, le=100
    )  # Queue priority (0-100, higher = sooner)


class BackupResponse(BaseModel):
    """Response model for backup"""

    id: str
    vm_id: str
    vm_name: str
    status: str
    progress: int
    size_bytes: Optional[int]
    retention_days: int
    tags: dict
    created_at: str
    completed_at: Optional[str]


class PaginatedResponse(BaseModel):
    """Generic paginated response model"""

    items: List[dict]
    total: int
    skip: int
    limit: int
    has_more: bool


class BulkBackupCreate(BaseModel):
    """Request model for bulk backup creation"""

    vm_ids: Optional[List[str]] = None
    filter: Optional[dict] = None  # {search, agent_id, state, group_id}
    retention_days: int = Field(default=30, ge=1, le=36500)
    tags: Optional[dict] = {}
    workers: None = Field(
        default=None, description="Per-backup worker overrides are unsupported"
    )
    _validate_workers = field_validator("workers", mode="before")(_unsupported_workers)


class BulkBackupDelete(BaseModel):
    """Request model for bulk backup deletion"""

    backup_ids: List[str]


class BulkBackupTag(BaseModel):
    """Request model for bulk tagging"""

    backup_ids: List[str]
    tags: dict  # Tags to add/update
    overwrite: bool = False  # If True, replace all tags; if False, merge with existing


# ============================================================================
# VM GROUP SCHEMAS
# ============================================================================


class VMGroupCreate(BaseModel):
    """Request model for creating VM group"""

    name: str
    description: Optional[str] = None
    tags: Optional[List[str]] = []
    group_type: Optional[str] = "static"
    rules: Optional[List[dict]] = None
    rules_match: Optional[str] = "all"


class VMGroupUpdate(BaseModel):
    """Request model for updating VM group"""

    name: Optional[str] = None
    description: Optional[str] = None
    tags: Optional[List[str]] = None
    group_type: Optional[str] = None
    rules: Optional[List[dict]] = None
    rules_match: Optional[str] = None


class VMGroupAddVMs(BaseModel):
    """Request model for adding VMs to group"""

    vm_ids: List[str]


# ============================================================================
# USER SCHEMAS
# ============================================================================


class UserCreate(BaseModel):
    """Request model for creating user"""

    model_config = ConfigDict(extra="forbid", strict=True)

    username: str = Field(min_length=1, max_length=255)
    password: str = Field(min_length=1)
    full_name: Optional[str] = None
    email: Optional[str] = None
    is_active: bool = True
    role: Literal["admin", "operator", "viewer"] = "viewer"


class UserUpdate(BaseModel):
    """Request model for updating user"""

    model_config = ConfigDict(extra="forbid", strict=True)

    username: Optional[str] = Field(default=None, min_length=1, max_length=255)
    full_name: Optional[str] = None
    email: Optional[str] = None
    password: Optional[str] = Field(default=None, min_length=1)
    role: Optional[Literal["admin", "operator", "viewer"]] = None
    role_source: Optional[Literal["local", "oidc"]] = None
    is_active: Optional[bool] = None


# ============================================================================
# SCHEDULE SCHEMAS
# ============================================================================


def _valid_schedule_disks(disks):
    if disks is None:
        return None
    if len(set(disks)) != len(disks) or any(
        re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", disk) is None
        for disk in disks
    ):
        raise ValueError("Schedule exclusions require distinct disk names")
    return disks


class ScheduleCreate(BaseModel):
    """Request model for creating schedule"""

    name: str
    vm_id: Optional[str] = None
    vm_group_id: Optional[str] = None
    cron_expression: str  # e.g., "0 2 * * *" for 2 AM daily
    backup_type: Literal["full", "incremental", "automatic"] = "full"
    backup_policy: Optional[dict] = None
    retention_days: int = Field(default=30, ge=1, le=36500)
    tags: Optional[dict] = {}
    enabled: bool = False
    exclude_disks: List[str] = Field(default_factory=list, max_length=256)
    workers: None = Field(
        default=None, description="Per-backup worker overrides are unsupported"
    )
    _validate_workers = field_validator("workers", mode="before")(_unsupported_workers)

    _validate_exclude_disks = field_validator("exclude_disks")(_valid_schedule_disks)

    @model_validator(mode="after")
    def validate_backup_mode(self):
        from core.scheduler_policy import validate_mode

        self.backup_policy = validate_mode(self.backup_type, self.backup_policy)
        return self


class ScheduleUpdate(BaseModel):
    """Request model for updating schedule"""

    name: Optional[str] = None
    cron_expression: Optional[str] = None
    backup_type: Optional[Literal["full", "incremental", "automatic"]] = None
    backup_policy: Optional[dict] = None
    retention_days: Optional[int] = Field(default=None, ge=1, le=36500)
    tags: Optional[dict] = None
    enabled: Optional[bool] = None
    exclude_disks: Optional[List[str]] = Field(default=None, max_length=256)
    workers: None = Field(
        default=None, description="Per-backup worker overrides are unsupported"
    )
    _validate_workers = field_validator("workers", mode="before")(_unsupported_workers)

    _validate_exclude_disks = field_validator("exclude_disks")(_valid_schedule_disks)

    @field_validator("backup_policy")
    @classmethod
    def validate_backup_policy(cls, value):
        from core.scheduler_policy import validate_policy

        return None if value is None else validate_policy(value)


# ============================================================================
# REPORT SCHEMAS
# ============================================================================


class ReportCreate(BaseModel):
    """Request model for creating report"""

    name: str
    report_type: str
    schedule: Optional[str] = None
    format: str = "pdf"
    recipients: Optional[List[str]] = None
    filters: Optional[dict] = None
    enabled: bool = True


# ============================================================================
# API KEY SCHEMAS
# ============================================================================


class OrchestratorAPIKeyCreate(BaseModel):
    """Request model for creating orchestrator API key"""

    name: str
    expires_at: Optional[datetime] = None


class OrchestratorAPIKeyUpdate(BaseModel):
    """Request model for updating orchestrator API key"""

    name: Optional[str] = None
    expires_at: Optional[datetime] = None
    enabled: Optional[bool] = None


class AgentRegistrationKeyCreate(BaseModel):
    """Request model for creating agent registration key"""

    name: str
    agent_hostname: str = Field(min_length=1, max_length=255)
    expires_at: Optional[datetime] = None
    max_uses: Optional[int] = None


class AgentRegistrationKeyUpdate(BaseModel):
    """Request model for updating agent registration key"""

    name: Optional[str] = None
    expires_at: Optional[datetime] = None
    max_uses: Optional[int] = None
    enabled: Optional[bool] = None


class AgentAPIKeyRotate(BaseModel):
    """Request model for rotating agent API key"""

    expires_at: Optional[datetime] = None


# ============================================================================
# AGENT SCHEMAS
# ============================================================================


class AgentUpdateRequest(BaseModel):
    """Request model for updating agent"""

    display_name: Optional[str] = None
    status: Optional[str] = None


class AgentSettingsUpdate(BaseModel):
    model_config = {"extra": "forbid"}
    selected_source_namespaces: Optional[list[str]] = None
    """Request model for updating agent runtime settings (delivered via heartbeat)"""

    max_concurrent_backups: Optional[int] = None
    backup_storage_path: Optional[str] = None
    virtnbdbackup_path: Optional[str] = None
    virtnbdrestore_path: Optional[str] = None
    virtnbd_scratch_dir: Optional[str] = None
    libvirt_uri: Optional[str] = None
    heartbeat_interval: Optional[int] = None
    log_level: Optional[str] = None
    compression_type: Optional[str] = None
    compression_level: Optional[str] = None
