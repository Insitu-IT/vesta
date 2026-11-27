"""
Database models for vnbui Minimal MVP
All models in one file for simplicity
"""

from sqlalchemy import (
    Column,
    Uuid,
    JSON,
    String,
    Integer,
    BigInteger,
    Boolean,
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    Text,
    Table,
    LargeBinary,
    func,
    text,
    Index,
    UniqueConstraint,
    CheckConstraint,
    select,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.ext.mutable import MutableDict
from sqlalchemy.orm import relationship, declared_attr
from datetime import datetime
import uuid
from core.scheduler_policy import SCHEDULE_POLICY_CHECK

Base = declarative_base()


def generate_uuid():
    """Generate UUID as string"""
    return str(uuid.uuid4())


class Organization(Base):
    """
    Organization model - for multi-tenancy (MSP/Enterprise feature)
    OSS: Always uses single 'default' organization
    MSP: Multiple organizations with isolation
    Enterprise: Organizations with compliance features
    """

    __tablename__ = "organizations"

    id = Column(String, primary_key=True, default=generate_uuid)
    name = Column(String(255), nullable=False)
    parent_id = Column(
        String, ForeignKey("organizations.id"), nullable=True
    )  # For hierarchies
    settings = Column(JSONB, default=dict)
    branding = Column(JSONB, default=dict)  # White-labeling data
    limits = Column(JSONB, default=dict)  # Resource quotas
    enabled = Column(Boolean, default=True)
    scheduler_epoch = Column(BigInteger, nullable=False, server_default=text("0"))
    scheduler_order = Column(BigInteger, nullable=False, server_default=text("0"))
    created_at = Column(DateTime, default=datetime.utcnow, server_default=func.now())
    updated_at = Column(
        DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
        server_default=func.now(),
    )

    def __repr__(self):
        return f"<Organization {self.name}>"


class OrganizationDefault(Base):
    """Explicit OSS organization assignment, seeded by migration, never guessed."""

    __tablename__ = "organization_defaults"
    __table_args__ = (
        CheckConstraint("slot = 'oss'", name="ck_organization_defaults_slot"),
    )

    slot = Column(String(16), primary_key=True)
    org_id = Column(String, ForeignKey("organizations.id"), nullable=False)


def default_organization_id(context):
    """Neutral insert default only; this is not a tenant authorization mechanism."""
    from core.tenant_context import identity

    org, _, platform = identity()
    if org is not None and org != "default":
        return org
    if platform:
        raise RuntimeError("Platform writes require explicit org_id attribution")
    org_id = context.connection.execute(
        select(OrganizationDefault.org_id).where(OrganizationDefault.slot == "oss")
    ).scalar_one_or_none()
    if org_id is None:
        raise RuntimeError(
            "OSS organization assignment is missing; run alembic upgrade head "
            "before starting the backend"
        )
    return org_id


class OrganizationScoped:
    """Preserve organization attribution without introducing tenant filtering."""

    @declared_attr
    def org_id(cls):
        return Column(
            String,
            ForeignKey("organizations.id", name=f"fk_{cls.__tablename__}_org_id"),
            nullable=False,
            default=default_organization_id,
        )


class OperatorRequest(OrganizationScoped, Base):
    """Retained request identity and nonsecret admission outcome."""

    __tablename__ = "operator_requests"
    __table_args__ = (
        UniqueConstraint(
            "org_id", "request_id", name="uq_operator_requests_org_request"
        ),
    )
    id = Column(String, primary_key=True, default=generate_uuid)
    request_id = Column(String(36), nullable=False)
    actor_id = Column(String, nullable=False)
    action = Column(String(64), nullable=False)
    fingerprint = Column(String(64), nullable=False)
    contract_version = Column(Integer, nullable=False, server_default=text("1"))
    created_at = Column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    response_status = Column(Integer)
    response_body = Column(JSONB)
    completed_at = Column(DateTime(timezone=True))
    secret_delivery = Column(Boolean, nullable=False, server_default=text("false"))


class OperatorDispatch(OrganizationScoped, Base):
    """Durable work admission, independent of a request process lifetime."""

    __tablename__ = "operator_dispatches"
    __table_args__ = (
        UniqueConstraint("kind", "resource_id", name="uq_operator_dispatches_resource"),
        Index("ix_operator_dispatches_state_created", "state", "created_at", "id"),
    )
    id = Column(String, primary_key=True, default=generate_uuid)
    request_record_id = Column(
        String, ForeignKey("operator_requests.id"), nullable=False
    )
    kind = Column(String(16), nullable=False)
    resource_id = Column(String, nullable=False)
    actor_id = Column(String, nullable=False)
    state = Column(String(16), nullable=False, server_default=text("'pending'"))
    reason = Column(String(64))
    created_at = Column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at = Column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class AgentKeyRotation(OrganizationScoped, Base):
    """A staged hashed credential; plaintext is never retained."""

    __tablename__ = "agent_key_rotations"
    __table_args__ = (
        UniqueConstraint("request_record_id", name="uq_agent_key_rotations_request"),
        UniqueConstraint("candidate_hash", name="uq_agent_key_rotations_candidate"),
        Index(
            "ix_agent_key_rotations_pending",
            "agent_id",
            unique=True,
            postgresql_where=text("(state)::text = 'pending'::text"),
        ),
    )
    id = Column(String, primary_key=True, default=generate_uuid)
    agent_id = Column(String, nullable=False)
    request_record_id = Column(
        String, ForeignKey("operator_requests.id"), nullable=False
    )
    predecessor_hash = Column(String(64), nullable=False)
    candidate_hash = Column(String(64), nullable=False)
    key_prefix = Column(String(8), nullable=False)
    state = Column(String(16), nullable=False, server_default=text("'pending'"))
    created_at = Column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    expires_at = Column(DateTime(timezone=True), nullable=False)
    activated_at = Column(DateTime(timezone=True))
    created_by = Column(String, nullable=False)


class OIDCLoginState(OrganizationScoped, Base):
    """One-time login binding; no browser or provider credential is persisted."""

    __tablename__ = "oidc_login_states"
    digest = Column(String(64), primary_key=True)
    issuer = Column(Text, nullable=False)
    client_id = Column(Text, nullable=False)
    purpose = Column(String(32), nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    consumed_at = Column(DateTime(timezone=True), nullable=True)


class DemoSession(Base):
    """Isolated synthetic state for one anonymous public-demo browser session.

    This is deliberately separate from Organization and the commercial tenancy
    machinery. Only a SHA-256 digest of the opaque browser token is persisted.
    """

    __tablename__ = "demo_sessions"

    id = Column(String, primary_key=True, default=generate_uuid)
    token_hash = Column(String(64), unique=True, nullable=False)
    fixture_version = Column(String(32), nullable=False)
    state = Column(JSONB, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    last_seen_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    expires_at = Column(DateTime, nullable=False, index=True)
    absolute_expires_at = Column(DateTime, nullable=False, index=True)

    def __repr__(self):
        return f"<DemoSession {self.id} fixture={self.fixture_version}>"


class DemoRateBucket(Base):
    """Bounded, non-identifying request counter for the public demo."""

    __tablename__ = "demo_rate_buckets"

    key_hash = Column(String(64), primary_key=True)
    window_started_at = Column(DateTime, nullable=False)
    request_count = Column(Integer, nullable=False, default=0)


# Association table for many-to-many relationship between VMs and Groups
vm_group_association = Table(
    "vm_group_members",
    Base.metadata,
    Column("vm_id", String, ForeignKey("vms.id"), primary_key=True),
    Column("group_id", String, ForeignKey("vm_groups.id"), primary_key=True),
    Column("added_at", DateTime, default=datetime.utcnow),
)


class User(OrganizationScoped, Base):
    """User model - for authentication"""

    __tablename__ = "users"
    __table_args__ = (
        UniqueConstraint("org_id", "username", name="uq_users_org_username"),
    )

    id = Column(String, primary_key=True, default=generate_uuid)
    username = Column(String(100), nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    role = Column(
        String(20), default="viewer", nullable=False
    )  # admin, operator, viewer
    # Provisioned by the platform operator; never accepted by user CRUD schemas
    # or inferred from an organization role or a token claim.
    is_platform_admin = Column(
        Boolean, nullable=False, default=False, server_default=text("false")
    )
    email = Column(String(255), nullable=True)
    full_name = Column(String(255), nullable=True)
    last_login = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    is_active = Column(
        Boolean, default=True, nullable=False, server_default=text("true")
    )

    # v3.0: OIDC authentication support
    auth_source = Column(
        String(20), default="local", server_default=text("'local'")
    )  # 'local' | 'oidc'
    role_source = Column(
        String(20), default="local", server_default=text("'local'")
    )  # 'local' | 'oidc'
    oidc_subject = Column(String(255), nullable=True)  # OIDC sub claim
    oidc_issuer = Column(String(255), nullable=True)  # OIDC issuer URL

    def __repr__(self):
        return f"<User {self.username} ({self.role})>"


class Agent(OrganizationScoped, Base):
    """Agent model - represents KVM hosts"""

    __tablename__ = "agents"
    __table_args__ = (
        UniqueConstraint("org_id", "hostname", name="uq_agents_org_hostname"),
    )

    id = Column(String, primary_key=True, default=generate_uuid)
    hostname = Column(String(255), nullable=False)
    display_name = Column(
        String(255), nullable=True
    )  # UI-configurable name (overrides hostname)
    status = Column(String(20), default="online")  # online, offline
    last_heartbeat = Column(DateTime, default=datetime.utcnow)  # Last health check
    created_at = Column(DateTime, default=datetime.utcnow)

    # Agent identification
    # Native agents report an IP; KubeVirt agents report their service DNS name.
    ip_address = Column(String(255), nullable=True)
    port = Column(Integer, nullable=True)  # Agent listen port
    version = Column(String(32), nullable=True)  # Agent software version
    platform = Column(String(64), nullable=True)  # OS/platform info

    # Legacy API Key Authentication (deprecated - moved to AgentAPIKey table)
    api_key_hash = Column(String(64), nullable=True)  # SHA-256 hash of agent API key
    key_created_at = Column(DateTime, nullable=True)  # When key was generated
    key_last_used_at = Column(DateTime, nullable=True)  # Last successful authentication

    # Agent Capabilities and Metrics
    capabilities = Column(
        JSONB, default=dict, server_default=text("'{}'"), nullable=False
    )  # Agent features/versions
    metrics = Column(
        JSONB, default=dict, server_default=text("'{}'"), nullable=False
    )  # Resource usage, performance stats

    # UI-configurable settings (delivered via heartbeat, overridable by local agent.env)
    config = Column(
        JSONB, default=dict, server_default=text("'{}'"), nullable=False
    )  # Settings managed from UI

    # mTLS certificate tracking (v3.1)
    cert_fingerprint = Column(String(64), nullable=True)
    cert_expires_at = Column(DateTime, nullable=True)
    mtls_enabled = Column(Boolean, default=False, server_default=text("false"))

    # Relationships
    vms = relationship("VM", back_populates="agent")
    api_key = relationship("AgentAPIKey", back_populates="agent", uselist=False)
    certificates = relationship("AgentCertificate", back_populates="agent")

    def __repr__(self):
        return f"<Agent {self.display_name or self.hostname}>"

    def get_display_name(self) -> str:
        """Get display name (UI override or hostname)"""
        return self.display_name or self.hostname


class VM(OrganizationScoped, Base):
    """VM model - virtual machines discovered from agents"""

    __tablename__ = "vms"
    __table_args__ = (
        UniqueConstraint(
            "agent_id", "provider", "namespace", "vm_uid", name="uq_vm_identity"
        ),
    )

    id = Column(String, primary_key=True, default=generate_uuid)
    name = Column(String(255), nullable=False)
    agent_id = Column(String, ForeignKey("agents.id"), nullable=False)
    state = Column(String(20), default="running")  # running, stopped
    created_at = Column(DateTime, default=datetime.utcnow)

    # VM identification and specs (from libvirt)
    uuid = Column(String(36), nullable=True)  # libvirt UUID
    provider = Column(String(32), nullable=True)
    namespace = Column(String(255), nullable=True)
    vm_uid = Column(String(64), nullable=True)
    vmi_uid = Column(String(64), nullable=True)
    inventory_present = Column(
        Boolean, nullable=False, default=True, server_default="true"
    )
    last_observed_at = Column(DateTime, nullable=True)
    absent_since = Column(DateTime, nullable=True)
    replaces_vm_id = Column(String, ForeignKey("vms.id"), nullable=True)
    memory_kb = Column(BigInteger, nullable=True)  # Memory in KB
    vcpu_count = Column(Integer, nullable=True)  # Number of vCPUs
    disks = Column(
        JSONB, default=list, server_default=text("'[]'")
    )  # Disk info [{name, bus, type, source}]
    vm_metadata = Column(
        JSONB, default=dict, server_default=text("'{}'")
    )  # Additional metadata (persistent, autostart, etc.)

    # Relationships
    agent = relationship("Agent", back_populates="vms")
    backups = relationship("Backup", back_populates="vm")
    groups = relationship(
        "VMGroup", secondary=vm_group_association, back_populates="vms"
    )

    def __repr__(self):
        return f"<VM {self.name}>"


class VMGroup(OrganizationScoped, Base):
    """VMGroup model - logical grouping of VMs"""

    __tablename__ = "vm_groups"
    __table_args__ = (UniqueConstraint("org_id", "name", name="uq_vm_groups_org_name"),)

    id = Column(String, primary_key=True, default=generate_uuid)
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    tags = Column(JSONB, nullable=True, default=list)  # List of tag strings
    group_type = Column(
        String(20), default="static", server_default=text("'static'"), nullable=False
    )  # static, dynamic, hybrid
    rules = Column(JSONB, nullable=True)  # [{field, op, value}, ...]
    rules_match = Column(
        String(10), default="all", server_default=text("'all'"), nullable=False
    )  # all (AND) | any (OR)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationship
    vms = relationship("VM", secondary=vm_group_association, back_populates="groups")

    def __repr__(self):
        return f"<VMGroup {self.name} ({self.group_type})>"


class Backup(OrganizationScoped, Base):
    """Backup model - backup jobs"""

    __tablename__ = "backups"

    __table_args__ = (
        CheckConstraint(
            "(capacity_state = 'unreserved' AND capacity_id IS NULL AND capacity_reserved_at IS NULL AND "
            "capacity_policy_revision IS NULL AND capacity_release IS NULL) OR (capacity_state IN "
            "('reserved','legacy_held','released') AND capacity_id IS NOT NULL AND capacity_reserved_at IS "
            "NOT NULL AND ((capacity_state='reserved' AND capacity_policy_revision IS NOT NULL AND "
            "capacity_policy_revision>0 AND capacity_release IS NULL) OR (capacity_state='legacy_held' AND "
            "capacity_policy_revision IS NULL AND capacity_release IS NULL) OR (capacity_state='released' "
            "AND capacity_policy_revision IS NOT NULL AND capacity_policy_revision>0 AND capacity_release "
            "IS NOT NULL)))",
            name="ck_backup_capacity_state",
        ),
        CheckConstraint(
            "capacity_terminal_evidence IS NULL AND capacity_terminal_xid IS NULL",
            name="ck_backup_capacity_terminal_dormant",
        ),
        Index(
            "uq_backup_capacity_vm",
            "org_id",
            "vm_id",
            unique=True,
            postgresql_where=text("(capacity_state)::text = 'reserved'::text"),
            sqlite_where=text("capacity_state = 'reserved'"),
        ),
    )

    id = Column(String, primary_key=True, default=generate_uuid)
    unverified_legacy_s3 = Column(Boolean, nullable=False, server_default=text("false"))
    capacity_state = Column(String, nullable=False, server_default=text("'unreserved'"))
    capacity_id = Column(Uuid(as_uuid=False), nullable=True)
    capacity_reserved_at = Column(DateTime(timezone=True), nullable=True)
    capacity_policy_revision = Column(BigInteger, nullable=True)
    capacity_release = Column(JSONB, nullable=True)
    # Operator-only, append-only classification of predecessor capacity holds.
    # The database trigger refuses ordinary runtime edits to this field.
    capacity_legacy_reviews = Column(JSONB, nullable=False, server_default=text("'[]'"))
    # Migration-owner-only disposition of modern effect-held attempts.
    capacity_modern_reviews = Column(JSONB, nullable=False, server_default=text("'[]'"))
    capacity_terminal_evidence = Column(JSONB, nullable=True)
    capacity_terminal_xid = Column(BigInteger, nullable=True)
    native_job_intent = Column(JSONB, nullable=True)
    native_job_transaction_id = Column(BigInteger, nullable=True)
    native_inventory = Column(JSONB, nullable=True)
    native_inventory_transaction_id = Column(BigInteger, nullable=True)
    native_no_effect = Column(JSONB, nullable=True)
    # Positive post-begin writer termination, never success or no-effect.
    native_closed_failure = Column(JSONB, nullable=True)
    # Immutable actual producer request, committed before native execution.
    native_execution = Column(JSONB, nullable=True)
    # Failed-only kernel-fenced output; transaction orders the required full reset.
    native_fenced_failure = Column(JSONB, nullable=True)
    native_fenced_failure_xid = Column(BigInteger, nullable=True)
    vm_id = Column(String, ForeignKey("vms.id"), nullable=False)
    authority_kind = Column(String, nullable=True)
    scheduler_occurrence_id = Column(String, nullable=True)
    initiating_user_id = Column(
        String, ForeignKey("users.id"), nullable=True, index=True
    )
    status = Column(
        String(20), default="pending"
    )  # pending, running, completed, failed
    progress = Column(Integer, default=0)  # 0-100
    # Observed transfer state, separate from immutable scheduled caller tags.
    storage_progress = Column(JSONB, nullable=True)
    size_bytes = Column(
        BigInteger, nullable=True
    )  # Changed to BigInteger for >2GB files
    retention_days = Column(
        Integer, default=30, nullable=False
    )  # How long to keep this backup
    backup_type = Column(
        String(20), default="full", server_default=text("'full'")
    )  # full, incremental, differential
    storage_path = Column(
        String(512), nullable=True
    )  # Path where backup is stored (file:// or s3://)
    tags = Column(
        MutableDict.as_mutable(JSONB), default=dict, nullable=False
    )  # Key-value tags for backup metadata
    created_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)

    # virtnbdbackup options (v2.4.0)
    exclude_disks = Column(
        JSONB, default=list, server_default=text("'[]'")
    )  # Disks to exclude from backup [-x]
    workers = Column(Integer, nullable=True)  # Concurrent backup workers [--worker]
    checkpoints = Column(
        JSONB, default=list, server_default=text("'[]'")
    )  # Available checkpoints for PITR

    # Envelope encryption (v3.1 KMS)
    encryption_key_id = Column(String, ForeignKey("encryption_keys.id"), nullable=True)
    wrapped_dek = Column(Text, nullable=True)  # Base64-encoded AES-wrapped DEK

    # Incremental chain tracking (v4.1)
    chain_id = Column(
        String, ForeignKey("backups.id"), nullable=True, index=True
    )  # Full backup that starts this chain
    parent_backup_id = Column(
        String, ForeignKey("backups.id"), nullable=True
    )  # Previous backup in chain
    chain_position = Column(
        Integer, nullable=True
    )  # 0=full, 1=first inc, 2=second inc...

    # Relationship
    vm = relationship("VM", back_populates="backups")
    encryption_key = relationship("EncryptionKey")

    def __repr__(self):
        return f"<Backup {self.id} for VM {self.vm_id}>"


class StorageLineageGeneration(OrganizationScoped, Base):
    """Immutable accepted-fact interface; D06 publication is not implemented."""

    __tablename__ = "storage_lineage_generations"
    id = Column(String, primary_key=True)
    vm_id = Column(String, ForeignKey("vms.id"), nullable=False, index=True)
    backup_id = Column(String, ForeignKey("backups.id"), nullable=False)
    root_backup_id = Column(String, ForeignKey("backups.id"), nullable=False)
    state = Column(String, nullable=False)
    receipt_sha256 = Column(String, nullable=False)
    root_receipt_sha256 = Column(String, nullable=False)
    manifest_receipt_sha256 = Column(String, nullable=False)
    tracker_uid = Column(String, nullable=False)
    checkpoint = Column(String, nullable=False)
    accepted_request = Column(JSONB, nullable=False)


class RecoveryPublication(OrganizationScoped, Base):
    """One durable, append-only signed offsite record for an accepted generation."""

    __tablename__ = "recovery_publications"
    __table_args__ = (
        UniqueConstraint("org_id", "backup_id", name="uq_recovery_publication_backup"),
        Index("ix_recovery_publication_due", "org_id", "next_attempt_at"),
        CheckConstraint(
            "attempt_count >= 0", name="ck_recovery_publication_attempt_count"
        ),
    )

    generation_id = Column(
        String, ForeignKey("storage_lineage_generations.id"), primary_key=True
    )
    backup_id = Column(String, ForeignKey("backups.id"), nullable=False)
    object_key = Column(String(1024), nullable=False)
    created_at = Column(DateTime(timezone=True), nullable=False)
    next_attempt_at = Column(DateTime(timezone=True), nullable=False)
    attempt_count = Column(Integer, nullable=False, server_default=text("0"))
    last_failure_at = Column(DateTime(timezone=True))
    claim_token = Column(String, nullable=False)
    envelope = Column(Text)
    published_at = Column(DateTime(timezone=True))
    publication_receipt = Column(JSONB(none_as_null=True))


class StorageLineageHead(OrganizationScoped, Base):
    """Single DB-current selection; ordinary runtime cannot publish or retarget."""

    __tablename__ = "storage_lineage_heads"
    vm_id = Column(String, ForeignKey("vms.id"), primary_key=True)
    generation_id = Column(
        String, ForeignKey("storage_lineage_generations.id"), nullable=False
    )
    state = Column(String, nullable=False)
    manifest_receipt_sha256 = Column(String, nullable=False)
    root_backup_id = Column(String, ForeignKey("backups.id"), nullable=False)
    tracker_uid = Column(String, nullable=False)
    checkpoint = Column(String, nullable=False)


class StorageConfigurationClock(Base):
    """Monotonic installation S3 configuration revision, never a credential."""

    __tablename__ = "storage_configuration_clock"
    __table_args__ = (
        CheckConstraint(
            "slot = 1 AND revision > 0", name="ck_storage_configuration_clock"
        ),
    )
    slot = Column(Integer, primary_key=True, autoincrement=False)
    installation_id = Column(String, nullable=False)
    revision = Column(BigInteger, nullable=False)


class StorageConfigurationGeneration(OrganizationScoped, Base):
    """Immutable non-secret descriptor of an exact installation configuration."""

    __tablename__ = "storage_configuration_generations"
    __table_args__ = (
        UniqueConstraint("org_id", "id", name="uq_storage_configuration_org"),
        UniqueConstraint("org_id", "sha256", name="uq_storage_configuration_digest"),
        CheckConstraint("revision > 0", name="ck_storage_configuration_revision"),
    )
    id = Column(String, primary_key=True, default=generate_uuid)
    revision = Column(BigInteger, nullable=False)
    descriptor = Column(JSONB, nullable=False)
    sha256 = Column(String, nullable=False)


class StorageConfigurationActivation(OrganizationScoped, Base):
    """Append-only selection/fence; a selected generation cannot be resurrected."""

    __tablename__ = "storage_configuration_activations"
    __table_args__ = (
        ForeignKeyConstraint(
            ["org_id", "generation_id"],
            [
                "storage_configuration_generations.org_id",
                "storage_configuration_generations.id",
            ],
            name="fk_storage_configuration_activation",
        ),
        UniqueConstraint("generation_id", name="uq_storage_configuration_activation"),
    )
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    generation_id = Column(String, nullable=True)
    reason = Column(String, nullable=False)


class StorageCapabilityEvidence(OrganizationScoped, Base):
    """Immutable tenant-visible installation evidence, not operation approval."""

    __tablename__ = "storage_capability_evidence"
    __table_args__ = (
        UniqueConstraint("org_id", "id", name="uq_storage_evidence_org"),
        CheckConstraint("revision > 0", name="ck_storage_evidence_revision"),
    )
    id = Column(String, primary_key=True, default=generate_uuid)
    revision = Column(BigInteger, nullable=False)
    facts = Column(JSONB, nullable=False)
    sha256 = Column(String, nullable=False)


class StorageCapabilityQualification(OrganizationScoped, Base):
    """Explicit immutable per-operation approval, never inferred from facts."""

    __tablename__ = "storage_capability_qualifications"
    __table_args__ = (
        ForeignKeyConstraint(
            ["org_id", "evidence_id"],
            ["storage_capability_evidence.org_id", "storage_capability_evidence.id"],
            name="fk_storage_qualification_evidence",
            ondelete="RESTRICT",
        ),
    )
    evidence_id = Column(String, primary_key=True)
    operation = Column(String, primary_key=True)
    approval = Column(JSONB, nullable=False)


class StorageCapabilityRevocation(OrganizationScoped, Base):
    """Append-only fence; neither history nor approval is overwritten."""

    __tablename__ = "storage_capability_revocations"
    __table_args__ = (
        ForeignKeyConstraint(
            ["org_id", "evidence_id"],
            ["storage_capability_evidence.org_id", "storage_capability_evidence.id"],
            name="fk_storage_revocation_evidence",
            ondelete="RESTRICT",
        ),
    )
    evidence_id = Column(String, primary_key=True)
    operation = Column(String, primary_key=True)
    reason = Column(String, nullable=False)


class S3Publication(OrganizationScoped, Base):
    """Write-ahead storage ownership; retained even after object reclamation."""

    __tablename__ = "s3_publications"
    __table_args__ = (
        UniqueConstraint("org_id", "id", name="uq_s3_publication_org"),
        UniqueConstraint("backup_id", "kind", name="uq_s3_publication_backup_kind"),
        UniqueConstraint(
            "endpoint", "bucket", "object_key", name="uq_s3_publication_object"
        ),
        CheckConstraint(
            "kind IN ('payload', 'chain_manifest')", name="ck_s3_publication_kind"
        ),
        CheckConstraint(
            "state IN ('reserved', 'published', 'cleanup_required', 'deleted')",
            name="ck_s3_publication_state",
        ),
    )

    id = Column(String, primary_key=True, default=generate_uuid)
    backup_id = Column(String, ForeignKey("backups.id"), nullable=False)
    kind = Column(String, nullable=False)
    endpoint = Column(String, nullable=False)
    bucket = Column(String, nullable=False)
    object_key = Column(String, nullable=False)
    expected_plan = Column(JSON(none_as_null=True), nullable=True)
    plan_transaction_id = Column(BigInteger, nullable=True)
    dispatch_admission = Column(JSONB, nullable=True)
    dispatch_token = Column(String, nullable=True)
    dispatch_transaction_id = Column(BigInteger, nullable=True)
    prepared_receipt = Column(JSON(none_as_null=True), nullable=True)
    receipt_transaction_id = Column(BigInteger, nullable=True)
    receipt_verification_intent = Column(JSONB, nullable=True)
    receipt_verification_xid = Column(BigInteger, nullable=True)
    attempt_key_preparation_intent = Column(JSONB, nullable=True)
    attempt_key_preparation_xid = Column(BigInteger, nullable=True)
    attempt_key_disclosure_intent = Column(JSONB, nullable=True)
    attempt_key_disclosure_xid = Column(BigInteger, nullable=True)
    wrapped_attempt_key = Column(JSON(none_as_null=True), nullable=True)
    wrapped_attempt_key_xid = Column(BigInteger, nullable=True)
    provider_control = Column(JSON(none_as_null=True), nullable=True)
    provider_create = Column(JSONB, nullable=True)
    finalize_intent = Column(JSON(none_as_null=True), nullable=True)
    finalize_transaction_id = Column(BigInteger, nullable=True)
    checkpoint_proof = Column(JSON(none_as_null=True), nullable=True)
    checkpoint_transaction_id = Column(BigInteger, nullable=True)
    cleanup_intent = Column(JSON(none_as_null=True), nullable=True)
    cleanup_transaction_id = Column(BigInteger, nullable=True)
    cleanup_result = Column(JSON(none_as_null=True), nullable=True)
    state = Column(
        String, nullable=False, default="reserved", server_default="reserved"
    )


class S3UploadPart(OrganizationScoped, Base):
    """One immutable part signing admission and authenticated agent receipt."""

    __tablename__ = "s3_upload_parts"
    __table_args__ = (
        ForeignKeyConstraint(
            ["org_id", "publication_id"],
            ["s3_publications.org_id", "s3_publications.id"],
            name="fk_upload_part_publication",
            ondelete="RESTRICT",
        ),
        UniqueConstraint(
            "publication_id", "artifact_key", "number", name="uq_upload_part"
        ),
        CheckConstraint(
            "number BETWEEN 1 AND 10000 AND byte_count >= 0",
            name="ck_upload_part_bounds",
        ),
        CheckConstraint("length(sha256) = 64", name="ck_upload_part_hash"),
        Index(
            "idx_upload_part_unacknowledged",
            "publication_id",
            postgresql_where=text("acknowledgment IS NULL"),
        ),
    )
    id = Column(String, primary_key=True, default=generate_uuid)
    publication_id = Column(String, nullable=False)
    artifact_key = Column(String, nullable=False)
    number = Column(Integer, nullable=False)
    byte_count = Column(BigInteger, nullable=False)
    sha256 = Column(String, nullable=False)
    intent = Column(JSONB, nullable=False)
    intent_xid = Column(BigInteger)
    signing_result = Column(JSONB)
    signing_xid = Column(BigInteger)
    acknowledgment = Column(JSONB)
    acknowledgment_xid = Column(BigInteger)


class S3UploadResult(OrganizationScoped, Base):
    """Separate one-send completion and verified HEAD custody per artifact."""

    __tablename__ = "s3_upload_results"
    __table_args__ = (
        ForeignKeyConstraint(
            ["org_id", "publication_id"],
            ["s3_publications.org_id", "s3_publications.id"],
            name="fk_upload_result_publication",
            ondelete="RESTRICT",
        ),
        UniqueConstraint(
            "publication_id", "artifact_key", "operation", name="uq_upload_result"
        ),
        CheckConstraint(
            "operation IN ('complete','head')", name="ck_upload_result_operation"
        ),
    )
    id = Column(String, primary_key=True, default=generate_uuid)
    publication_id = Column(String, nullable=False)
    artifact_key = Column(String, nullable=False)
    operation = Column(String, nullable=False)
    intent = Column(JSONB, nullable=False)
    intent_xid = Column(BigInteger)
    response = Column(JSONB)
    response_xid = Column(BigInteger)


class S3PartObservationScan(OrganizationScoped, Base):
    """Immutable observation generation, never a recovery authorization."""

    __tablename__ = "s3_part_observation_scans"
    __table_args__ = (
        ForeignKeyConstraint(
            ["org_id", "publication_id"],
            ["s3_publications.org_id", "s3_publications.id"],
            name="fk_part_scan_publication",
            ondelete="RESTRICT",
        ),
        UniqueConstraint("org_id", "id", name="uq_part_scan_org_id"),
    )
    id = Column(String, primary_key=True, default=generate_uuid)
    publication_id = Column(String, nullable=False)
    artifact_key = Column(String, nullable=False)
    intent = Column(JSONB, nullable=False)
    intent_xid = Column(BigInteger)
    admitted_at = Column(BigInteger, nullable=False)


class S3PartObservationPage(OrganizationScoped, Base):
    """One acknowledged creator GET and its separately committed observation."""

    __tablename__ = "s3_part_observation_pages"
    __table_args__ = (
        ForeignKeyConstraint(
            ["org_id", "publication_id"],
            ["s3_publications.org_id", "s3_publications.id"],
            name="fk_part_page_publication",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["org_id", "scan_id"],
            ["s3_part_observation_scans.org_id", "s3_part_observation_scans.id"],
            name="fk_part_page_scan",
            ondelete="RESTRICT",
        ),
        UniqueConstraint("scan_id", "number", name="uq_part_page_number"),
        UniqueConstraint("scan_id", "marker", name="uq_part_page_marker"),
        CheckConstraint(
            "number BETWEEN 1 AND 10001 AND marker BETWEEN 0 AND 10000",
            name="ck_part_page_bounds",
        ),
    )
    id = Column(String, primary_key=True, default=generate_uuid)
    publication_id = Column(String, nullable=False)
    artifact_key = Column(String, nullable=False)
    scan_id = Column(String, nullable=False)
    number = Column(Integer, nullable=False)
    marker = Column(Integer, nullable=False)
    intent = Column(JSONB, nullable=False)
    intent_xid = Column(BigInteger)
    observation = Column(JSONB)
    observation_xid = Column(BigInteger)
    retained_bytes = Column(BigInteger, nullable=False)


class EncryptionKey(OrganizationScoped, Base):
    """
    Encryption key (KEK) for envelope encryption.

    Local provider: key material encrypted with Fernet (VNBUI_ENCRYPTION_KEY).
    External providers (Vault, AWS KMS): material is None, provider_key_ref points to external key.
    """

    __tablename__ = "encryption_keys"

    id = Column(String, primary_key=True, default=generate_uuid)
    name = Column(String(255), nullable=False)
    algorithm = Column(
        String(50), default="aes-256-gcm", server_default=text("'aes-256-gcm'")
    )
    key_hash = Column(String(64), nullable=False)  # SHA256 prefix of raw key material
    encrypted_material = Column(
        Text, nullable=True
    )  # Fernet-encrypted KEK (local provider only)
    status = Column(
        String(20), default="active", server_default=text("'active'")
    )  # active, rotated, revoked
    provider = Column(
        String(50), default="local", server_default=text("'local'")
    )  # local, vault, aws-kms
    provider_key_ref = Column(
        String(255), nullable=True
    )  # External ref (Vault path, AWS ARN)
    created_at = Column(DateTime, default=datetime.utcnow, server_default=func.now())
    created_by = Column(String, ForeignKey("users.id"), nullable=True)
    rotated_at = Column(DateTime, nullable=True)
    replaced_by_id = Column(String, ForeignKey("encryption_keys.id"), nullable=True)
    backed_up = Column(Boolean, default=False, server_default=text("false"))
    backed_up_at = Column(DateTime, nullable=True)
    backed_up_locations = Column(JSONB, default=list, server_default=text("'[]'"))

    def __repr__(self):
        return f"<EncryptionKey {self.name} ({self.status})>"


class BackupQueue(Base):
    """
    BackupQueue model - queue for pending backup requests.

    Instead of failing immediately when max concurrent backups is reached,
    backups are queued and processed when slots become available.
    """

    __tablename__ = "backup_queue"

    id = Column(String, primary_key=True, default=generate_uuid)
    vm_id = Column(String, ForeignKey("vms.id"), nullable=False)
    authority_kind = Column(String, nullable=True)
    scheduler_occurrence_id = Column(String, nullable=True)
    initiating_user_id = Column(
        String, ForeignKey("users.id"), nullable=True, index=True
    )
    started_backup_id = Column(
        String, ForeignKey("backups.id"), nullable=True, index=True
    )
    priority = Column(
        Integer, default=0
    )  # Higher = more urgent. 0=normal, 10=high, 100=urgent
    retention_days = Column(Integer, default=30)
    backup_type = Column(String(20), default="full")
    backup_decision = Column(JSONB(none_as_null=True), nullable=True)
    tags = Column(MutableDict.as_mutable(JSONB), default=dict)
    exclude_disks = Column(JSONB, default=list)
    workers = Column(Integer, nullable=True)

    # Queue metadata
    status = Column(String(20), default="queued")  # queued, processing, cancelled
    position = Column(Integer, nullable=True)  # Queue position (calculated)
    queued_at = Column(DateTime, default=datetime.utcnow)
    started_at = Column(DateTime, nullable=True)  # When processing started
    created_by = Column(
        String, ForeignKey("users.id"), nullable=True
    )  # User who queued it

    claim_id = Column(Uuid(as_uuid=False), nullable=True)
    claimed_at = Column(DateTime(timezone=True), nullable=True)
    hold_reason = Column(String(64), nullable=True)

    # Source info
    schedule_id = Column(String, ForeignKey("schedules.id"), nullable=True)
    is_bulk_operation = Column(Boolean, default=False)

    # Relationships
    vm = relationship("VM")
    user = relationship("User", foreign_keys=[created_by])
    schedule = relationship("Schedule")

    def __repr__(self):
        return f"<BackupQueue {self.id} for VM {self.vm_id} priority={self.priority}>"


class ActivityLog(Base):
    """ActivityLog model - audit trail of user actions"""

    __tablename__ = "activity_logs"

    id = Column(String, primary_key=True, default=generate_uuid)
    user_id = Column(String, ForeignKey("users.id"), nullable=False)
    action = Column(
        String(100), nullable=False
    )  # e.g., "backup_created", "vm_group_deleted"
    resource_type = Column(String(50), nullable=True)  # e.g., "backup", "vm_group"
    resource_id = Column(String, nullable=True)  # ID of affected resource
    details = Column(JSONB, default=dict)  # Additional context as JSON
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationship
    user = relationship("User")

    def __repr__(self):
        return f"<ActivityLog {self.action} by user {self.user_id}>"


class Schedule(OrganizationScoped, Base):
    """Schedule model - automated backup schedules"""

    __tablename__ = "schedules"
    __table_args__ = (
        CheckConstraint(SCHEDULE_POLICY_CHECK, name="ck_schedule_backup_policy").ddl_if(
            dialect="postgresql"
        ),
    )

    id = Column(String, primary_key=True, default=generate_uuid)
    authority_revision = Column(BigInteger, nullable=False, server_default=text("1"))
    current_grant_id = Column(String, nullable=True)
    retired_at = Column(DateTime(timezone=True), nullable=True)
    name = Column(String(255), nullable=False)
    vm_id = Column(
        String, ForeignKey("vms.id"), nullable=True
    )  # Either vm_id OR vm_group_id
    vm_group_id = Column(String, ForeignKey("vm_groups.id"), nullable=True)
    cron_expression = Column(
        String(100), nullable=False
    )  # Standard cron format: "0 2 * * *"
    retention_days = Column(
        Integer, default=30, server_default=text("30")
    )  # Default retention for scheduled backups
    tags = Column(
        MutableDict.as_mutable(JSONB), default=dict, server_default=text("'{}'")
    )  # Default tags to apply to scheduled backups
    enabled = Column(
        Boolean, default=True, server_default=text("true")
    )  # Whether schedule is active
    last_run_at = Column(DateTime, nullable=True)  # When schedule last executed
    next_run_at = Column(DateTime, nullable=True)  # When schedule will next execute
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # virtnbdbackup options (v2.4.0)
    backup_type = Column(
        String(20), default="full", server_default=text("'full'")
    )  # full, incremental, automatic
    backup_policy = Column(JSONB(none_as_null=True), nullable=True)
    exclude_disks = Column(
        JSONB, default=list, server_default=text("'[]'")
    )  # Disks to exclude from backup [-x]
    workers = Column(Integer, nullable=True)  # Concurrent backup workers [--worker]

    # Relationships
    vm = relationship("VM")
    vm_group = relationship("VMGroup")

    def __repr__(self):
        target = f"VM {self.vm_id}" if self.vm_id else f"Group {self.vm_group_id}"
        return f"<Schedule {self.name} for {target}>"


class FileSchedule(OrganizationScoped, Base):
    """A revocable organization grant for a fixed enrolled host and file set."""

    __tablename__ = "file_schedules"
    __table_args__ = (
        UniqueConstraint(
            "org_id", "id", "agent_id", "file_set", name="uq_file_schedule_target"
        ),
        CheckConstraint(
            r"storage_endpoint ~ '^https://([a-z0-9.-]+|\[[0-9a-f:]+\])(:[1-9][0-9]{0,4})?$' "
            r"AND storage_region ~ '^[a-z0-9][a-z0-9-]{0,62}$'",
            name="ck_file_schedule_storage_origin",
        ).ddl_if(dialect="postgresql"),
        Index("ix_file_schedules_due", "org_id", "enabled", "next_run_at"),
    )

    id = Column(String, primary_key=True, default=generate_uuid)
    agent_id = Column(String, nullable=False)
    file_set = Column(String(63), nullable=False)
    storage_endpoint = Column(String(320), nullable=False)
    storage_region = Column(String(63), nullable=False)
    storage_bucket = Column(String(63), nullable=False)
    storage_prefix = Column(String(512), nullable=False)
    storage_recipient_sha256 = Column(String(64), nullable=False)
    name = Column(String(255), nullable=False)
    cron_expression = Column(String(100), nullable=False)
    enabled = Column(Boolean, nullable=False)
    authorized_by = Column(String, nullable=False)
    grant_id = Column(String, nullable=False)
    org_epoch = Column(BigInteger, nullable=False)
    created_at = Column(DateTime(timezone=True), nullable=False)
    retired_at = Column(DateTime(timezone=True))
    last_run_at = Column(DateTime(timezone=True))
    next_run_at = Column(DateTime(timezone=True))


class FileBackup(OrganizationScoped, Base):
    """Persistent custody and recovery reference for a full file archive."""

    __tablename__ = "file_backups"
    __table_args__ = (
        ForeignKeyConstraint(
            ("org_id", "schedule_id", "agent_id", "file_set"),
            (
                "file_schedules.org_id",
                "file_schedules.id",
                "file_schedules.agent_id",
                "file_schedules.file_set",
            ),
            name="fk_file_backup_schedule_target",
        ),
        UniqueConstraint(
            "org_id", "actor_id", "request_key", name="uq_file_backup_request"
        ),
        UniqueConstraint(
            "schedule_id", "scheduled_at", name="uq_file_backup_occurrence"
        ),
        CheckConstraint(
            "(schedule_id IS NULL AND schedule_grant_id IS NULL AND scheduled_at IS NULL AND actor_id IS NOT NULL) OR "
            "(schedule_id IS NOT NULL AND schedule_grant_id IS NOT NULL AND scheduled_at IS NOT NULL "
            "AND actor_id IS NULL AND request_key IS NULL)",
            name="ck_file_backup_authority",
        ),
        CheckConstraint(
            "status IN ('pending', 'running', 'completed', 'failed') AND "
            "((status IN ('completed', 'failed')) = (completed_at IS NOT NULL))",
            name="ck_file_backup_status",
        ),
        CheckConstraint(
            "(status = 'completed' AND s3_path IS NOT NULL AND s3_version_id IS NOT NULL "
            "AND archive_format IS NOT NULL AND archive_size_bytes > 0 AND archive_size_bytes IS NOT NULL "
            "AND archive_sha256 IS NOT NULL AND recipient_sha256 IS NOT NULL "
            "AND files IS NOT NULL AND directories IS NOT NULL AND bytes IS NOT NULL AND error IS NULL) OR "
            "(status <> 'completed' AND s3_path IS NULL AND s3_version_id IS NULL "
            "AND archive_format IS NULL AND archive_size_bytes IS NULL AND archive_sha256 IS NULL "
            "AND recipient_sha256 IS NULL)",
            name="ck_file_backup_archive",
        ),
        CheckConstraint(
            r"storage_endpoint ~ '^https://([a-z0-9.-]+|\[[0-9a-f:]+\])(:[1-9][0-9]{0,4})?$' "
            r"AND storage_region ~ '^[a-z0-9][a-z0-9-]{0,62}$'",
            name="ck_file_backup_storage_origin",
        ).ddl_if(dialect="postgresql"),
        Index("ix_file_backups_ready", "org_id", "status", "next_check_at"),
        Index("ix_file_backups_target", "org_id", "agent_id", "file_set", "created_at"),
        Index("ix_file_backups_schedule", "org_id", "schedule_id", "scheduled_at"),
    )

    id = Column(String, primary_key=True, default=generate_uuid)
    agent_id = Column(String, nullable=False)
    file_set = Column(String(63), nullable=False)
    storage_endpoint = Column(String(320), nullable=False)
    storage_region = Column(String(63), nullable=False)
    storage_bucket = Column(String(63), nullable=False)
    storage_prefix = Column(String(512), nullable=False)
    storage_recipient_sha256 = Column(String(64), nullable=False)
    schedule_id = Column(String)
    schedule_grant_id = Column(String)
    scheduled_at = Column(DateTime(timezone=True))
    actor_id = Column(String)
    request_key = Column(String(128))
    status = Column(String(16), nullable=False, default="pending")
    created_at = Column(DateTime(timezone=True), nullable=False)
    started_at = Column(DateTime(timezone=True))
    dispatch_started_at = Column(DateTime(timezone=True))
    agent_accepted_at = Column(DateTime(timezone=True))
    completed_at = Column(DateTime(timezone=True))
    next_check_at = Column(DateTime(timezone=True), nullable=False)
    check_token = Column(String)
    files = Column(BigInteger)
    directories = Column(BigInteger)
    bytes = Column(BigInteger)
    error = Column(String(255))
    s3_path = Column(String(2048))
    s3_version_id = Column(String(1024))
    archive_format = Column(String(40))
    archive_size_bytes = Column(BigInteger)
    archive_sha256 = Column(String(64))
    recipient_sha256 = Column(String(64))

    @property
    def target(self):
        return {
            "kind": "file_set",
            "agent_id": self.agent_id,
            "file_set": self.file_set,
        }


class SchedulerPrincipal(OrganizationScoped, Base):
    """Dormant noninteractive schedule identity; never a User or credential."""

    __tablename__ = "scheduler_principals"
    id = Column(String, primary_key=True, default=generate_uuid)
    schedule_id = Column(String, nullable=False)
    created_at = Column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    __table_args__ = (
        UniqueConstraint(
            "org_id", "id", "schedule_id", name="uq_scheduler_principal_binding"
        ),
        UniqueConstraint(
            "org_id", "schedule_id", name="uq_scheduler_principal_schedule"
        ),
        ForeignKeyConstraint(
            ["org_id", "schedule_id"],
            ["schedules.org_id", "schedules.id"],
            ondelete="RESTRICT",
        ),
    )


class SchedulerGrant(OrganizationScoped, Base):
    """Immutable scope and audit provenance, with terminal revocation."""

    __tablename__ = "scheduler_grants"
    id = Column(String, primary_key=True, default=generate_uuid)
    principal_id = Column(String, nullable=False)
    schedule_id = Column(String, nullable=False)
    schedule_revision = Column(BigInteger, nullable=False)
    org_epoch = Column(BigInteger, nullable=False)
    scope = Column(JSONB, nullable=False)
    scope_sha256 = Column(String, nullable=False)
    enrolled_by = Column(String, nullable=False)
    enrollment_request_id = Column(String, nullable=False)
    created_at = Column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    state = Column(String, nullable=False)
    revoked_at = Column(DateTime(timezone=True))
    revoked_by = Column(String)
    revoke_reason = Column(String)
    revoke_order = Column(BigInteger)
    __table_args__ = (
        UniqueConstraint(
            "org_id",
            "id",
            "schedule_id",
            "schedule_revision",
            name="uq_scheduler_grant_binding",
        ),
        UniqueConstraint(
            "org_id",
            "schedule_id",
            "enrollment_request_id",
            name="uq_scheduler_enrollment_request",
        ),
        ForeignKeyConstraint(
            ["org_id", "principal_id", "schedule_id"],
            [
                "scheduler_principals.org_id",
                "scheduler_principals.id",
                "scheduler_principals.schedule_id",
            ],
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["org_id", "enrolled_by"], ["users.org_id", "users.id"], ondelete="RESTRICT"
        ),
        ForeignKeyConstraint(
            ["org_id", "revoked_by"], ["users.org_id", "users.id"], ondelete="RESTRICT"
        ),
        CheckConstraint(
            "schedule_revision > 0 AND org_epoch >= 0",
            name="ck_scheduler_grant_generation",
        ),
        CheckConstraint(
            "(state = 'active' AND revoked_at IS NULL AND revoked_by IS NULL "
            "AND revoke_reason IS NULL AND revoke_order IS NULL) OR "
            "(state = 'revoked' AND revoked_at IS NOT NULL AND revoke_reason IS NOT NULL "
            "AND revoke_order IS NOT NULL AND revoke_order > 0)",
            name="ck_scheduler_grant_state",
        ),
        Index(
            "uq_scheduler_active_grant",
            "org_id",
            "schedule_id",
            unique=True,
            postgresql_where=text("(state)::text = 'active'::text"),
            sqlite_where=text("state = 'active'"),
        ),
    )


class ScheduleOccurrence(OrganizationScoped, Base):
    """Dormant immutable intended cron instant and original grant binding."""

    __tablename__ = "schedule_occurrences"
    id = Column(String, primary_key=True, default=generate_uuid)
    schedule_id = Column(String, nullable=False)
    schedule_revision = Column(BigInteger, nullable=False)
    grant_id = Column(String, nullable=False)
    scheduled_at = Column(DateTime(timezone=True), nullable=False)
    admission_order = Column(BigInteger, nullable=False)
    construction_xid = Column(BigInteger, nullable=True)
    created_at = Column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    __table_args__ = (
        UniqueConstraint("org_id", "id", name="uq_schedule_occurrence_org"),
        UniqueConstraint(
            "org_id",
            "schedule_id",
            "schedule_revision",
            "scheduled_at",
            name="uq_schedule_occurrence_instant",
        ),
        ForeignKeyConstraint(
            ["org_id", "grant_id", "schedule_id", "schedule_revision"],
            [
                "scheduler_grants.org_id",
                "scheduler_grants.id",
                "scheduler_grants.schedule_id",
                "scheduler_grants.schedule_revision",
            ],
            ondelete="RESTRICT",
        ),
        CheckConstraint("admission_order > 0", name="ck_schedule_occurrence_order"),
    )


class ScheduleOccurrenceMember(OrganizationScoped, Base):
    __tablename__ = "schedule_occurrence_members"
    occurrence_id = Column(String, primary_key=True)
    vm_id = Column(String, primary_key=True)
    source_snapshot = Column(JSONB, nullable=False)
    source_sha256 = Column(String, nullable=False)
    __table_args__ = (
        ForeignKeyConstraint(
            ["org_id", "occurrence_id"],
            ["schedule_occurrences.org_id", "schedule_occurrences.id"],
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["org_id", "vm_id"], ["vms.org_id", "vms.id"], ondelete="RESTRICT"
        ),
    )


class Restore(OrganizationScoped, Base):
    """Restore model - tracks backup restore operations"""

    __tablename__ = "restores"

    __table_args__ = (
        CheckConstraint(
            "(backup_id IS NOT NULL AND s3_recovery IS NULL) OR "
            "(backup_id IS NULL "
            "AND s3_recovery IS NOT NULL AND restore_to_original IS FALSE "
            "AND target_vm_id IS NULL AND (native_plan IS NULL) <> (kubevirt_plan IS NULL))",
            name="ck_restores_one_source",
        ),
    )

    id = Column(String, primary_key=True, default=generate_uuid)
    backup_id = Column(String, ForeignKey("backups.id"), nullable=True)
    s3_recovery = Column(JSONB(none_as_null=True), nullable=True)
    target_vm_id = Column(
        String, ForeignKey("vms.id"), nullable=True
    )  # If restoring to new VM
    restore_to_original = Column(
        Boolean, default=True, server_default=text("true")
    )  # True = restore to original VM
    target_vm_name = Column(String(255), nullable=True)  # New VM name if creating new
    status = Column(
        String(20), default="pending", server_default=text("'pending'")
    )  # pending, running, completed, failed, cancelled
    progress = Column(
        Integer, default=0, server_default=text("0")
    )  # Progress percentage 0-100
    error_message = Column(Text, nullable=True)  # Error details if failed
    created_by = Column(String, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)

    # virtnbdrestore options (v2.4.0)
    until_checkpoint = Column(
        String(255), nullable=True
    )  # Point-in-time restore [--until]
    auto_define = Column(
        Boolean, default=False, server_default=text("false")
    )  # Register VM after restore [-D]
    adjust_config = Column(
        Boolean, default=False, server_default=text("false")
    )  # Adjust VM config [-c]
    selected_disks = Column(
        JSONB, default=list, server_default=text("'[]'")
    )  # Specific disks to restore [-d]

    # Fresh KubeVirt destinations and accepted receipt bundle; never credentials.
    kubevirt_plan = Column(JSONB, nullable=True)
    kubevirt_result = Column(JSONB, nullable=True)
    kubevirt_cleanup_review = Column(JSONB, nullable=True)
    native_plan = Column(JSONB, nullable=True)
    native_result = Column(JSONB, nullable=True)

    # Relationships
    backup = relationship("Backup")
    target_vm = relationship("VM", foreign_keys=[target_vm_id])
    user = relationship("User")

    def __repr__(self):
        return f"<Restore {self.id} - Backup {self.backup_id} ({self.status})>"


class SystemSettings(Base):
    """System settings model - stores global configuration"""

    __tablename__ = "system_settings"

    id = Column(String, primary_key=True, default=generate_uuid)
    category = Column(String(50), nullable=False)  # email, backup, storage, agent
    key = Column(String(100), nullable=False)
    value = Column(Text, nullable=True)
    value_type = Column(
        String(20), default="string", server_default=text("'string'")
    )  # string, integer, boolean, json
    description = Column(Text, nullable=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    updated_by = Column(String, ForeignKey("users.id"), nullable=True)

    def __repr__(self):
        return f"<SystemSettings {self.category}.{self.key}>"


class NotificationRule(OrganizationScoped, Base):
    """Notification rule model - defines when and how to send notifications"""

    __tablename__ = "notification_rules"

    id = Column(String, primary_key=True, default=generate_uuid)
    name = Column(String(255), nullable=False)
    event_type = Column(
        String(50), nullable=False
    )  # backup_failed, backup_completed, schedule_run, health_warning
    enabled = Column(Boolean, default=True, server_default=text("true"))
    notification_type = Column(
        String(20), default="email", server_default=text("'email'")
    )  # email (future: slack, webhook)
    recipients = Column(JSONB, default=list)  # List of email addresses
    conditions = Column(
        JSONB, default=dict
    )  # Optional conditions (e.g., {"severity": "critical"})
    template = Column(Text, nullable=True)  # Custom email template (optional)
    created_by = Column(String, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationship
    user = relationship("User")

    def __repr__(self):
        return f"<NotificationRule {self.name} ({self.event_type})>"


class NotificationLog(OrganizationScoped, Base):
    """Notification log model - tracks sent notifications"""

    __tablename__ = "notification_logs"

    id = Column(String, primary_key=True, default=generate_uuid)
    rule_id = Column(String, ForeignKey("notification_rules.id"), nullable=True)
    event_type = Column(String(50), nullable=False)
    recipient = Column(String(255), nullable=False)
    subject = Column(String(500), nullable=True)
    body = Column(Text, nullable=True)
    status = Column(
        String(20), default="sent", server_default=text("'sent'")
    )  # sent, failed
    error_message = Column(Text, nullable=True)
    read = Column(Boolean, default=False, server_default=text("false"), nullable=False)
    sent_at = Column(DateTime, default=datetime.utcnow)

    # Relationship
    rule = relationship("NotificationRule")

    def __repr__(self):
        return (
            f"<NotificationLog {self.event_type} to {self.recipient} ({self.status})>"
        )


class BackupVerification(OrganizationScoped, Base):
    """Backup verification model - tracks backup integrity checks"""

    __tablename__ = "backup_verifications"
    # Predicate text follows PostgreSQL reflection, as required by schema parity.
    __table_args__ = (
        Index(
            "ix_backup_verifications_one_unfinished_backup",
            "org_id",
            "backup_id",
            unique=True,
            postgresql_where=text(
                "(((verification_type)::text = 'artifact_scrub'::text) AND "
                "((status)::text <> ALL (ARRAY['passed'::text, 'failed'::text, 'cancelled'::text])))"
            ),
            sqlite_where=text(
                "verification_type='artifact_scrub' AND status NOT IN ('passed','failed','cancelled')"
            ),
        ),
        Index(
            "ix_backup_verifications_unfinished_scrub",
            "org_id",
            "status",
            postgresql_where=text(
                "(((verification_type)::text = 'artifact_scrub'::text) AND "
                "((status)::text <> ALL (ARRAY['passed'::text, 'failed'::text, 'cancelled'::text])))"
            ),
            sqlite_where=text(
                "verification_type='artifact_scrub' AND status NOT IN ('passed','failed','cancelled')"
            ),
        ),
    )

    id = Column(String, primary_key=True, default=generate_uuid)
    backup_id = Column(String, ForeignKey("backups.id"), nullable=False)
    status = Column(
        String(20), default="pending", server_default=text("'pending'")
    )  # pending, running, passed, failed
    verification_type = Column(
        String(50), default="checksum", server_default=text("'checksum'")
    )  # checksum, mount_test, integrity
    result_message = Column(Text, nullable=True)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    created_by = Column(String, ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Original nonsecret scrub custody. Credentials/DEKs are request-local only.
    verification_plan_canonical = Column(Text, nullable=True)
    verification_plan_sha256 = Column(String(64), nullable=True)
    verification_authority_canonical = Column(Text, nullable=True)
    verification_agent_id = Column(String, ForeignKey("agents.id"), nullable=True)
    verification_bound_xid = Column(BigInteger, nullable=True)
    verification_worker_id = Column(String(36), nullable=True)
    verification_worker_xid = Column(BigInteger, nullable=True)
    verification_next_poll_at = Column(DateTime, nullable=True)
    verification_admission_budget = Column(JSONB, nullable=True)
    verification_result = Column(JSONB, nullable=True)
    verification_read_attempts = Column(
        Integer, nullable=False, default=0, server_default=text("0")
    )
    verification_last_busy_attempt = Column(
        Integer, nullable=False, default=0, server_default=text("0")
    )
    verification_read_limit = Column(
        Integer, nullable=False, default=3, server_default=text("3")
    )
    verification_cancel_requested = Column(
        Boolean, nullable=False, default=False, server_default=text("false")
    )

    # Relationships
    backup = relationship("Backup")
    user = relationship("User")

    def __repr__(self):
        return (
            f"<BackupVerification {self.id} - Backup {self.backup_id} ({self.status})>"
        )


class SavedSearch(OrganizationScoped, Base):
    """Saved search model - stores user's saved search filters"""

    __tablename__ = "saved_searches"

    id = Column(String, primary_key=True, default=generate_uuid)
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    search_type = Column(String(20), nullable=False)  # backup, vm, activity, restore
    filters = Column(JSONB, default=dict)  # Search filters as JSON
    is_public = Column(
        Boolean, default=False, server_default=text("false"), nullable=False
    )  # Share with all users
    created_by = Column(String, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationship
    user = relationship("User")

    def __repr__(self):
        return f"<SavedSearch {self.name} ({self.search_type})>"


class Report(OrganizationScoped, Base):
    """Report model - scheduled report configurations"""

    __tablename__ = "reports"

    id = Column(String, primary_key=True, default=generate_uuid)
    name = Column(String(255), nullable=False)
    report_type = Column(
        String(50), nullable=False
    )  # backup_summary, compliance, health, activity
    schedule = Column(
        String(50), nullable=True
    )  # daily, weekly, monthly, or cron expression
    enabled = Column(Boolean, default=True, server_default=text("true"))
    format = Column(
        String(20), default="pdf", server_default=text("'pdf'")
    )  # pdf, csv, json
    recipients = Column(JSONB, default=list)  # Email recipients
    filters = Column(JSONB, default=dict)  # Report filters/parameters
    last_run_at = Column(DateTime, nullable=True)
    next_run_at = Column(DateTime, nullable=True)
    created_by = Column(String, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationship
    user = relationship("User")

    def __repr__(self):
        return f"<Report {self.name} ({self.report_type})>"


class ReportExecution(OrganizationScoped, Base):
    """Report execution log - tracks report generation history"""

    __tablename__ = "report_executions"

    id = Column(String, primary_key=True, default=generate_uuid)
    report_id = Column(String, ForeignKey("reports.id"), nullable=True)
    status = Column(
        String(20), default="pending", server_default=text("'pending'")
    )  # pending, running, completed, failed
    file_path = Column(
        String(500), nullable=True
    )  # Legacy: Path to generated report file
    file_size_bytes = Column(Integer, nullable=True)
    error_message = Column(Text, nullable=True)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Database storage (preferred over file_path)
    file_content = Column(LargeBinary, nullable=True)  # Report content stored in DB
    file_name = Column(String(255), nullable=True)  # Original filename for download
    content_type = Column(String(100), nullable=True)  # MIME type for download

    # Relationship
    report = relationship("Report")

    def __repr__(self):
        return f"<ReportExecution {self.id} ({self.status})>"


class OrchestratorAPIKey(Base):
    """Orchestrator API Keys - for agent → orchestrator authentication"""

    __tablename__ = "orchestrator_api_keys"

    id = Column(String, primary_key=True, default=generate_uuid)
    name = Column(String(255), nullable=False)  # User-friendly name
    key_hash = Column(String(64), nullable=False, unique=True)  # SHA-256 hash
    key_prefix = Column(String(16), nullable=False)  # First 8 chars for identification
    expires_at = Column(DateTime, nullable=True)  # Optional expiration
    enabled = Column(Boolean, default=True)  # Can disable without deleting
    last_used_at = Column(DateTime, nullable=True)
    created_by = Column(String, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    user = relationship("User")

    def __repr__(self):
        return f"<OrchestratorAPIKey {self.name} ({self.key_prefix}...)>"

    def is_expired(self) -> bool:
        """Check if key is expired"""
        if not self.expires_at:
            return False
        return datetime.utcnow() > self.expires_at

    def is_valid(self) -> bool:
        """Check if key is enabled and not expired"""
        return self.enabled and not self.is_expired()


class AgentRegistrationKey(Base):
    """Agent Registration Keys - one-time keys for initial agent registration"""

    __tablename__ = "agent_registration_keys"

    id = Column(String, primary_key=True, default=generate_uuid)
    name = Column(String(255), nullable=False)  # User-friendly name
    agent_hostname = Column(String(255), nullable=True)  # Admin-authorized identity
    key_hash = Column(String(64), nullable=False, unique=True)  # SHA-256 hash
    key_prefix = Column(String(16), nullable=False)  # First 8 chars for identification
    expires_at = Column(DateTime, nullable=True)  # Optional expiration
    enabled = Column(Boolean, default=True)
    max_uses = Column(Integer, nullable=True)  # Optional use limit (None = unlimited)
    use_count = Column(Integer, default=0)  # Track usage
    last_used_at = Column(DateTime, nullable=True)
    created_by = Column(String, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    user = relationship("User")

    def __repr__(self):
        return f"<AgentRegistrationKey {self.name} ({self.key_prefix}...)>"

    def is_expired(self) -> bool:
        """Check if key is expired"""
        if not self.expires_at:
            return False
        return datetime.utcnow() > self.expires_at

    def is_max_uses_reached(self) -> bool:
        """Check if key has reached max uses"""
        if not self.max_uses:
            return False
        return self.use_count >= self.max_uses

    def is_valid(self) -> bool:
        """Check if key is enabled, not expired, and not max uses reached"""
        return self.enabled and not self.is_expired() and not self.is_max_uses_reached()


class AgentAPIKey(Base):
    """Agent API Keys - for orchestrator → agent authentication (per-agent credentials)"""

    __tablename__ = "agent_api_keys"

    id = Column(String, primary_key=True, default=generate_uuid)
    agent_id = Column(String, ForeignKey("agents.id"), nullable=False, unique=True)
    name = Column(String(255), nullable=True)  # Optional custom name (UI can override)
    key_hash = Column(String(64), nullable=False)  # SHA-256 hash
    key_prefix = Column(String(16), nullable=False)  # First 8 chars for identification
    expires_at = Column(DateTime, nullable=True)  # Optional expiration
    enabled = Column(Boolean, default=True)
    last_used_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    agent = relationship("Agent", back_populates="api_key")

    def __repr__(self):
        agent_name = self.name or f"Agent {self.agent_id}"
        return f"<AgentAPIKey {agent_name} ({self.key_prefix}...)>"

    def is_expired(self) -> bool:
        """Check if key is expired"""
        if not self.expires_at:
            return False
        return datetime.utcnow() > self.expires_at

    def is_valid(self) -> bool:
        """Check if key is enabled and not expired"""
        return self.enabled and not self.is_expired()


class AgentCertificate(Base):
    """Agent TLS certificate tracking for mTLS authentication."""

    __tablename__ = "agent_certificates"

    id = Column(String, primary_key=True, default=generate_uuid)
    agent_id = Column(String, ForeignKey("agents.id"), nullable=False)
    serial_number = Column(String(64), unique=True, index=True)
    fingerprint = Column(String(64), nullable=False)
    common_name = Column(String(255))
    issued_at = Column(DateTime, default=datetime.utcnow, server_default=func.now())
    expires_at = Column(DateTime, nullable=False)
    status = Column(
        String(20), default="active", server_default=text("'active'")
    )  # active, expired, revoked
    revoked_at = Column(DateTime, nullable=True)

    # Relationship
    agent = relationship("Agent", back_populates="certificates")

    def __repr__(self):
        return f"<AgentCertificate {self.common_name} ({self.status})>"


def event_organization_id(context):
    if context.get_current_parameters().get("attribution") == "platform":
        from core.tenant_context import identity

        if not identity()[2]:
            raise RuntimeError("Installation events require explicit platform scope")
        return None
    return default_organization_id(context)


class SystemEvent(Base):
    """System-generated events (agent, scheduler, reconciliation).

    Unlike ActivityLog which tracks user actions (requires user_id),
    SystemEvent tracks system/agent events with no user context.
    These events provide observability into automated operations.
    """

    __tablename__ = "system_events"
    __table_args__ = (
        CheckConstraint(
            "(attribution = 'tenant' AND org_id IS NOT NULL AND org_id <> '') OR "
            "(attribution IN ('platform', 'legacy_unattributed') AND org_id IS NULL)",
            name="ck_system_events_attribution",
        ),
    )

    id = Column(String, primary_key=True, default=generate_uuid)
    attribution = Column(String(32), nullable=False, default="tenant")
    # Durable history outlives deletion of its source and organization.
    org_id = Column(String, nullable=True, default=event_organization_id)
    event_type = Column(
        String(100), nullable=False, index=True
    )  # backup_job, vm_lifecycle, backup_reconciled, etc.
    source = Column(String(50), nullable=False)  # agent, scheduler, system
    source_id = Column(String, nullable=True)  # Agent ID, schedule ID, etc.
    resource_type = Column(String(50), nullable=True)  # backup, vm, schedule
    resource_id = Column(String, nullable=True)  # ID of affected resource
    details = Column(
        JSONB, default=dict, server_default=text("'{}'"), nullable=False
    )  # Full event data
    created_at = Column(
        DateTime,
        default=datetime.utcnow,
        index=True,
        server_default=func.now(),
        nullable=False,
    )

    def __repr__(self):
        return f"<SystemEvent {self.event_type} from {self.source}>"


class SettingV3(Base):
    """v3.0: Non-secret settings with source tracking.

    Stores configuration values that can come from:
    - default: Built-in default value
    - ui: User configured via settings UI
    - env: Environment variable override
    - vault: Vault-sourced (tracked but value read at runtime)
    """

    __tablename__ = "settings_v3"

    key = Column(String(100), primary_key=True)
    value = Column(Text, nullable=True)
    value_type = Column(
        String(20), default="string", server_default=text("'string'")
    )  # string, int, bool, json
    source = Column(
        String(20), default="default", server_default=text("'default'")
    )  # default, ui, env, vault
    updated_at = Column(
        DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
        server_default=func.now(),
    )
    updated_by = Column(String(100), nullable=True)

    def __repr__(self):
        return f"<SettingV3 {self.key}={self.value[:20] if self.value else None}>"


class SecretV3(Base):
    """v3.0: Encrypted credentials for UI-entered secrets.

    Vault-sourced secrets are NOT stored here - they're read at runtime via ESO.
    Only UI-entered credentials are stored (encrypted with Fernet).
    """

    __tablename__ = "secrets_v3"

    key = Column(String(100), primary_key=True)
    encrypted_value = Column(Text, nullable=True)  # Fernet encrypted
    source = Column(String(20), default="ui", server_default=text("'ui'"))  # ui, vault
    vault_path = Column(String(255), nullable=True)  # If source=vault
    updated_at = Column(
        DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
        server_default=func.now(),
    )

    def __repr__(self):
        return f"<SecretV3 {self.key} source={self.source}>"


# Migration-owned indexes are part of the application schema contract. Keep them
# in metadata so autogeneration cannot propose deleting them as unknown extras.
for _table in Base.metadata.tables.values():
    if "org_id" in _table.c and _table.name != "organization_defaults":
        Index(f"idx_{_table.name}_org_id", _table.c.org_id)

for _table_name, _index_name, _columns in (
    (
        "oidc_login_states",
        "ix_oidc_login_states_expiry_batch",
        ("org_id", "expires_at", "digest"),
    ),
    ("activity_logs", "ix_activity_logs_action", ("action",)),
    ("activity_logs", "ix_activity_logs_created_at", ("created_at",)),
    ("activity_logs", "ix_activity_logs_user_id", ("user_id",)),
    ("backup_queue", "ix_backup_queue_status_priority", ("status", "priority")),
    ("backup_verifications", "ix_backup_verifications_backup_id", ("backup_id",)),
    ("backup_verifications", "ix_backup_verifications_status", ("status",)),
    ("demo_sessions", "ix_demo_sessions_token_hash", ("token_hash",)),
    ("encryption_keys", "ix_encryption_keys_status", ("status",)),
    ("notification_logs", "ix_notification_logs_event_type", ("event_type",)),
    ("notification_logs", "ix_notification_logs_sent_at", ("sent_at",)),
    ("notification_rules", "ix_notification_rules_enabled", ("enabled",)),
    ("notification_rules", "ix_notification_rules_event_type", ("event_type",)),
    ("report_executions", "ix_report_executions_created_at", ("created_at",)),
    ("report_executions", "ix_report_executions_report_id", ("report_id",)),
    ("reports", "ix_reports_enabled", ("enabled",)),
    ("reports", "ix_reports_report_type", ("report_type",)),
    ("restores", "ix_restores_backup_id", ("backup_id",)),
    ("restores", "ix_restores_created_at", ("created_at",)),
    ("restores", "ix_restores_status", ("status",)),
    ("saved_searches", "ix_saved_searches_created_by", ("created_by",)),
    ("saved_searches", "ix_saved_searches_search_type", ("search_type",)),
    ("schedules", "ix_schedules_enabled", ("enabled",)),
    ("schedules", "ix_schedules_next_run_at", ("next_run_at",)),
    ("system_settings", "ix_system_settings_category", ("category",)),
    ("users", "ix_users_oidc_subject", ("oidc_subject", "oidc_issuer")),
):
    _table = Base.metadata.tables[_table_name]
    Index(
        _index_name,
        *(_table.c[name] for name in _columns),
        unique=_index_name == "ix_users_oidc_subject",
        **(
            {"postgresql_where": text("oidc_subject IS NOT NULL")}
            if _index_name == "ix_users_oidc_subject"
            else {}
        ),
    )

UniqueConstraint(
    SystemSettings.__table__.c.category,
    SystemSettings.__table__.c.key,
    name="uq_settings_category_key",
)

# Exact tenant bindings for dormant scheduler records.
for _parent in (Schedule, User, VM):
    _parent.__table__.append_constraint(
        UniqueConstraint("org_id", "id", name=f"uq_{_parent.__tablename__}_org_id")
    )
Schedule.__table__.append_constraint(
    ForeignKeyConstraint(
        ["org_id", "current_grant_id", "id", "authority_revision"],
        [
            "scheduler_grants.org_id",
            "scheduler_grants.id",
            "scheduler_grants.schedule_id",
            "scheduler_grants.schedule_revision",
        ],
        name="fk_schedule_current_grant",
        deferrable=True,
        initially="DEFERRED",
        use_alter=True,
    )
)
for _model in (Backup, BackupQueue):
    _model.__table__.append_constraint(
        ForeignKeyConstraint(
            ["scheduler_occurrence_id", "vm_id"],
            [
                "schedule_occurrence_members.occurrence_id",
                "schedule_occurrence_members.vm_id",
            ],
            name=f"fk_{_model.__tablename__}_occurrence",
            ondelete="RESTRICT",
        )
    )
    _model.__table__.append_constraint(
        UniqueConstraint(
            "scheduler_occurrence_id",
            "vm_id",
            name=f"uq_{_model.__tablename__}_occurrence",
        )
    )

for _model in (Backup, BackupQueue):
    _model.__table__.append_constraint(
        CheckConstraint(
            "authority_kind IS NOT NULL AND "
            "((authority_kind='human' AND initiating_user_id IS NOT NULL AND scheduler_occurrence_id IS NULL) OR "
            "(authority_kind='scheduler' AND initiating_user_id IS NULL AND scheduler_occurrence_id IS NOT NULL) OR "
            "(authority_kind='legacy_held' AND initiating_user_id IS NULL AND scheduler_occurrence_id IS NULL))",
            name=f"ck_{_model.__tablename__}_authority",
        ).ddl_if(dialect="postgresql")
    )
Schedule.__table__.append_constraint(
    CheckConstraint("authority_revision > 0", name="ck_schedule_authority_revision")
)

UniqueConstraint(BackupQueue.__table__.c.claim_id, name="uq_backup_queue_claim")
BackupQueue.__table__.append_constraint(
    CheckConstraint(
        """authority_kind <> 'scheduler' OR (
    status IS NOT NULL AND
    ((status IN ('queued','held_unclaimed') AND claim_id IS NULL AND claimed_at IS NULL AND started_backup_id IS NULL)
     OR (status IN ('claimed','held_claimed') AND claim_id IS NOT NULL
         AND claimed_at IS NOT NULL AND started_backup_id IS NOT NULL))
    AND ((status IN ('queued','claimed') AND hold_reason IS NULL)
      OR (status IN ('held_unclaimed','held_claimed') AND hold_reason IS NOT NULL AND hold_reason IN
        ('source_unavailable','authority_revoked','organization_fenced','scope_drift','recovery_required','commit_outcome_unknown')))
)""",
        name="ck_scheduler_queue_state",
    )
)
