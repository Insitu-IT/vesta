"""Discover bucket recovery points without turning bucket contents into backups."""

from typing import Annotated, Literal
from uuid import uuid4

from botocore.exceptions import BotoCoreError, ClientError
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field, UUID4
from sqlalchemy.orm import Session

from core import bucket_recovery
from core.kubevirt_restore import RestoreTarget as KubeVirtRestoreTarget
from core.native_restore import NativeTarget
from core.operator_requests import begin_admission, request_identity
from core.recovery_retention import (
    check_recovery_source_scope,
    retain_local_recovery_chain,
)
from core.s3_ownership import StorageOwnershipError
from core.vm_agent_peer import AgentPeerUnavailable
from database import get_db
from deps import get_admin_user, get_installation_admin, log_activity
from models import Agent, Restore

router = APIRouter(prefix="/api/v1", tags=["bucket-recovery"])


class DiscoverRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    trust: bucket_recovery.TrustAnchor | None = None
    cursor: str | None = Field(default=None, min_length=1, max_length=4096)
    legacy: bool = False


class PointRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    trust: bucket_recovery.TrustAnchor


class RestoreRequest(PointRequest):
    agent_id: str = Field(min_length=1, max_length=64)
    native_target: dict | None = None
    kubevirt_target: dict | None = None


class RecoveryPointResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    backup_id: str | None
    name: str | None
    provider: Literal["libvirt", "kubevirt"] | None
    completed_at: str | None
    installation_id: str | None
    org_id: str | None
    status: Literal[
        "verified", "trust_required", "unsigned", "incomplete", "invalid", "unavailable"
    ]
    generation_key: str | None = None
    version_id: str | None = None
    requires_kek: bool | None = None


class DiscoverResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    points: list[RecoveryPointResponse]
    next_cursor: str | None


class DestinationAgent(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str
    name: str
    namespaces: list[str]


class SourceVolume(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str
    capacity_bytes: int


class NativeInterface(BaseModel):
    model_config = ConfigDict(extra="forbid")
    source_mac: str
    source_network: str | None


class KubeVirtNetwork(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str
    type: Literal["pod", "multus"]
    source_mac: str | None


class KubeVirtDependency(BaseModel):
    model_config = ConfigDict(extra="forbid")
    kind: Literal["secret", "configMap"]
    name: str


class KubeVirtSource(BaseModel):
    model_config = ConfigDict(extra="forbid")
    volumes: list[SourceVolume]
    networks: list[KubeVirtNetwork]
    dependencies: list[KubeVirtDependency]


class NativeSource(BaseModel):
    model_config = ConfigDict(extra="forbid")
    disks: list[str]
    exclusions: list[str]
    interfaces: list[NativeInterface]


class PreviewResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    point: RecoveryPointResponse
    source: KubeVirtSource | NativeSource
    destination_agents: list[DestinationAgent]
    requires_kek: bool


class NativeRecoveryTarget(NativeTarget):
    vm_uuid: UUID4 = Field(strict=False)


class QueuedRecoveryResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str
    request_id: str
    backup_id: None
    recovery_source: RecoveryPointResponse
    status: Literal["pending"]
    progress: int
    restore_to_original: Literal[False]
    target_vm_name: str
    native_target: NativeRecoveryTarget | None = None
    kubevirt_target: KubeVirtRestoreTarget | None = None
    message: str


class RetiredImportDetail(BaseModel):
    model_config = ConfigDict(extra="forbid")
    code: Literal["unsigned_s3_import_retired"]
    message: str


class RetiredImportResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    detail: RetiredImportDetail


def _discover(db, data):
    trust = data.trust.model_dump(exclude_none=True) if data.trust else None
    try:
        return bucket_recovery.discover(db, trust, data.cursor, data.legacy)
    except StorageOwnershipError as exc:
        raise HTTPException(409, str(exc)) from None
    except (BotoCoreError, ClientError, ValueError, KeyError, TypeError):
        raise HTTPException(
            502, "Unable to read the configured S3 repository"
        ) from None


@router.post(
    "/recovery/s3/discover",
    response_model=DiscoverResponse,
    response_model_exclude_unset=True,
)
def discover_points(
    data: DiscoverRequest,
    current_user=Depends(get_installation_admin),
    db: Session = Depends(get_db),
):
    """List bounded signed or historical generation metadata from configured S3."""
    return _discover(db, data)


@router.get(
    "/s3/discover", response_model=DiscoverResponse, response_model_exclude_unset=True
)
def discover_chains(
    installation_id: Annotated[str | None, Query(max_length=36)] = None,
    org_id: Annotated[str | None, Query(max_length=36)] = None,
    public_key: Annotated[str | None, Query(max_length=43)] = None,
    cursor: Annotated[str | None, Query(min_length=1, max_length=4096)] = None,
    legacy: bool = False,
    current_user=Depends(get_installation_admin),
    db: Session = Depends(get_db),
):
    """Read-only compatibility alias for bucket discovery."""
    trust = None
    if installation_id is not None or org_id is not None or public_key is not None:
        from pydantic import ValidationError

        try:
            trust = bucket_recovery.TrustAnchor(
                installation_id=installation_id, org_id=org_id, public_key=public_key
            )
        except ValidationError:
            raise HTTPException(422, "Explicit recovery trust is invalid") from None
    return _discover(db, DiscoverRequest(trust=trust, cursor=cursor, legacy=legacy))


def _require_recovery_admin(user):
    if not bucket_recovery.recovery_admin(user):
        raise HTTPException(
            403, "Local organization and installation administration required"
        )


@router.post(
    "/recovery/s3/points/{backup_id}/preview",
    response_model=PreviewResponse,
    response_model_exclude_unset=True,
)
def preview_point(
    backup_id: str,
    data: PointRequest,
    current_user=Depends(get_installation_admin),
    db: Session = Depends(get_db),
):
    """Resolve a signed source and list compatible locally enrolled destinations."""
    _require_recovery_admin(current_user)
    trust = data.trust.model_dump(exclude_none=True)
    try:
        check_recovery_source_scope(db, current_user.org_id, trust)
        cfg, point, bundle, wrapped = bucket_recovery.load_point(db, trust, backup_id)
        bucket_recovery.require_imported_keys(db, current_user.org_id, bundle, wrapped)
        _, mappings = bucket_recovery.inspect_definition(
            db, current_user.org_id, cfg, bundle, wrapped
        )
    except StorageOwnershipError as exc:
        raise HTTPException(409, str(exc)) from None
    agents = []
    for agent in (
        db.query(Agent)
        .filter_by(org_id=current_user.org_id, status="online")
        .order_by(Agent.hostname, Agent.id)
        .limit(100)
        .all()
    ):
        try:
            namespaces = bucket_recovery.compatible_destination(
                db, agent, point["provider"], bundle
            )
        except (StorageOwnershipError, AgentPeerUnavailable):
            continue
        agents.append(
            {"id": agent.id, "name": agent.get_display_name(), "namespaces": namespaces}
        )
    selected = bundle["members"][-1]
    if point["provider"] == "libvirt":
        manifest = selected["push_result"]["manifest"]
        source = {
            "disks": [disk["target"] for disk in manifest["disks"]],
            "exclusions": manifest["exclusions"],
        }
    else:
        source = {
            "volumes": [
                {"name": volume["name"], "capacity_bytes": volume["capacity_bytes"]}
                for volume in selected["request"]["plan"]["source"]["volumes"]
            ]
        }
    return {
        "point": bucket_recovery.public_point(point),
        "source": {**source, **mappings},
        "destination_agents": agents,
        "requires_kek": any(
            member["request"]["plan"]["encryption"]["format"] != "none"
            for member in bundle["members"]
        ),
    }


@router.post(
    "/recovery/s3/points/{backup_id}/restore",
    status_code=201,
    response_model=QueuedRecoveryResponse,
    response_model_exclude_unset=True,
)
def restore_point(
    backup_id: str,
    data: RestoreRequest,
    current_user=Depends(get_installation_admin),
    db: Session = Depends(get_db),
    request_id: str | None = Depends(request_identity),
):
    """Queue a signed recovery-only restore to explicitly selected local resources."""
    _require_recovery_admin(current_user)
    intent = data.model_dump(mode="json", exclude_none=True)
    trust = intent["trust"]
    try:
        check_recovery_source_scope(db, current_user.org_id, trust)
    except StorageOwnershipError as exc:
        raise HTTPException(409, str(exc)) from None
    admission = begin_admission(
        db,
        current_user,
        "restore.create",
        {"recovery_s3_point": backup_id, **intent},
        request_id,
    )
    if admission.replay:
        return admission.response()

    try:
        cfg, point, bundle, wrapped = bucket_recovery.load_point(db, trust, backup_id)
        native = point["provider"] == "libvirt"
        if (
            native
            and (data.native_target is None or data.kubevirt_target is not None)
            or not native
            and (data.kubevirt_target is None or data.native_target is not None)
        ):
            raise HTTPException(
                422,
                "An explicit fresh target for the selected backup provider is required",
            )
        bucket_recovery.require_imported_keys(db, current_user.org_id, bundle, wrapped)
        source_name, required = bucket_recovery.inspect_definition(
            db, current_user.org_id, cfg, bundle, wrapped
        )
        identity = str(uuid4())
        plan = bucket_recovery.build_plan(
            db,
            current_user,
            data.agent_id,
            identity,
            trust,
            point,
            bundle,
            data.native_target if native else data.kubevirt_target,
        )
        bucket_recovery.require_capture_mappings(plan, source_name, required)
        local_chain = retain_local_recovery_chain(
            db, current_user.org_id, trust, point, bundle
        )
    except (StorageOwnershipError, AgentPeerUnavailable) as exc:
        raise HTTPException(409, str(exc)) from None
    restore = Restore(
        id=identity,
        org_id=current_user.org_id,
        backup_id=None,
        s3_recovery={"trust": trust, "point": point, "local_chain": local_chain},
        restore_to_original=False,
        target_vm_name=plan["target"]["vm_name"],
        status="pending",
        progress=0,
        created_by=current_user.id,
        auto_define=True,
        **({"native_plan": plan} if native else {"kubevirt_plan": plan}),
    )
    db.add(restore)
    db.flush()
    log_activity(
        db,
        current_user,
        "s3_recovery_restore_created",
        "restore",
        restore.id,
        {
            "source_backup_id": backup_id,
            "source_installation_id": point["installation_id"],
            "destination_agent_id": data.agent_id,
            "target_vm_name": restore.target_vm_name,
        },
        commit=False,
    )
    admission.dispatch("restore", identity)
    receipt = QueuedRecoveryResponse.model_validate(
        {
            "id": identity,
            "request_id": admission.row.request_id,
            "backup_id": None,
            "recovery_source": bucket_recovery.public_point(point),
            "status": "pending",
            "progress": 0,
            "restore_to_original": False,
            "target_vm_name": restore.target_vm_name,
            ("native_target" if native else "kubevirt_target"): plan["target"],
            "message": "Fresh inactive S3 recovery restore queued",
        }
    )
    return admission.finish(
        receipt.model_dump(mode="json", exclude_unset=True), status=201
    )


@router.post(
    "/s3/import",
    status_code=410,
    response_description="Use bucket discovery and a recovery-only restore.",
    deprecated=True,
    response_model=RetiredImportResponse,
    openapi_extra={
        "x-no-success-response": "The retired operation always refuses admission"
    },
)
def import_chain(current_user=Depends(get_admin_user)):
    """Legacy unsigned VM-chain catalog import is retired."""
    return RetiredImportResponse(
        detail=RetiredImportDetail(
            code="unsigned_s3_import_retired",
            message=(
                "Use Recover from S3 in Restores or POST /api/v1/recovery/s3/discover. "
                "For complete unsigned generations, use vesta-restore s3 restore "
                "--allow-unsigned-legacy to recover into new disks."
            ),
        )
    )
